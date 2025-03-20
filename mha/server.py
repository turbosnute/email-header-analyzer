from flask import Flask
from flask import render_template
from flask import request

from email.parser import HeaderParser
import time
import dateutil.parser

from datetime import datetime
import re

import pygal
from pygal.style import Style

from IPy import IP
import geoip2.database


###
import os
import json
import uuid
from flask import redirect, url_for
###

import argparse

app = Flask(__name__)
reader = geoip2.database.Reader(
    '%s/data/GeoLite2-Country.mmdb' % app.static_folder)

STORAGE_DIR = os.path.join(app.root_path, 'storage')
if not os.path.exists(STORAGE_DIR):
    os.makedirs(STORAGE_DIR)

@app.context_processor
def utility_processor():
    def getCountryForIP(line):
        ipv4_address = re.compile(r"""
            \b((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.
            (?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.
            (?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.
            (?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d))\b""", re.X)
        ip = ipv4_address.findall(line)
        if ip:
            ip = ip[0]  # take the 1st ip and ignore the rest
            if IP(ip).iptype() == 'PUBLIC':
                r = reader.country(ip).country
                if r.iso_code and r.name:
                    return {
                        'iso_code': r.iso_code.lower(),
                        'country_name': r.name
                    }
    return dict(country=getCountryForIP)


@app.context_processor
def utility_processor():
    def duration(seconds, _maxweeks=99999999999):
        return ', '.join(
            '%d %s' % (num, unit)
            for num, unit in zip([
                (seconds // d) % m
                for d, m in (
                    (604800, _maxweeks),
                    (86400, 7), (3600, 24),
                    (60, 60), (1, 60))
            ], ['wk', 'd', 'hr', 'min', 'sec'])
            if num
        )
    return dict(duration=duration)


def dateParser(line):
    try:
        r = dateutil.parser.parse(line, fuzzy=True)

    # if the fuzzy parser failed to parse the line due to
    # incorrect timezone information issue #5 GitHub
    except ValueError:
        r = re.findall('^(.*?)\s*(?:\(|utc)', line, re.I)
        if r:
            r = dateutil.parser.parse(r[0])
    return r


def getHeaderVal(h, data, rex='\s*(.*?)\n\S+:\s'):
    r = re.findall('%s:%s' % (h, rex), data, re.X | re.DOTALL | re.I)
    if r:
        return r[0].strip()
    else:
        return None
    
def cleanup_old_analyses():
    """Remove analyses older than 30 days"""
    now = datetime.now()
    for filename in os.listdir(STORAGE_DIR):
        file_path = os.path.join(STORAGE_DIR, filename)
        if os.path.isfile(file_path) and filename.endswith('.json'):
            file_age = now - datetime.fromtimestamp(os.path.getmtime(file_path))
            if file_age.days > 30:
                os.remove(file_path)

@app.route('/', methods=['GET', 'POST'])
def index():
    # Check if we're trying to retrieve a saved analysis
    analysis_id = request.args.get('id')
    if analysis_id:
        try:
            # Attempt to load the saved analysis
            file_path = os.path.join(STORAGE_DIR, f"{analysis_id}.json")
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    saved_data = json.load(f)
                
                return render_template(
                    'index.html', 
                    data=saved_data['data'], 
                    delayed=saved_data['delayed'],
                    summary=saved_data['summary'],
                    n=HeaderParser().parsestr(saved_data['raw_headers']),
                    chart=saved_data['chart'],
                    security_headers=saved_data['security_headers'],
                    analysis_id=analysis_id
                )
            else:
                # If file doesn't exist, show error message
                return render_template('index.html', error=f"Analysis ID {analysis_id} not found")
        except Exception as e:
            return render_template('index.html', error=f"Error loading analysis: {str(e)}")

    if request.method == 'POST':
        mail_data = request.form['headers'].strip()
        r = {}
        n = HeaderParser().parsestr(mail_data)
        graph = []
        received = n.get_all('Received')
        if received:
            received = [i for i in received if ('from' in i or 'by' in i)]
        else:
            received = re.findall(
                'Received:\s*(.*?)\n\S+:\s+', mail_data, re.X | re.DOTALL | re.I)
        c = len(received)
        for i in range(len(received)):
            if ';' in received[i]:
                line = received[i].split(';')
            else:
                line = received[i].split('\r\n')
            line = list(map(str.strip, line))
            line = [x.replace('\r\n', ' ') for x in line]
            try:
                if ';' in received[i + 1]:
                    next_line = received[i + 1].split(';')
                else:
                    next_line = received[i + 1].split('\r\n')
                next_line = list(map(str.strip, next_line))
                next_line = [x.replace('\r\n', '') for x in next_line]
            except IndexError:
                next_line = None

            org_time = dateParser(line[-1])
            if not next_line:
                next_time = org_time
            else:
                next_time = dateParser(next_line[-1])

            if line[0].startswith('from'):
                data = re.findall(
                    """
                    from\s+
                    (.*?)\s+
                    by(.*?)
                    (?:
                        (?:with|via)
                        (.*?)
                        (?:\sid\s|$)
                        |\sid\s|$
                    )""", line[0], re.DOTALL | re.X)
            else:
                data = re.findall(
                    """
                    ()by
                    (.*?)
                    (?:
                        (?:with|via)
                        (.*?)
                        (?:\sid\s|$)
                        |\sid\s
                    )""", line[0], re.DOTALL | re.X)

            delay = (org_time - next_time).seconds
            if delay < 0:
                delay = 0

            try:
                ftime = org_time.utctimetuple()
                ftime = time.strftime('%m/%d/%Y %I:%M:%S %p', ftime)
                r[c] = {
                    'Timestmp': org_time.isoformat(),
                    'Time': ftime,
                    'Delay': delay,
                    'Direction': [x.replace('\n', ' ') for x in list(map(str.strip, data[0]))]
                }
                c -= 1
            except IndexError:
                pass

        for i in list(r.values()):
            if i['Direction'][0]:
                graph.append(["From: %s" % i['Direction'][0], i['Delay']])
            else:
                graph.append(["By: %s" % i['Direction'][1], i['Delay']])

        totalDelay = sum([x['Delay'] for x in list(r.values())])
        fTotalDelay = utility_processor()['duration'](totalDelay)
        delayed = True if totalDelay else False

        custom_style = Style(
            background='transparent',
            plot_background='transparent',
            font_family='googlefont:Open Sans',
            # title_font_size=12,
        )
        line_chart = pygal.HorizontalBar(
            style=custom_style, height=250, legend_at_bottom=True,
            tooltip_border_radius=10)
        line_chart.tooltip_fancy_mode = False
        line_chart.title = 'Total Delay is: %s' % fTotalDelay
        line_chart.x_title = 'Delay in seconds.'
        for i in graph:
            line_chart.add(i[0], i[1])
        chart = line_chart.render(is_unicode=True)

        summary = {
            'From': n.get('From') or getHeaderVal('from', mail_data),
            'To': n.get('to') or getHeaderVal('to', mail_data),
            'Cc': n.get('cc') or getHeaderVal('cc', mail_data),
            'Subject': n.get('Subject') or getHeaderVal('Subject', mail_data),
            'MessageID': n.get('Message-ID') or getHeaderVal('Message-ID', mail_data),
            'Date': n.get('Date') or getHeaderVal('Date', mail_data),
        }

        security_headers = ['Received-SPF', 'Authentication-Results',
                            'DKIM-Signature', 'ARC-Authentication-Results']
        

        # Generate a unique ID for this analysis
        analysis_id = str(uuid.uuid4())[:8]  # Use first 8 chars of UUID for shorter URLs
        
        # Save the analysis data
        save_data = {
            'data': r,
            'delayed': delayed,
            'summary': summary,
            'raw_headers': mail_data,  # Store original headers
            'chart': chart,
            'security_headers': security_headers,
            'timestamp': datetime.now().isoformat()  # Convert datetime to string
        }
        
        file_path = os.path.join(STORAGE_DIR, f"{analysis_id}.json")
        with open(file_path, 'w') as f:
            json.dump(save_data, f)



        #return render_template(
        #    'index.html', data=r, delayed=delayed, summary=summary,
        #    n=n, chart=chart, security_headers=security_headers)
        # Redirect to the same page with the ID parameter
        return redirect(url_for('index', id=analysis_id))
    else:
        return render_template('index.html')
    
@app.route('/about')
def about():
    return render_template('about.html')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Mail Header Analyser")
    parser.add_argument("-d", "--debug", action="store_true", default=False,
                        help="Enable debug mode")
    parser.add_argument("-b", "--bind", default="127.0.0.1", type=str)
    parser.add_argument("-p", "--port", default="8080", type=int)
    args = parser.parse_args()

    app.debug = args.debug
    app.run(host=args.bind, port=args.port)
