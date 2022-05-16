import os

from flask import Flask, render_template, request, send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import base64
import json
import libraries

app = Flask(__name__)
limiter = Limiter(app, key_func=get_remote_address, default_limits=["10 per minute", "1 per second"], strategy="fixed-window-elastic-expiry", headers_enabled=True)


@app.route('/')
@limiter.exempt
def home():
    return render_template("index.html", page_title='AlienMaster')


@app.route('/count')
def count():
    return str(libraries.Library().cached_number())


@app.route('/favicon.ico')
@limiter.exempt
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')


@app.route('/api', methods=['POST'])
def api():
    try:
        event_data = request.get_json(force=True)
        (password, license_, pssh, headers, buildinfo, cache, challege, response) = (
            event_data['password'] if 'password' in event_data else '', event_data['license'] if 'license' in event_data
            else '', event_data['pssh'] if 'pssh' in event_data else '',
            event_data['headers'] if 'headers' in event_data
            else '', event_data['buildInfo'] if 'buildinfo' in event_data else '', True if 'cache' in
                                                                                           event_data else False,
            True if 'challege' in event_data else False, event_data['response'] if 'response' in
                                                                                   event_data else None)
        magic = libraries.Pywidevine(password, license_, pssh, headers, buildinfo, cache=cache, response=response)
        return magic.api()
    except Exception as e:
        error = {"Error": f"{str(e)}"}
        return json.dumps(error)


@app.route('/wv', methods=['POST', 'GET'])
def wv():
    try:
        if request.method == 'POST':
            event_data = request.get_json(force=True)
            (password, license_, pssh, headers, buildinfo, cache) = (event_data['password'], event_data['license'],
                                                                     event_data['pssh'],
                                                                     event_data['headers'], event_data['buildInfo'],
                                                                     event_data['cache'])

            magic = libraries.Pywidevine(password, license_, pssh, headers, buildinfo, cache=cache)
            return magic.main()
        else:
            return render_template("error.html", page_title='GET Method is not Allowed', error="GET Method is not"
                                                                                               "Allowed")
    except Exception as e:
        return render_template("error.html", page_title='ERROR', error=str(e))


@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        blob = request.files['blob']
        key = request.files['key']
        blob_base = base64.b64encode(blob.stream.read())
        key_base = base64.b64encode(key.stream.read())
        output = libraries.Library.update_cdm(blob_base, key_base)
        return f"UPDATED: {output}"
    elif request.method == 'GET':
        return render_template('upload.html')


@app.errorhandler(429)
def ratelimit_handler(_):
    return render_template('error.html', page_title='Rate Limit Exceeded', error="Too many requests")

if __name__ == "__main__":
    app.debug = True
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
