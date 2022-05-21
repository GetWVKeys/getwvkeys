import os
from sqlite3 import DatabaseError

from flask import Flask, render_template, request, send_from_directory, send_file
from flask_limiter import Limiter
import base64
import json
import libraries
import sys


def get_remote_address():
    return request.headers.get("CF-Connecting-IP", request.remote_addr)


app = Flask(__name__)


# limiter = Limiter(app, key_func=get_remote_address, default_limits=["10 per minute"],
#                   strategy="fixed-window-elastic-expiry", headers_enabled=True)
#
#
# @limiter.request_filter
# def ip_whitelist():
#     return request.remote_addr == ""


@app.route('/')
# @limiter.exempt
def home():
    return render_template("index.html", page_title='GetWVkeys')


def get_ip():  # InCase Request IP Needed
    if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
        ip = request.environ['REMOTE_ADDR']
    else:
        ip = request.environ['HTTP_X_FORWARDED_FOR']
    return ip


@app.route('/scripts')
def scripts():
    files = os.listdir(os.path.dirname(os.path.abspath(__file__)) + '/download')
    return render_template("scripts.html", script_names=files)


@app.route('/count')
# # @limiter.exempt
def count():
    return str(libraries.Library().cached_number())


@app.route('/favicon.ico')
# @limiter.exempt
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')


@app.route('/findpssh', methods=['POST', 'GET'])
# @limiter.exempt
def find():
    if request.method == 'POST':
        pssh = request.stream.read().decode()
        if pssh is None or pssh == "":
            return ""
        data = libraries.Library().match(pssh)
        if data == {}:
            return render_template("error.html", page_title='ERROR', error="Not Found")
        else:
            return render_template("cache.html", cache=data)
    else:
        return render_template("find.html", page_title='SEARCH DATABASE')


@app.route('/wv', methods=['POST', 'GET'])
# @limiter.limit("1 per sec")
def wv():
    try:
        if request.method == 'POST':
            event_data = request.get_json(force=True)
            (proxy, license_, pssh, headers, buildinfo, cache) = (event_data['proxy'], event_data['license'],
                                                                  event_data['pssh'],
                                                                  event_data['headers'], event_data['buildInfo'],
                                                                  event_data['cache'])

            magic = libraries.Pywidevine(proxy, license_, pssh, headers, buildinfo, cache=cache)
            return magic.main()
        else:
            return render_template("error.html", page_title='GET Method is not Allowed', error="GET Method is not"
                                                                                               "Allowed")
    except Exception as e:
        return render_template("error.html", page_title='ERROR', error=str(e))


@app.route('/dev', methods=['POST'])
# @limiter.limit("1 per sec")
def dev():
    try:
        event_data = request.get_json(force=True)
        (pssh, keys, access) = (event_data['pssh'], event_data['keys'], event_data['access'])
        magic = libraries.Library().dev_append(pssh, keys, access)
        return magic
    except (Exception,):
        type, value, traceback = sys.exc_info()
        resp = {
            "error": str(type) + str(value)
        }
        return json.dumps(resp)


@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        blob = request.files['blob']
        key = request.files['key']
        blob_base = base64.b64encode(blob.stream.read()).decode()
        key_base = base64.b64encode(key.stream.read()).decode()
        output = libraries.Library().update_cdm(blob_base, key_base)
        return render_template('upload_complete.html', page_title="Success", buildinfo=output)
    elif request.method == 'GET':
        return render_template('upload.html')


@app.route('/api', methods=['POST', 'GET'])
# @limiter.limit("1 per sec")
def curl():
    if request.method == 'POST':
        try:
            event_data = request.get_json(force=True)
            (proxy, license_, pssh, headers, buildinfo, cache) = (
                event_data['proxy'] if "proxy" in event_data else '', event_data['license'],
                event_data['pssh'], event_data['headers'] if 'headers' in event_data else '',
                event_data['buildInfo'] if 'buildinfo' in event_data else '',
                event_data['cache'] if 'cache' in event_data else True)
            magic = libraries.Pywidevine(proxy, license_, pssh, headers, buildinfo, cache=cache)
            return magic.main(curl=True)

        except Exception as e:
            return json.dumps({"error": str(e)})

    else:
        return render_template("api.html", page_title='GET Method is not Allowed', error="GET Method is not Allowed")


@app.route('/pywidevine', methods=['POST'])
# @limiter.limit("2 per sec")
def pywidevine():
    try:
        event_data = request.get_json(force=True)
        (password, license_, pssh, headers, buildinfo, cache, challege, response) = (
            event_data['password'] if 'password' in event_data else '', event_data['license'] if 'license' in event_data
            else '', event_data['pssh'] if 'pssh' in event_data else '',
            event_data['headers'] if 'headers' in event_data
            else '', event_data['buildInfo'] if 'buildinfo' in event_data else '', event_data['cache'] if 'cache' in
                                                                                                          event_data else True,
            True if 'challege' in event_data else False, event_data['response'] if 'response' in
                                                                                   event_data else None)
        magic = libraries.Pywidevine(password, license_, pssh, headers, buildinfo, cache=cache, response=response)
        return magic.api()
    except Exception as e:
        error = {"Error": f"{str(e)}"}
        return json.dumps(error)


@app.route('/faq')
def faq():
    return render_template("faq.html", page_title='FAQ')


@app.route('/download/<file>')
def downloadfile(file):
    path = os.path.join(app.root_path, "download", file)
    if not os.path.isfile(path):
        return "FILE NOT FOUND"
    return send_file(path, as_attachment=True)


@app.errorhandler(429)
def ratelimit_handler(_):
    return render_template('error.html', page_title='Rate Limit Exceeded',
                           error="Too many requests. Please try again later.")


@app.errorhandler(DatabaseError)
def database_error(_):
    return render_template('error.html', page_title='Internal Server Error',
                           error="Internal Server Error. Please try again later.")


if __name__ == "__main__":
    app.debug = True
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))
