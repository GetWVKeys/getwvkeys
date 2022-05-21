import os
from sqlite3 import DatabaseError

from flask import Flask, flash, redirect, render_template, request, send_from_directory, send_file, url_for
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from oauthlib.oauth2 import WebApplicationClient
import base64
import json

import requests
import libraries
import sys

from dotenv import load_dotenv

# load .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24)

login_manager = LoginManager()
login_manager.init_app(app)

client = WebApplicationClient(os.environ.get("OAUTH2_CLIENT_ID"))

def get_ip():  # InCase Request IP Needed
    if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
        ip = request.environ['REMOTE_ADDR']
    else:
        ip = request.environ['HTTP_X_FORWARDED_FOR']
    return ip

@login_manager.user_loader
def load_user(user_id):
    return libraries.User.get(user_id)

@app.route('/')
@login_required
def home():
    return render_template("index.html", page_title='GetWVkeys', is_authenticated=current_user.is_authenticated)


@app.route('/scripts')
def scripts():
    files = os.listdir(os.path.dirname(os.path.abspath(__file__)) + '/download')
    return render_template("scripts.html", script_names=files, is_authenticated=current_user.is_authenticated)


@app.route('/count')
def count():
    return str(libraries.Library().cached_number())


@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')


@app.route('/findpssh', methods=['POST', 'GET'])
@login_required
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
        return render_template("find.html", page_title='SEARCH DATABASE', is_authenticated=current_user.is_authenticated)


@app.route('/wv', methods=['POST'])
@login_required
def wv():
    try:
        event_data = request.get_json(force=True)
        (proxy, license_, pssh, headers, buildinfo, cache) = (event_data['proxy'], event_data['license'],
                                                                event_data['pssh'],
                                                                event_data['headers'], event_data['buildInfo'],
                                                                event_data['cache'])

        magic = libraries.Pywidevine(proxy, license_, pssh, headers, buildinfo, cache=cache)
        return magic.main()
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
@login_required
def upload_file():
    if request.method == 'POST':
        blob = request.files['blob']
        key = request.files['key']
        blob_base = base64.b64encode(blob.stream.read()).decode()
        key_base = base64.b64encode(key.stream.read()).decode()
        output = libraries.Library().update_cdm(blob_base, key_base)
        return render_template('upload_complete.html', page_title="Success", buildinfo=output)
    elif request.method == 'GET':
        return render_template('upload.html', is_authenticated=current_user.is_authenticated)


@app.route('/api', methods=['POST', 'GET'])
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
        return render_template("api.html", is_authenticated=current_user.is_authenticated)


@app.route('/pywidevine', methods=['POST'])
@login_required
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
    return render_template("faq.html", page_title='FAQ', is_authenticated=current_user.is_authenticated)


@app.route('/download/<file>')
def downloadfile(file):
    path = os.path.join(app.root_path, "download", file)
    if not os.path.isfile(path):
        return "FILE NOT FOUND"
    return send_file(path, as_attachment=True)

# auth endpoints
@app.route("/login")
def login():
    if current_user.is_authenticated:
        flash("You are already logged in.", "warning")
        return redirect("/")
    request_uri = client.prepare_request_uri("https://discord.com/api/oauth2/authorize", redirect_uri=request.base_url + "/callback", scope=["guilds", "guilds.join", "guilds.members.read", "identify"])
    return render_template("login.html", auth_url=request_uri, is_authenticated=current_user.is_authenticated)

@app.route("/login/callback")
def login_callback():
    code = request.args.get("code")
    if not code:
        return render_template("error.html", page_title='ERROR', error="No code provided")
    token_url, headers, body = client.prepare_token_request(
        "https://discord.com/api/oauth2/token",
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(os.environ.get("OAUTH2_CLIENT_ID"), os.environ.get("OAUTH2_CLIENT_SECRET")),
    )
    client.parse_request_body_response(json.dumps(token_response.json()))
    uri, headers, body = client.add_token("https://discord.com/api/oauth2/@me")
    info_response = requests.get(uri, headers=headers, data=body)
    info = info_response.json()
    userinfo = info.get("user")
    user = libraries.User.get(userinfo.get("id"))
    if not user:
        libraries.User.create(userinfo)
        user = libraries.User.get(userinfo.get("id"))
    # TODO: get users guilds
    # TODO: check if user is in getwvkeys server
    # TODO: add user to getwvkeys server if they're not in it
    # TODO: check if user has verified role in getwvkeys server
    login_user(user, True)
    flash("Welcome, {}!".format(user.username), "success")
    return redirect("/")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/")

@app.errorhandler(DatabaseError)
def database_error(e):
    print(e)
    return render_template('error.html', page_title='Internal Server Error',
                           error="Internal Server Error. Please try again later.")

@app.errorhandler(405)
def method_not_allowed(_):
    return render_template('error.html', page_title='Method Not Allowed',
                           error="Method Not Allowed.")

@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect('/login?next=' + request.path)

if __name__ == "__main__":
    app.debug = True
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))
