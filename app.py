from functools import wraps
import os
import git
from sqlite3 import DatabaseError

from flask import Flask, flash, make_response, redirect, render_template, request, send_from_directory, send_file, session
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

app = Flask(__name__, instance_relative_config=True)
app.config.from_object('config')
app.config.from_pyfile('config.py')

login_manager = LoginManager()
login_manager.init_app(app)

client = WebApplicationClient(app.config.get("OAUTH2_CLIENT_ID"))

# get current git commit sha
repo = git.Repo(search_parent_directories=True)
sha = repo.git.rev_parse(repo.head.object.hexsha,
                         short=7) if repo else "unknown"

# Utilities


def get_ip():  # InCase Request IP Needed
    if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
        ip = request.environ['REMOTE_ADDR']
    else:
        ip = request.environ['HTTP_X_FORWARDED_FOR']
    return ip


def api_key_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method != "POST":
            return f(*args, **kwargs)
        api_key = request.headers.get(
            "X-API-Key") or request.form.get("X-API-Key")
        print(request.headers)
        if not api_key:
            return "API Key Required", 401
        is_valid = libraries.User.api_key_is_valid(api_key)
        if not is_valid:
            return "Invalid API Key", 403
        return f(*args, **kwargs)
    return decorated_function


@login_manager.user_loader
def load_user(user_id):
    return libraries.User.get(user_id)


@app.route('/')
@login_required
def home():
    return render_template("index.html", page_title='GetWVkeys', current_user=current_user, website_version=sha)


@app.route('/scripts')
def scripts():
    files = os.listdir(os.path.dirname(
        os.path.abspath(__file__)) + '/download')
    return render_template("scripts.html", script_names=files, current_user=current_user, website_version=sha)


@app.route('/count')
def count():
    return str(libraries.Library().cached_number())


@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')


@app.route('/findpssh', methods=['POST', 'GET'])
@login_required
@api_key_required
def find():
    if request.method == 'POST':
        pssh = request.stream.read().decode()
        if pssh is None or pssh == "":
            return ""
        data = libraries.Library().match(pssh)
        if data == {}:
            return render_template("error.html", page_title='Error', error="No Matches Found")
        else:
            return render_template("cache.html", cache=data)
    else:
        return render_template("find.html", page_title='SEARCH DATABASE', current_user=current_user, website_version=sha)


@app.route('/wv', methods=['POST'])
@api_key_required
def wv():
    try:
        event_data = request.get_json(force=True)
        (proxy, license_, pssh, headers, buildinfo, cache) = (event_data['proxy'], event_data['license'],
                                                              event_data['pssh'],
                                                              event_data['headers'], event_data['buildInfo'],
                                                              event_data['cache'])

        magic = libraries.Pywidevine(
            proxy, license_, pssh, headers, buildinfo, cache=cache)
        return magic.main()
    except Exception as e:
        return render_template("error.html", page_title='Error', error=str(e))


@app.route('/dev', methods=['POST'])
@api_key_required
def dev():
    try:
        event_data = request.get_json(force=True)
        (pssh, keys, access) = (
            event_data['pssh'], event_data['keys'], event_data['access'])
        magic = libraries.Library().dev_append(pssh, keys, access)
        return magic
    except Exception as e:
        resp = {
            "error": str(e)
        }
        return json.dumps(resp)


@app.route('/upload', methods=['GET', 'POST'])
@login_required
@api_key_required
def upload_file():
    if request.method == 'POST':
        user = current_user.id
        blob = request.files['blob']
        key = request.files['key']
        blob_base = base64.b64encode(blob.stream.read()).decode()
        key_base = base64.b64encode(key.stream.read()).decode()
        output = libraries.Library().update_cdm(blob_base, key_base, user)
        return render_template('upload_complete.html', page_title="Success", buildinfo=output, website_version=sha)
    elif request.method == 'GET':
        return render_template('upload.html', current_user=current_user, website_version=sha)


@app.route('/api', methods=['POST', 'GET'])
@api_key_required
def curl():
    if request.method == 'POST':
        try:
            event_data = request.get_json(force=True)
            (proxy, license_, pssh, headers, buildinfo, cache) = (
                event_data['proxy'] if "proxy" in event_data else '', event_data['license'],
                event_data['pssh'], event_data['headers'] if 'headers' in event_data else '',
                event_data['buildInfo'] if 'buildInfo' in event_data else '',
                event_data['cache'] if 'cache' in event_data else True)
            magic = libraries.Pywidevine(
                proxy, license_, pssh, headers, buildinfo, cache=cache)
            return magic.main(curl=True)

        except Exception as e:
            return json.dumps({"error": str(e)})
    else:
        return render_template("api.html", current_user=current_user, website_version=sha)


@app.route('/pywidevine', methods=['POST'])
@api_key_required
def pywidevine():
    try:
        event_data = request.get_json(force=True)
        (password, license_, pssh, headers, buildinfo, cache, challege, response) = (
            event_data['password'] if 'password' in event_data else '', event_data['license'] if 'license' in event_data
            else '', event_data['pssh'] if 'pssh' in event_data else '',
            event_data['headers'] if 'headers' in event_data
            else '', event_data['buildInfo'] if 'buildInfo' in event_data else '', event_data['cache'] if 'cache' in
                                                                                                          event_data else True,
            True if 'challege' in event_data else False, event_data['response'] if 'response' in
                                                                                   event_data else None)
        magic = libraries.Pywidevine(
            password, license_, pssh, headers, buildinfo, cache=cache, response=response)
        return magic.api()
    except Exception as e:
        error = {"Error": f"{str(e)}"}
        return json.dumps(error)


@app.route('/faq')
def faq():
    return render_template("faq.html", page_title='FAQ', current_user=current_user, website_version=sha)


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
    request_uri = client.prepare_request_uri("https://discord.com/api/oauth2/authorize", redirect_uri=app.config.get(
        "OAUTH2_REDIRECT_URL"), scope=["guilds", "guilds.members.read", "identify"])
    return render_template("login.html", auth_url=request_uri, current_user=current_user, website_version=sha)


@app.route("/login/callback")
def login_callback():
    code = request.args.get("code")
    if not code:
        return render_template("error.html", page_title='Error', error="No code provided")
    token_url, headers, body = client.prepare_token_request(
        "https://discord.com/api/oauth2/token",
        authorization_response=request.url,
        redirect_url=app.config.get("OAUTH2_REDIRECT_URL"),
        code=code
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(app.config.get("OAUTH2_CLIENT_ID"),
              app.config.get("OAUTH2_CLIENT_SECRET")),
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
    # update the user info in the database as some fields can change like username
    libraries.User.update(userinfo)
    # check if the user is in the getwvkeys server
    is_in_guild = libraries.User.user_is_in_guild(client.access_token)
    if not is_in_guild:
        session.clear()
        return render_template("error.html", page_title="Error", error="You must be in our Discord support server and be verified to use this service. You can join our server here: https://discord.gg/sMBEwDEGQg"), 403
    # check if the user is verified
    user_is_verified = libraries.User.user_is_verified(client.access_token)
    if not user_is_verified:
        session.clear()
        return render_template("error.html", page_title="Error", error="You must be verified to use this service. Please read the #rules channel."), 403
    login_user(user, True)
    # flash("Welcome, {}!".format(user.username), "success")
    resp = make_response(redirect("/"))
    resp.set_cookie("api_key", user.api_key)
    return resp


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/")


@app.route("/me")
@login_required
def user_profile():
    user_cdms = current_user.get_user_cdms()
    return render_template("profile.html", current_user=current_user, cdms=user_cdms, website_version=sha)


# error handlers
@app.errorhandler(DatabaseError)
def database_error(e):
    print(e)
    return render_template('error.html', page_title='Internal Server Error',
                           error="Internal Server Error. Please try again later."), 500


@app.errorhandler(405)
def method_not_allowed(_):
    return render_template('error.html', page_title='Method Not Allowed',
                           error="Method Not Allowed."), 405


@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect('/login?next=' + request.path)


# routes that are removed
@app.route('/pssh')
def pssh():
    return render_template("error.html", page_title='Gone', error="This page is no longer available."), 410


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))
