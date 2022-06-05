import base64
import json
import os
from functools import update_wrapper, wraps
from pprint import pprint
from sqlite3 import DatabaseError

import requests
from dunamai import Style, Version
from flask import (Flask, flash, jsonify, make_response, redirect,
                   render_template, request, send_file, send_from_directory,
                   session)
from flask_login import LoginManager, current_user, login_user, logout_user
from oauthlib.oauth2 import WebApplicationClient
from werkzeug.exceptions import (BadRequest, Forbidden, HTTPException,
                                 Unauthorized)
from werkzeug.middleware.proxy_fix import ProxyFix

from getwvclone import libraries, config
from getwvclone.utils import construct_logger, APIAction

app = Flask(__name__, instance_relative_config=True)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.config.from_object('getwvclone.config')
app.config.from_pyfile('config.py')

# Logger setup
logger = construct_logger()

login_manager = LoginManager()
login_manager.init_app(app)

client = WebApplicationClient(app.config.get("OAUTH2_CLIENT_ID"))

# get current git commit sha
sha = Version.from_git().serialize(style=Style.SemVer, dirty=True)


# Utilities
def authentication_required(exempt_methods=[], admin_only=False):
    def decorator(func):
        @wraps(func)
        def wrapped_function(*args, **kwargs):
            if request.method in exempt_methods:
                return func(*args, **kwargs)
            elif app.config.get('LOGIN_DISABLED'):
                return func(*args, **kwargs)
            elif not current_user.is_authenticated:
                # check if they passed in an api key
                api_key = request.headers.get(
                    "X-API-Key") or request.form.get("X-API-Key")
                if not api_key:
                    raise Unauthorized("API Key Required")
                # check if the key is a valid user key
                is_valid = libraries.User.is_api_key_valid(api_key)
                if not is_valid:
                    raise Forbidden("Invalid API Key")
                # user = libraries.User.get_user_by_api_key(api_key)
                # if not user:
                #     raise Forbidden("Invalid API Key")
                # login_user(user, remember=True)
            elif admin_only and not current_user.is_admin == 1:
                raise Forbidden("This maze wasn't meant for you.")
            return func(*args, **kwargs)
        return update_wrapper(wrapped_function, func)
    return decorator


@login_manager.user_loader
def load_user(user_id):
    return libraries.User.get(user_id)


@app.route('/')
@authentication_required()
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
@authentication_required()
def find():
    if request.method == 'POST':
        pssh = request.stream.read().decode()
        if pssh is None or pssh == "":
            return ""
        data = libraries.Library().match(pssh)
        if data == {}:
            return render_template("error.html", page_title='Error', error="Not Found in our Database But you can add it, contact us on our discord server to have the powers to add cache keys in the database ")
        else:
            return render_template("cache.html", cache=data)
    else:
        return render_template("find.html", page_title='SEARCH DATABASE', current_user=current_user, website_version=sha)


@app.route('/wv', methods=['POST'])
@authentication_required()
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
@authentication_required()
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
@authentication_required()
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
@authentication_required(exempt_methods=["GET"])
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
@authentication_required()
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
@authentication_required()
def logout():
    logout_user()
    return redirect("/")


@app.route("/me")
@authentication_required()
def user_profile():
    user_cdms = current_user.get_user_cdms()
    return render_template("profile.html", current_user=current_user, cdms=user_cdms, website_version=sha)


# admin routes
# @app.route("/admin/users/<id>", methods=["GET"])
# @authentication_required(admin_only=True)
# def admin_user(id):
#     user = libraries.User.get(id)

#     if request.method == "GET":
#         """view user"""
#         return render_template("admin_user.html", current_user=current_user, user=user, website_version=sha)
#     elif request.method == "PATCH":
#         """edit user"""
#         data = request.get_json()
#         if not data:
#             return json.dumps({"error": "No data provided"}), 400
#         try:
#             user.patch(data)
#             user = libraries.User.get(id)
#             return jsonify(user.to_json()), 200
#         except HTTPException as e:
#             return json.dumps({"error": f"{e.description}"}), e.code
#         except Exception as e:
#             logger.error(e)
#             return json.dumps({"error": "Bad Request"}), 400


@app.route("/admin/api", methods=["POST"])
@authentication_required(admin_only=True)
def admin_api():
    data = request.get_json()
    if not data:
        raise BadRequest("Bad Request")

    action = data.get("action")
    if action == APIAction.DISABLE_USER.value:
        user_id = data.get("user_id")
        if not user_id:
            raise BadRequest("Bad Request")
        libraries.User.disable_user(user_id)
        return jsonify({"error": False}), 200
    elif action == APIAction.DISABLE_USER_BULK.value:
        user_ids = data.get("user_ids")
        if not user_ids:
            raise BadRequest("Bad Request")
        libraries.User.disable_users(user_ids)
        return jsonify({"error": False}), 200
    elif action == APIAction.ENABLE_USER.value:
        user_id = data.get("user_id")
        if not user_id:
            raise BadRequest("Bad Request")
        libraries.User.enable_user(user_id)
        return jsonify({"error": False}), 200
    elif action == APIAction.KEY_COUNT.value:
        return jsonify({"error": False, "message": libraries.Library().cached_number()}), 200
    elif action == APIAction.USER_COUNT.value:
        return jsonify({"error": False, "message": libraries.User.get_user_count()}), 200
    elif action == APIAction.SEARCH.value:
        query = data.get("query")
        if not query:
            raise BadRequest("Bad Request")
        results = libraries.Library.search(query)
        keys = []
        pprint(results)
        for result in results:
            a = result[0]
            b: list[dict] = json.loads(a)
            for k in b:
                keys.append(k.get("key"))
        return jsonify({"error": False, "message": keys}), 200

    raise BadRequest("Bad Request")


# error handlers
@app.errorhandler(DatabaseError)
def database_error(e):
    logger.error("[Database] {}".format(e))
    return render_template('error.html', page_title='Internal Server Error',
                           error="Internal Server Error. Please try again later."), 500


@app.errorhandler(HTTPException)
def http_exception(e: HTTPException):
    if request.method == "GET":
        if e.code == 401 or e.code == 403:
            return app.login_manager.unauthorized()
        return render_template('error.html', page_title=e.name, error=e.description), e.code
    else:
        return jsonify({
            "error": True,
            "code": e.code,
            "message": e.description
        }), e.code


@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect('/login?next=' + request.path)


# routes that are removed
@app.route('/pssh')
def pssh():
    return render_template("error.html", page_title='Gone', error="This page is no longer available."), 410


def main():
    app.run(config.API_HOST, config.API_PORT)


if __name__ == "__main__":
    main()
