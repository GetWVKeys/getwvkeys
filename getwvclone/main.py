import base64
import json
import os
from functools import update_wrapper, wraps
from pathlib import Path
from pprint import pprint
from sqlite3 import DatabaseError
import time

import requests
from dunamai import Style, Version
from flask import Flask, jsonify, make_response, redirect, render_template, request, send_file, send_from_directory, session, g
from flask_login import LoginManager, current_user, login_user, logout_user
from oauthlib.oauth2 import WebApplicationClient
from werkzeug.exceptions import BadRequest, Forbidden, Gone, HTTPException, Unauthorized
from werkzeug.middleware.proxy_fix import ProxyFix

from getwvclone import config, libraries
from getwvclone.utils import APIAction, DatabaseManager, construct_logger, log_date_time_string

app = Flask(__name__.split(".")[0], root_path=str(Path(__file__).parent))
app.secret_key = config.SECRET_KEY
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Logger setup
logger = construct_logger()

# create database manager instance
db_manager = DatabaseManager(logger)

login_manager = LoginManager()
login_manager.init_app(app)

client = WebApplicationClient(config.OAUTH2_CLIENT_ID)

# get current git commit sha
sha = Version.from_git().serialize(style=Style.SemVer, dirty=True)

# create library instance
library = libraries.Library(db_manager)

# Utilities
def authentication_required(exempt_methods=[], admin_only=False):
    def decorator(func):
        @wraps(func)
        def wrapped_function(*args, **kwargs):
            if request.method in exempt_methods:
                return func(*args, **kwargs)
            elif config.LOGIN_DISABLED:
                return func(*args, **kwargs)
            elif not current_user.is_authenticated:
                # check if they passed in an api key
                api_key = request.headers.get("X-API-Key") or request.form.get("X-API-Key")
                if not api_key:
                    raise Unauthorized("API Key Required")
                # check if the key is a valid user key
                is_valid = libraries.User.is_api_key_valid(db_manager, api_key)
                if not is_valid:
                    raise Forbidden("Invalid API Key")
                user = libraries.User.get_user_by_api_key(db_manager, api_key)
                if not user:
                    raise Forbidden("Invalid API Key")
                login_user(user, remember=False)
            elif admin_only and not current_user.is_admin == 1:
                raise Forbidden("This maze wasn't meant for you.")
            return func(*args, **kwargs)

        return update_wrapper(wrapped_function, func)

    return decorator


@login_manager.user_loader
def load_user(user_id):
    return libraries.User.get(db_manager, user_id)


@app.before_request
def before_request():
    request.start_time = time.time()


@app.after_request
def log_request_info(response):
    time_taken = round((time.time() - request.start_time) * 1000, 2)
    logger.info(f'{request.remote_addr} - - [{log_date_time_string()}] "{request.method} {request.path}" {response.status_code} - {current_user.id} - {time_taken}ms')
    return response


@app.route("/")
@authentication_required()
def home():
    return render_template("index.html", page_title="GetWVkeys", current_user=current_user, website_version=sha)


@app.route("/scripts")
def scripts():
    files = os.listdir(os.path.dirname(os.path.abspath(__file__)) + "/download")
    return render_template("scripts.html", script_names=files, current_user=current_user, website_version=sha)


@app.route("/count")
def count():
    return str(library.get_keycount())


@app.route("/favicon.ico")
def favicon():
    return send_from_directory(os.path.join(app.root_path, "static"), "favicon.ico", mimetype="image/vnd.microsoft.icon")


@app.route("/search", methods=["POST", "GET"])
@authentication_required()
def search():
    if request.method == "POST":
        query = request.stream.read().decode()
        if query is None or query == "":
            raise BadRequest("Missing or Invalid Search Query")
        data = library.search(query)
        if len(data) == 0:
            return render_template(
                "error.html", page_title="Error", error="Oops, there were no results. But guess what? You can contact us on our Discord server to get access to add cached keys to the database!"
            )
        else:
            data = library.search_res_to_dict(query, data)
            return render_template("cache.html", results=data)
    else:
        return render_template("search.html", page_title="Search Database", current_user=current_user, website_version=sha)


@app.route("/wv", methods=["POST"])
@authentication_required()
def wv():
    try:
        event_data = request.get_json(force=True)
        (proxy, license_url, pssh, headers, buildinfo, cache) = (
            event_data["proxy"],
            event_data["license_url"],
            event_data["pssh"],
            event_data["headers"],
            event_data["buildInfo"],
            event_data["cache"],
        )

        magic = libraries.Pywidevine(library, proxy, license_url, pssh, headers, buildinfo, cache=cache, user_id=current_user.id)
        return magic.main(library)
    except Exception as e:
        logger.exception(e)
        return render_template("error.html", page_title="Error", error=str(e))


@app.route("/dev", methods=["POST"])
@authentication_required()
def dev():
    try:
        event_data = request.get_json(force=True)
        (keys, access) = (event_data["keys"], event_data["access"])
        magic = library.dev_append(keys, access, user_id=current_user.id)
        return magic
    except Exception as e:
        logger.exception(e)
        raise BadRequest(str(e))


@app.route("/upload", methods=["GET", "POST"])
@authentication_required()
def upload_file():
    if request.method == "POST":
        user = current_user.id
        blob = request.files["blob"]
        key = request.files["key"]
        blob_base = base64.b64encode(blob.stream.read()).decode()
        key_base = base64.b64encode(key.stream.read()).decode()
        output = library.update_cdm(blob_base, key_base, user)
        return render_template("upload_complete.html", page_title="Success", buildinfo=output, website_version=sha)
    elif request.method == "GET":
        return render_template("upload.html", current_user=current_user, website_version=sha)


@app.route("/api", methods=["POST", "GET"])
@authentication_required(exempt_methods=["GET"])
def curl():
    if request.method == "POST":
        try:
            event_data = request.get_json(force=True)
            (proxy, license_url, pssh, headers, buildinfo, cache) = (
                event_data["proxy"] if "proxy" in event_data else "",
                event_data["license_url"],
                event_data["pssh"],
                event_data["headers"] if "headers" in event_data else "",
                event_data["buildInfo"] if "buildInfo" in event_data else "",
                event_data["cache"] if "cache" in event_data else True,
            )
            magic = libraries.Pywidevine(library, proxy, license_url, pssh, headers, buildinfo, cache=cache, user_id=current_user.id)
            return magic.main(library, curl=True)

        except Exception as e:
            logger.exception(e)
            raise BadRequest(str(e))
    else:
        return render_template("api.html", current_user=current_user, website_version=sha)


@app.route("/pywidevine", methods=["POST"])
@authentication_required()
def pywidevine():
    try:
        event_data = request.get_json(force=True)
        (proxy, license_url, pssh, headers, buildinfo, cache, response) = (
            event_data["proxy"] if "proxy" in event_data else "",
            event_data["license_url"] if "license_url" in event_data else "",
            event_data["pssh"] if "pssh" in event_data else "",
            event_data["headers"] if "headers" in event_data else "",
            event_data["buildInfo"] if "buildInfo" in event_data else "",
            event_data["cache"] if "cache" in event_data else True,
            event_data["response"] if "response" in event_data else None,
        )
        magic = libraries.Pywidevine(library, proxy, license_url, pssh, headers, buildinfo, cache=cache, response=response, user_id=current_user.id)
        return magic.api(library)
    except Exception as e:
        logger.exception(e)
        raise BadRequest(str(e))


@app.route("/faq")
def faq():
    return render_template("faq.html", page_title="FAQ", current_user=current_user, website_version=sha)


@app.route("/download/<file>")
def downloadfile(file):
    path = os.path.join(app.root_path, "download", file)
    if not os.path.isfile(path):
        return "FILE NOT FOUND"
    return send_file(path, as_attachment=True)


# auth endpoints
@app.route("/login")
def login():
    if current_user.is_authenticated:
        return redirect("/")
    request_uri = client.prepare_request_uri(
        "https://discord.com/api/oauth2/authorize",
        redirect_uri=[
            config.OAUTH2_REDIRECT_URL,
            config.OAUTH2_REDIRECT_URL_DEV,
        ][config.IS_DEVELOPMENT],
        scope=["guilds", "guilds.members.read", "identify"],
    )
    return render_template("login.html", auth_url=request_uri, current_user=current_user, website_version=sha)


@app.route("/login/callback")
def login_callback():
    code = request.args.get("code")
    if not code:
        return render_template("error.html", page_title="Error", error="No code provided")
    token_url, headers, body = client.prepare_token_request(
        "https://discord.com/api/oauth2/token",
        authorization_response=request.url,
        redirect_url=[
            config.OAUTH2_REDIRECT_URL,
            config.OAUTH2_REDIRECT_URL_DEV,
        ][config.IS_DEVELOPMENT],
        code=code,
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(config.OAUTH2_CLIENT_ID, config.OAUTH2_CLIENT_SECRET),
    )
    client.parse_request_body_response(json.dumps(token_response.json()))
    uri, headers, body = client.add_token("https://discord.com/api/oauth2/@me")
    info_response = requests.get(uri, headers=headers, data=body)
    info = info_response.json()
    userinfo = info.get("user")
    user = libraries.User.get(db_manager, userinfo.get("id"))
    if not user:
        libraries.User.create(db_manager, userinfo)
        user = libraries.User.get(db_manager, userinfo.get("id"))
    # update the user info in the database as some fields can change like username
    libraries.User.update(db_manager, userinfo)
    # check if the user is in the getwvkeys server
    is_in_guild = libraries.User.user_is_in_guild(client.access_token)
    if not is_in_guild:
        session.clear()
        return (
            render_template(
                "error.html",
                page_title="Error",
                error="You must be in our Discord support server and be verified to use this service. You can join our server here: https://discord.gg/sMBEwDEGQg",
            ),
            403,
        )
    # check if the user is verified
    user_is_verified = libraries.User.user_is_verified(client.access_token)
    if not user_is_verified:
        session.clear()
        return (
            render_template(
                "error.html",
                page_title="Error",
                error="You must be verified to use this service. Please read the #rules channel.",
            ),
            403,
        )
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
        libraries.User.disable_user(db_manager, user_id)
        return jsonify({"error": False}), 200
    elif action == APIAction.DISABLE_USER_BULK.value:
        user_ids = data.get("user_ids")
        if not user_ids:
            raise BadRequest("Bad Request")
        libraries.User.disable_users(db_manager, user_ids)
        return jsonify({"error": False}), 200
    elif action == APIAction.ENABLE_USER.value:
        user_id = data.get("user_id")
        if not user_id:
            raise BadRequest("Bad Request")
        libraries.User.enable_user(db_manager, user_id)
        return jsonify({"error": False}), 200
    elif action == APIAction.KEY_COUNT.value:
        return jsonify({"error": False, "message": library.get_keycount()}), 200
    elif action == APIAction.USER_COUNT.value:
        return jsonify({"error": False, "message": libraries.User.get_user_count(db_manager)}), 200
    elif action == APIAction.SEARCH.value:
        query = data.get("query")
        if not query:
            raise BadRequest("Bad Request")
        results = library.search(query)
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
    return (
        render_template(
            "error.html",
            page_title="Internal Server Error",
            error="Internal Server Error. Please try again later.",
        ),
        500,
    )


@app.errorhandler(HTTPException)
def http_exception(e: HTTPException):
    if request.method == "GET":
        if e.code == 401 or e.code == 403:
            return app.login_manager.unauthorized()
        return render_template("error.html", page_title=e.name, error=e.description), e.code
    else:
        return jsonify({"error": True, "code": e.code, "message": e.description}), e.code


@app.errorhandler(Gone)
def gone_exception(_):
    return (
        render_template("error.html", page_title="Gone", error="This page is no longer available."),
        410,
    )


@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect("/login?next=" + request.path)


# routes that are removed
@app.route("/pssh")
def pssh():
    raise Gone()


# routes that have been moved
@app.route("/findpssh")
def findpssh():
    return redirect("/search", 301)


def main():
    conn_res = db_manager.connect()
    if conn_res == False:
        logger.fatal("Could not connect to the database.")
        exit(1)
    app.run(config.API_HOST, config.API_PORT, debug=config.IS_DEVELOPMENT)


if __name__ == "__main__":
    main()
