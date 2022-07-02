import base64
import json
import os
import pathlib
import time
from functools import update_wrapper, wraps
from io import BytesIO
from pathlib import Path
from sqlite3 import DatabaseError

import requests
import validators as validationlib
from dunamai import Style, Version
from flask import (
    Flask,
    Request,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    send_file,
    send_from_directory,
    session,
)
from flask_login import LoginManager, current_user, login_user, logout_user
from oauthlib.oauth2 import WebApplicationClient
from oauthlib.oauth2.rfc6749.errors import OAuth2Error
from werkzeug.exceptions import (
    BadRequest,
    Forbidden,
    Gone,
    HTTPException,
    ImATeapot,
    NotFound,
    Unauthorized,
    UnsupportedMediaType,
)
from werkzeug.middleware.proxy_fix import ProxyFix

from getwvclone import config, libraries

# these need to be kept
from getwvclone.models.CDM import CDM
from getwvclone.models.Key import Key
from getwvclone.models.Shared import db
from getwvclone.models.User import User
from getwvclone.redis import Redis
from getwvclone.utils import Blacklist, UserFlags, Validators, construct_logger

app = Flask(__name__.split(".")[0], root_path=str(Path(__file__).parent))
app.config["SQLALCHEMY_DATABASE_URI"] = config.SQLALCHEMY_DATABASE_URI
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.secret_key = config.SECRET_KEY
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
db.init_app(app)

# Logger setup
logger = construct_logger()

login_manager = LoginManager()
login_manager.init_app(app)

client = WebApplicationClient(config.OAUTH2_CLIENT_ID)

# get current git commit sha
sha = Version.from_git().serialize(style=Style.SemVer, dirty=True, format="{base}-post.{distance}+{commit}.{dirty}.{branch}")

# create library instance
library = libraries.Library(db)

# create validators instance
validators = Validators()

# initialize redis instance
redis = Redis(app, library)

# initialize blacklist class
blacklist = Blacklist()

# Utilities
def authentication_required(exempt_methods=[], flags_required: int = None):
    def decorator(func):
        @wraps(func)
        def wrapped_function(*args, **kwargs):
            if request.method in exempt_methods:
                return func(*args, **kwargs)
            if config.LOGIN_DISABLED:
                return func(*args, **kwargs)

            # handle api keys
            if not current_user.is_authenticated:
                # check if they passed in an api key
                api_key = request.headers.get("X-API-Key") or request.form.get("X-API-Key") or request.headers.get("Authorization") or request.form.get("Authorization")
                if not api_key:
                    raise Unauthorized("API Key Required")

                # check if the key is a bot
                if libraries.User.is_api_key_bot(api_key):
                    return func(*args, **kwargs)

                # check if the key is a valid user key
                user = libraries.User.get_user_by_api_key(db, api_key)

                if not user:
                    raise Forbidden("Invalid API Key")

                login_user(user, remember=False)

            # check if the user is enabled
            current_user.check_status()

            # check if the user has the required flags
            if flags_required and not current_user.flags.has(flags_required):
                raise Forbidden("Missing Access")

            return func(*args, **kwargs)

        return update_wrapper(wrapped_function, func)

    return decorator


def on_json_loading_failed(self, e):
    raise UnsupportedMediaType()


Request.on_json_loading_failed = on_json_loading_failed


def log_date_time_string():
    """Return the current time formatted for logging."""
    monthname = [None, "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    now = time.time()
    year, month, day, hh, mm, ss, x, y, z = time.localtime(now)
    s = "%02d/%3s/%04d %02d:%02d:%02d" % (day, monthname[month], year, hh, mm, ss)
    return s


@login_manager.user_loader
def load_user(user_id):
    return libraries.User.get(db, user_id)


@app.after_request
def log_request_info(response):
    user_id = current_user.id if current_user.is_authenticated else "N/A"
    l = f'{request.remote_addr} - - [{log_date_time_string()}] "{request.method} {request.path}" {response.status_code} - {user_id}'

    if request.data and len(request.data) > 0 and request.headers.get("Content-Type") == "application/json":
        l += f"\nRequest Data: {request.data.decode()}"

    logger.info(l)
    return response


@app.route("/")
@authentication_required()
def home():
    return render_template("index.html", page_title="GetWVkeys", current_user=current_user, website_version=sha)


@app.route("/faq")
def faq():
    return render_template("faq.html", page_title="FAQ", current_user=current_user, website_version=sha)


@app.route("/scripts")
def scripts():
    files = os.listdir(os.path.dirname(os.path.abspath(__file__)) + "/download")
    return render_template("scripts.html", script_names=files, current_user=current_user, website_version=sha)


@app.route("/scripts/<file>")
def downloadfile(file):
    path = pathlib.Path(app.root_path, "download", file)
    if not path.is_file():
        raise NotFound("File not found")
    if current_user.is_authenticated:
        data = open(path, "r").read()
        data = data.replace("__getwvkeys_api_key__", current_user.api_key, 1)
        f = BytesIO(data.encode())
        return send_file(f, as_attachment=True, download_name=path.name, mimetype="application/x-python-script")
    return send_file(path, as_attachment=True)


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
        if not query or query == "":
            raise BadRequest("Missing or Invalid Search Query")
        data = library.search(query)
        if len(data) == 0:
            raise NotFound("No keys found")
        else:
            data = library.search_res_to_dict(query, data)
            return render_template("cache.html", results=data)
    else:
        return render_template("search.html", page_title="Search Database", current_user=current_user, website_version=sha)


@app.route("/keys", methods=["POST"])
@authentication_required(flags_required=UserFlags.KEY_ADDING)
def keys():
    event_data = request.get_json()
    keys = event_data.get("keys")
    if not keys or not isinstance(keys, list) or len(keys) == 0:
        raise BadRequest("Invalid Body")
    return library.add_keys(keys, user_id=current_user.id)


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


@app.route("/wv", methods=["POST"])
@authentication_required()
def wv():
    event_data = request.get_json(force=True)
    (proxy, license_url, pssh, headers, buildinfo, cache) = (
        event_data.get("proxy", ""),
        event_data.get("license_url"),
        event_data.get("pssh"),
        event_data.get("headers", ""),
        event_data.get("buildInfo", ""),
        event_data.get("cache", True),
    )
    if not pssh or not license_url or not validationlib.url(license_url):
        raise BadRequest("Missing or Invalid Fields")
    if blacklist.is_url_blacklisted(license_url):
        raise ImATeapot()

    magic = libraries.Pywidevine(library, proxy=proxy, license_url=license_url, pssh=pssh, headers=headers, buildinfo=buildinfo, cache=cache, user_id=current_user.id)
    return magic.main(library)


@app.route("/api", methods=["POST", "GET"])
@authentication_required(exempt_methods=["GET"])
def curl():
    if request.method == "POST":
        event_data = request.get_json()
        (proxy, license_url, pssh, headers, buildinfo, cache, server_certificate, disable_privacy) = (
            event_data.get("proxy", ""),
            event_data.get("license_url"),
            event_data.get("pssh"),
            event_data.get("headers", ""),
            event_data.get("buildInfo", ""),
            event_data.get("cache", True),
            event_data.get("certificate"),
            event_data.get("disable_privacy", False),
        )
        if not pssh or not license_url:
            raise BadRequest("Missing Fields")
        if blacklist.is_url_blacklisted(license_url):
            raise ImATeapot()
        magic = libraries.Pywidevine(
            library,
            proxy=proxy,
            license_url=license_url,
            pssh=pssh,
            headers=headers,
            buildinfo=buildinfo,
            cache=cache,
            user_id=current_user.id,
            server_certificate=server_certificate,
            disable_privacy=disable_privacy,
        )
        return magic.main(library, curl=True)
    else:
        return render_template("api.html", current_user=current_user, website_version=sha)


@app.route("/pywidevine", methods=["POST"])
@authentication_required()
def pywidevine():
    event_data = request.get_json()
    (proxy, license_url, pssh, headers, buildinfo, cache, response, server_certificate, disable_privacy) = (
        event_data.get("proxy", ""),
        event_data.get("license_url"),
        event_data.get("pssh"),
        event_data.get("headers", ""),
        event_data.get("buildInfo", ""),
        event_data.get("cache", True),
        event_data.get("response"),
        event_data.get("certificate"),
        event_data.get("disable_privacy", False),
    )
    if not pssh or not license_url or not validationlib.url(license_url):
        raise BadRequest("Missing or Invalid Fields")
    if blacklist.is_url_blacklisted(license_url):
        raise ImATeapot()
    magic = libraries.Pywidevine(
        library,
        proxy=proxy,
        license_url=license_url,
        pssh=pssh,
        headers=headers,
        buildinfo=buildinfo,
        cache=cache,
        response=response,
        user_id=current_user.id,
        server_certificate=server_certificate,
        disable_privacy=disable_privacy,
    )
    return magic.api(library)


@app.route("/vinetrimmer", methods=["POST"])
def vinetrimmer():
    event_data = request.get_json()
    # validate the request body
    if not validators.vinetrimmer_validator(event_data):
        return jsonify({"status_code": 400, "message": "Malformed Body"})

    # get the data
    (method, params, token) = (event_data["method"], event_data["params"], event_data["token"])
    user = libraries.User.get_user_by_api_key(db, token)
    if not user:
        return jsonify({"status_code": 401, "message": "Invalid API Key"})

    if not user.flags.has(UserFlags.VINETRIMMER):
        return jsonify({"status_code": 403, "message": "Missing Access"})

    if method == "GetKeysX":
        # Validate params required for method
        if not validators.key_exchange_validator(params):
            return jsonify({"status_code": 400, "message": "Malformed Params"})
        return jsonify({"status_code": 501, "message": "Method Not Implemented"})
    elif method == "GetKeys":
        # Validate params required for method
        if not validators.keys_validator(params):
            return jsonify({"status_code": 400, "message": "Malformed Params"})
        (cdmkeyresponse, session_id) = (params["cdmkeyresponse"], params["session_id"])
        magic = libraries.Pywidevine(library, user.id, response=cdmkeyresponse, session_id=session_id)
        res = magic.vinetrimmer(library)
        return jsonify({"status_code": 200, "message": res})
    elif method == "GetChallenge":
        # Validate params required for method
        if not validators.challenge_validator(params):
            return jsonify({"status_code": 400, "message": "Malformed Params"})
        (init, cert, raw, licensetype, device) = (params["init"], params["cert"], params["raw"], params["licensetype"], params["device"])
        magic = libraries.Pywidevine(library, user.id, pssh=init, buildinfo=device, server_certificate=cert)
        res = magic.vinetrimmer(library)
        return jsonify({"status_code": 200, "message": res})

    return jsonify({"status_code": 400, "message": "Invalid Method"})


# auth endpoints
@app.route("/login")
def login():
    if current_user.is_authenticated:
        return redirect("/")
    request_uri = client.prepare_request_uri(
        "https://discord.com/api/oauth2/authorize",
        redirect_uri=config.OAUTH2_REDIRECT_URL,
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
        redirect_url=config.OAUTH2_REDIRECT_URL,
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
    user = libraries.User.get(db, userinfo.get("id"))
    if not user:
        libraries.User.create(db, userinfo)
        user = libraries.User.get(db, userinfo.get("id"))
    else:
        # update the user info in the database as some fields can change like username
        libraries.User.update(db, userinfo)
    # check if the user is in the getwvkeys server
    is_in_guild = libraries.User.user_is_in_guild(client.access_token)
    if not is_in_guild:
        session.clear()
        raise Forbidden("You must be in our Discord support server and be verified to use this service. You can join our server here: https://discord.gg/sMBEwDEGQg")
    # check if the user is verified
    user_is_verified = libraries.User.user_is_verified(client.access_token)
    if not user_is_verified:
        session.clear()
        raise Forbidden("You must be verified to use this service. Please read the #rules channel.")
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


# error handlers
@app.errorhandler(DatabaseError)
def database_error(e: DatabaseError):
    logger.exception(e)
    if request.method == "GET":
        return render_template("error.html", title=str(e), details="", current_user=current_user, website_version=sha), 500
    return jsonify({"error": True, "code": 500, "message": str(e)}), 500


@app.errorhandler(Exception)
def database_error(e: Exception):
    logger.exception(e)
    if request.method == "GET":
        return render_template("error.html", title=str(e), details="", current_user=current_user, website_version=sha), 400
    return jsonify({"error": True, "code": 400, "message": str(e)}), 400


@app.errorhandler(HTTPException)
def http_exception(e: HTTPException):
    if request.method == "GET":
        if e.code == 401:
            return app.login_manager.unauthorized()
        logger.error(e)
        return render_template("error.html", title=e.name, details=e.description, current_user=current_user, website_version=sha), e.code
    logger.error(e)
    return jsonify({"error": True, "code": e.code, "message": e.description}), e.code


@app.errorhandler(Gone)
def gone_exception(e: Gone):
    if request.method == "GET":
        return render_template("error.html", title=e.name, details="The page you are looking for is no longer available.", current_user=current_user, website_version=sha), e.code
    return jsonify({"error": True, "code": 500, "message": "The page you are looking for is no longer available."}), e.code


@app.errorhandler(OAuth2Error)
def oauth2_error(e: OAuth2Error):
    logger.error(e)
    return render_template("error.html", title=e.description, details="The code was probably already used or is invalid.", current_user=current_user, website_version=sha), e.status_code


@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect("/login?next=" + request.path)


# routes that are removed
@app.route("/pssh")
def pssh():
    raise Gone()


# routes that have been moved
@app.route("/findpssh", methods=["GET", "POST"])
def findpssh():
    return jsonify({"error": True, "code": 301, "message": "The page you are looking for has been moved to /search."}), 409


@app.route("/dev", methods=["GET", "POST"])
def dev():
    return jsonify({"error": True, "code": 301, "message": "The page you are looking for has been moved to /keys."}), 409


@app.route("/download/<file>")
def downloadfile_old(file):
    return redirect("/scripts/{}".format(file), 301)


def main():
    app.run(config.API_HOST, config.API_PORT, debug=config.IS_DEVELOPMENT, use_reloader=False)


def setup():
    with app.app_context():
        db.create_all()


if __name__ == "__main__":
    main()
