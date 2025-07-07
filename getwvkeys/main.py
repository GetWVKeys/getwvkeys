"""
This file is part of the GetWVKeys project (https://github.com/GetWVKeys/getwvkeys)
Copyright (C) 2022-2024 Notaghost, Puyodead1 and GetWVKeys contributors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, version 3 of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import base64
import json
import os
import pathlib
import time
from datetime import datetime, timezone
from functools import update_wrapper, wraps
from io import BytesIO
from pathlib import Path
from sqlite3 import DatabaseError

import requests
from dunamai import Version
from flask import (
    Flask,
    Request,
    g,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    send_file,
    send_from_directory,
    session,
)
from flask_caching import Cache
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

from alembic import command
from alembic.config import Config
from getwvkeys import config, libraries

# these need to be kept
from getwvkeys.models.Shared import db
from getwvkeys.models.TrafficLog import TrafficLog
from getwvkeys.redis import Redis
from getwvkeys.user import FlaskUser
from getwvkeys.utils import Blacklist, DRMType, UserFlags, Validators, construct_logger

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
website_version = Version.from_git().serialize(
    style=None, dirty=True, format="{base}-post.{distance}+{commit}.{dirty}.{branch}"
)

# create library instance
library = libraries.Library(db)

# create validators instance
validators = Validators()

# initialize redis instance
if not config.IS_STAGING and config.REDIS_URI is not None:
    # TODO: currently staging can reply which is unintended, but ignoring stuff like disabling users might not be ideal
    redis = Redis(app, library)
    app.config["CACHE_TYPE"] = "redis"
    app.config["CACHE_REDIS_URL"] = config.REDIS_URI
else:
    logger.warning("Redis is disabled, IPC will not work")
    app.config["CACHE_TYPE"] = "simple"
    app.config["CACHE_DEFAULT_TIMEOUT"] = 300

cache = Cache(app)

# initialize blacklist class
blacklist = Blacklist()


# Utilities
def authentication_required(
    exempt_methods=[], flags_required: int = None, ignore_suspended: bool = False
):
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
                api_key = (
                    request.headers.get("X-API-Key")
                    or request.form.get("X-API-Key")
                    or request.headers.get("Authorization")
                    or request.form.get("Authorization")
                )
                if not api_key:
                    raise Unauthorized("API Key Required")

                # check if the key is a bot
                if FlaskUser.is_api_key_bot(api_key):
                    return func(*args, **kwargs)

                # check if the key is a valid user key
                user = FlaskUser.get_user_by_api_key(db, api_key)

                if not user:
                    raise Forbidden("Invalid API Key")

                login_user(user, remember=False)

            # check if the user is enabled
            current_user.check_status(ignore_suspended)

            # check if the user has the required flags
            if flags_required and not current_user.flags.has(flags_required):
                raise Forbidden("Missing Access")

            return func(*args, **kwargs)

        return update_wrapper(wrapped_function, func)

    return decorator


def on_json_loading_failed(self, e):
    raise UnsupportedMediaType()


Request.on_json_loading_failed = on_json_loading_failed


def blacklist_check(device, license_url):
    # check if the license url is blacklisted, but only run this check on GetWVKeys owned device
    if (
        (device in config.SYSTEM_WVDS or device in config.SYSTEM_PRDS)
        and blacklist.is_url_blacklisted(license_url)
        and not current_user.is_blacklist_exempt()
    ):
        raise ImATeapot()


def log_date_time_string():
    """Return the current time formatted for logging."""
    monthname = [
        None,
        "Jan",
        "Feb",
        "Mar",
        "Apr",
        "May",
        "Jun",
        "Jul",
        "Aug",
        "Sep",
        "Oct",
        "Nov",
        "Dec",
    ]
    now = time.time()
    year, month, day, hh, mm, ss, x, y, z = time.localtime(now)
    s = "%02d/%3s/%04d %02d:%02d:%02d" % (day, monthname[month], year, hh, mm, ss)
    return s


@login_manager.user_loader
def load_user(user_id):
    return FlaskUser.get(db, user_id)


@app.before_request
def start_timer():
    g.start_time = time.time()


@app.after_request
def log_request_info(response):
    try:
        duration = int((time.time() - g.start_time) * 1000)
    except Exception:
        duration = None

    if not request.path.startswith("/static") or request.path in ["/favicon.ico"]:
        log_entry = TrafficLog(
            user_id=current_user.id if current_user.is_authenticated else None,
            path=request.path,
            timestamp=datetime.now(timezone.utc),
            ip=request.headers.get("X-Forwarded-For", request.remote_addr),
            user_agent=request.headers.get("User-Agent"),
            status_code=response.status_code,
            duration_ms=duration,
        )

        db.session.add(log_entry)
        db.session.commit()

    user_id = current_user.id if current_user.is_authenticated else "N/A"
    l = f'{request.remote_addr} - - [{log_date_time_string()}] "{request.method} {request.path}" {response.status_code} - {user_id}'

    if (
        request.data
        and len(request.data) > 0
        and request.headers.get("Content-Type") == "application/json"
    ):
        l += f"\nRequest Data: {request.data.decode()}"

    logger.info(l)

    # add some headers
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = (
        "Content-Type, Authorization, X-API-Key"
    )
    return response


@app.route("/")
@authentication_required()
def index():
    return render_template(
        "index.html",
        page_title="GetWVKeys",
        current_user=current_user,
        website_version=website_version,
    )


@app.route("/faq")
@authentication_required()
def faq():
    return render_template(
        "faq.html",
        page_title="FAQ",
        current_user=current_user,
        website_version=website_version,
    )


@app.route("/scripts")
@authentication_required()
def wv_scripts():
    files = os.listdir(os.path.dirname(os.path.abspath(__file__)) + "/scripts")
    return render_template(
        "scripts.html",
        script_names=files,
        current_user=current_user,
        website_version=website_version,
    )


@app.route("/scripts/<file>")
@authentication_required()
def download_wv_script(file):
    path = pathlib.Path(app.root_path, "scripts", file)
    if not path.is_file():
        raise NotFound("File not found")
    if current_user.is_authenticated:
        data = open(path, "r").read()
        data = data.replace("__getwvkeys_api_key__", current_user.api_key, 1)
        data = data.replace("__getwvkeys_api_url__", config.API_URL, 1)
        f = BytesIO(data.encode())
        return send_file(
            f,
            as_attachment=True,
            download_name=path.name,
            mimetype="application/x-python-script",
        )
    return send_file(path, as_attachment=True)


@app.route("/count")
@cache.cached(timeout=300)
def count():
    return str(library.get_keycount())


@app.route("/favicon.ico")
def favicon():
    return send_from_directory(
        os.path.join(app.root_path, "static"),
        "favicon.ico",
        mimetype="image/vnd.microsoft.icon",
    )


@app.route("/search", methods=["POST", "GET"])
@authentication_required()
def search():
    if request.method == "POST":
        query = request.stream.read().decode()
        if not query or query == "":
            raise BadRequest("Missing or Invalid Search Query")
        data = library.search(query)
        data = library.search_res_to_dict(query, data)
        return jsonify(data)
    else:
        return render_template(
            "search.html",
            page_title="Search Database",
            current_user=current_user,
            website_version=website_version,
        )


@app.route("/keys", methods=["POST"])
@authentication_required(flags_required=UserFlags.KEY_ADDING)
def keys():
    event_data = request.get_json()
    keys = event_data.get("keys")
    if not keys or not isinstance(keys, list) or len(keys) == 0:
        raise BadRequest("Invalid Body")
    return library.add_keys(keys=keys, user_id=current_user.id)


@app.route("/upload/wvd", methods=["GET", "POST"])
@authentication_required()
def upload_wvd():
    if request.method == "POST":
        user = current_user.id
        wvd = request.files["wvd"]
        wvd_base = base64.b64encode(wvd.stream.read()).decode()
        output = library.upload_wvd(wvd_base, user)
        return render_template(
            "upload_complete.html",
            page_title="Success",
            device_hash=output,
            website_version=website_version,
            device_name="WVD",
        )
    elif request.method == "GET":
        return render_template(
            "upload.html",
            current_user=current_user,
            website_version=website_version,
            device_name="WVD",
        )


@app.route("/upload/prd", methods=["GET", "POST"])
@authentication_required()
def upload_prd():
    if request.method == "POST":
        user = current_user.id
        prd = request.files["prd"]
        prd_base = base64.b64encode(prd.stream.read()).decode()
        output = library.upload_prd(prd_base, user)
        return render_template(
            "upload_complete.html",
            page_title="Success",
            device_hash=output,
            website_version=website_version,
            device_name="PRD",
        )
    elif request.method == "GET":
        return render_template(
            "upload.html",
            current_user=current_user,
            website_version=website_version,
            device_name="PRD",
        )


@app.route("/api", methods=["GET", "POST"])
@authentication_required()
def api():
    if request.method == "GET":
        return render_template(
            "api.html", current_user=current_user, website_version=website_version
        )
    elif request.method == "POST":
        event_data = request.get_json()
        (
            license_url,
            pssh,
            proxy,
            headers,
            device_hash,
            force,
            downgrade,
            certificate,
            is_web,
            is_curl,
            response,
            session_id,
        ) = (
            event_data.get("license_url"),
            event_data.get("pssh"),
            event_data.get("proxy", ""),
            event_data.get("headers", ""),
            event_data.get("device_hash"),
            event_data.get("force", False),
            event_data.get("downgrade"),
            event_data.get("certificate"),
            event_data.get("is_web", False),
            event_data.get("is_curl", False),
            event_data.get("response"),
            event_data.get("session_id"),
        )
        if not pssh or not license_url:
            raise BadRequest("Missing Fields")

        blacklist_check(device_hash, license_url)

        drm_type: DRMType = DRMType.INVALID
        service = None

        if device_hash is None or device_hash == "":
            # try to determine the drm type from the pssh
            drm_type = library.get_pssh_drm_type(pssh)
            logger.debug(f"[DEBUG] Detected DRM type from PSSH: {drm_type}")

            # get a random device hash
            if drm_type.is_playready():
                device_hash = libraries.get_random_prd()
            elif drm_type.is_widevine():
                device_hash = libraries.get_random_wvd()
        else:
            # use the device hash to determine the drm system
            drm_type = library.get_device_drm_type(device_hash)
            logger.debug(f"[DEBUG] Detected DRM type from device hash: {drm_type}")

        if drm_type.is_widevine():
            service = libraries.Widevine(
                library=library,
                proxy=proxy,
                license_url=license_url,
                pssh=pssh,
                headers=headers,
                device_hash=device_hash,
                force=force,
                user_id=current_user.id,
                server_certificate=certificate,
                is_web=is_web,
                response=response,
                session_id=session_id,
                is_curl=is_curl,
            )
        elif drm_type.is_playready():
            service = libraries.PlayReady(
                library=library,
                proxy=proxy,
                license_url=license_url,
                pssh=pssh,
                headers=headers,
                device_hash=device_hash,
                force=force,
                user_id=current_user.id,
                downgrade=downgrade,
                is_web=is_web,
                response=response,
                session_id=session_id,
                is_curl=is_curl,
            )
        else:
            raise BadRequest("Unable to determine DRM type from PSSH or device hash")

        if not service:
            raise BadRequest("Unable to determine DRM type from PSSH or device hash")

        return service.run()


# @app.route("/vinetrimmer", methods=["POST"])
# def vinetrimmer():
#     event_data = request.get_json()
#     # validate the request body
#     if not validators.vinetrimmer_validator(event_data):
#         return jsonify({"status_code": 400, "message": "Malformed Body"})

#     # get the data
#     (method, params, token) = (
#         event_data["method"],
#         event_data["params"],
#         event_data["token"],
#     )
#     user = FlaskUser.get_user_by_api_key(db, token)
#     if not user:
#         return jsonify({"status_code": 401, "message": "Invalid API Key"})

#     if not user.flags.has(UserFlags.VINETRIMMER):
#         return jsonify({"status_code": 403, "message": "Missing Access"})

#     if method == "GetKeysX":
#         # Validate params required for method
#         if not validators.key_exchange_validator(params):
#             return jsonify({"status_code": 400, "message": "Malformed Params"})
#         return jsonify({"status_code": 501, "message": "Method Not Implemented"})
#     elif method == "GetKeys":
#         # Validate params required for method
#         if not validators.keys_validator(params):
#             return jsonify({"status_code": 400, "message": "Malformed Params"})
#         (cdmkeyresponse, session_id) = (params["cdmkeyresponse"], params["session_id"])
#         magic = libraries.Pywidevine(
#             library,
#             user.id,
#             response=cdmkeyresponse,
#             session_id=session_id,
#             buildinfo=None,
#         )
#         res = magic.vinetrimmer(library)
#         return jsonify({"status_code": 200, "message": res})
#     elif method == "GetChallenge":
#         # Validate params required for method
#         if not validators.challenge_validator(params):
#             return jsonify({"status_code": 400, "message": "Malformed Params"})
#         (init, cert, raw, licensetype, device) = (
#             params["init"],
#             params["cert"],
#             params["raw"],
#             params["licensetype"],
#             params["device"],
#         )
#         magic = libraries.Pywidevine(
#             library, user.id, pssh=init, buildinfo=device, server_certificate=cert
#         )
#         res = magic.vinetrimmer(library)
#         return jsonify({"status_code": 200, "message": res})

#     return jsonify({"status_code": 400, "message": "Invalid Method"})


@app.route("/vault", methods=["GET"])
def vault():
    service = request.args.get("service").lower()
    password = request.args.get("password")
    kid = request.args.get("kid")
    key = request.args.get("key")
    user = FlaskUser.get_user_by_api_key(db, password)

    if not user:
        return jsonify({"status_code": 401, "message": "Invalid API Key"})

    if not user.flags.has(UserFlags.KEY_ADDING):
        return jsonify({"status_code": 403, "message": "Missing Access"})

    if len(kid) != 32 or not kid:
        return jsonify({"status_code": 403, "message": "Invalid Kid Length"})

    if not key:
        data = library.search(kid)
        data = library.search_res_to_dict(kid, data)
        data["status_code"] = 200
        for keys in data["keys"]:
            k = keys["key"].split(":")
            keys["kid"] = k[0]
            keys["key"] = k[-1]
        del data["kid"]
        return jsonify(data)
    else:
        keys = [{"key": f"{kid}:{key}", "license_url": f"https://{service}/"}]
        library.add_keys(keys=keys, user_id=current_user.id)
        return jsonify({"message": "Added", "inserted": True, "status_code": 200})


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
    return render_template(
        "login.html",
        auth_url=request_uri,
        current_user=current_user,
        website_version=website_version,
    )


@app.route("/login/callback")
def login_callback():
    code = request.args.get("code")
    if not code:
        return render_template(
            "error.html", page_title="Error", error="No code provided"
        )
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
    user = FlaskUser.get(db, userinfo.get("id"))
    if not user:
        FlaskUser.create(db, userinfo)
        user = FlaskUser.get(db, userinfo.get("id"))
    else:
        # update the user info in the database as some fields can change like username
        FlaskUser.update(db, userinfo)
    # check if the user is in the getwvkeys server
    is_in_guild = FlaskUser.user_is_in_guild(client.access_token)
    if not is_in_guild:
        session.clear()
        raise Forbidden(
            "You must be in our Discord support server and be verified to use this service. You can join our server here: https://discord.gg/ezK22qJFR8"
        )
    # check if the user is verified
    user_is_verified = FlaskUser.user_is_verified(client.access_token)
    if not user_is_verified:
        session.clear()
        raise Forbidden(
            "You must be verified to use this service. Please read the #rules channel."
        )
    login_user(user, True)
    # flash("Welcome, {}!".format(user.username), "success")
    resp = make_response(redirect("/"))
    resp.set_cookie("api_key", user.api_key)
    return resp


@app.route("/logout")
@authentication_required(ignore_suspended=True)
def logout():
    logout_user()
    return redirect("/")


@app.route("/me")
@authentication_required()
def user_profile():
    user_wvds = current_user.get_user_wvds()
    user_prds = current_user.get_user_prds()
    return render_template(
        "profile.html",
        current_user=current_user,
        wvds=user_wvds,
        prds=user_prds,
        website_version=website_version,
    )


@app.route("/me/wvds/<id>", methods=["DELETE"])
@authentication_required()
def user_delete_wvd(id):
    if not id:
        raise BadRequest("No WVD ID provided")
    current_user.delete_wvd(id)
    return jsonify({"status_code": 200, "message": "WVD Deleted"})


@app.route("/me/wvds", methods=["GET"])
@authentication_required()
def user_get_wvds():
    user_wvds = current_user.get_user_wvds()
    return jsonify({"status_code": 200, "message": user_wvds})


@app.route("/me/prds/<id>", methods=["DELETE"])
@authentication_required()
def user_delete_prd(id):
    if not id:
        raise BadRequest("No PRD ID provided")
    current_user.delete_prd(id)
    return jsonify({"status_code": 200, "message": "PRD Deleted"})


@app.route("/me/prds", methods=["GET"])
@authentication_required()
def user_get_prds():
    user_prds = current_user.get_user_prds()
    return jsonify({"status_code": 200, "message": user_prds})


# error handlers
@app.errorhandler(DatabaseError)
def database_error(e: Exception):
    logger.exception(
        e
    )  # database errors should always be logged as they are unexpected
    if request.method == "GET":
        return (
            render_template(
                "error.html",
                title=str(e),
                details="",
                current_user=current_user,
                website_version=website_version,
            ),
            400,
        )
    return jsonify({"error": True, "code": 400, "message": str(e)}), 400


@app.errorhandler(HTTPException)
def http_exception(e: HTTPException):
    if config.IS_DEVELOPMENT:
        logger.exception(e)
    if request.method == "GET":
        if e.code == 401:
            return app.login_manager.unauthorized()
        return (
            render_template(
                "error.html",
                title=e.name,
                details=e.description,
                current_user=current_user,
                website_version=website_version,
            ),
            e.code,
        )
    return jsonify({"error": True, "code": e.code, "message": e.description}), e.code


@app.errorhandler(Gone)
def gone_exception(e: Gone):
    if config.IS_DEVELOPMENT:
        logger.exception(e)
    if request.method == "GET":
        return (
            render_template(
                "error.html",
                title=e.name,
                details="The page you are looking for is no longer available.",
                current_user=current_user,
                website_version=website_version,
            ),
            e.code,
        )
    return (
        jsonify(
            {
                "error": True,
                "code": 500,
                "message": "The page you are looking for is no longer available.",
            }
        ),
        e.code,
    )


@app.errorhandler(OAuth2Error)
def oauth2_error(e: OAuth2Error):
    if config.IS_DEVELOPMENT:
        logger.exception(e)
    logger.error(e)
    return (
        render_template(
            "error.html",
            title=e.description,
            details="The code was probably already used or is invalid.",
            current_user=current_user,
            website_version=website_version,
        ),
        e.status_code,
    )


@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect("/login?next=" + request.path)


class Moved(HTTPException):
    code = 410


# routes that are removed
@app.route("/upload")
def upload():
    raise Gone(
        "This route is no longer available, please use /upload/prd or /upload/wvd instead"
    )


# routes that have been moved
@app.route("/findpssh", methods=["GET", "POST"])
def findpssh():
    return (
        jsonify(
            {
                "error": True,
                "code": 301,
                "message": "The page you are looking for has been moved to /search.",
            }
        ),
        409,
    )


@app.route("/dev", methods=["GET", "POST"])
def dev():
    return (
        jsonify(
            {
                "error": True,
                "code": 301,
                "message": "The page you are looking for has been moved to /keys.",
            }
        ),
        409,
    )


@app.route("/download/<file>")
def downloadfile_old(file):
    return redirect("/scripts/{}".format(file), 301)


@app.route("/me/cdms/<id>", methods=["DELETE"])
@authentication_required()
def user_delete_cdm(id):
    return redirect("/me/wvds/{}".format(id), 307)


@app.route("/me/wvds", methods=["GET"])
@authentication_required()
def user_get_cdms():
    return redirect("/me/wvds", 307)


def main():
    app.run(
        config.API_HOST,
        config.API_PORT,
        debug=config.IS_DEVELOPMENT,
        use_reloader=False,
    )


def run_migrations():
    alembic_cfg = Config("alembic.ini")
    command.upgrade(alembic_cfg, "head")


if __name__ == "__main__":
    main()
