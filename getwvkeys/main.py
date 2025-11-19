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

import atexit
import base64
import json
import os
import pathlib
import tempfile
import threading
import time
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from sqlite3 import DatabaseError

import requests
from flask import (
    Flask,
    Request,
    current_app,
    g,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    send_file,
    send_from_directory,
    session,
    url_for,
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
    UnsupportedMediaType,
)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename

from alembic import command
from alembic.config import Config
from getwvkeys import config
from getwvkeys.blueprints.api_import_blueprint import blueprint as api_import_blueprint
from getwvkeys.blueprints.api_remotecdm_blueprint import (
    blueprint as api_remotecdm_blueprint,
)
from getwvkeys.blueprints.me_blueprint import blueprint as me_blueprint

# these need to be kept
from getwvkeys.decorators import authentication_required
from getwvkeys.import_worker import ImportWorker
from getwvkeys.models.Shared import db
from getwvkeys.models.TrafficLog import TrafficLog
from getwvkeys.redis import Redis
from getwvkeys.services.PlayReady import PlayReady
from getwvkeys.services.Widevine import Widevine
from getwvkeys.shared import library, website_version
from getwvkeys.user import FlaskUser
from getwvkeys.utils import Blacklist, DRMType, UserFlags, Validators, construct_logger

app = Flask(__name__.split(".")[0], root_path=str(Path(__file__).parent))
app.config["SQLALCHEMY_DATABASE_URI"] = config.SQLALCHEMY_DATABASE_URI
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.secret_key = config.SECRET_KEY
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
db.init_app(app)

# Logger setup
logger = construct_logger()

login_manager = LoginManager()
login_manager.init_app(app)

client = WebApplicationClient(config.OAUTH2_CLIENT_ID)

app.import_worker = ImportWorker(library, app)
app.import_worker.start()
atexit.register(lambda: app.import_worker.stop())


# create validators instance
validators = Validators()

CACHE_TIME = 30 * 60  # seconds


# Background task for updating key count cache
def update_key_count_cache_periodically():
    while True:
        try:
            time.sleep(CACHE_TIME)
            with app.app_context():
                if library.should_refresh_cache(max_age_seconds=CACHE_TIME):
                    library.update_cached_keycount()
                    logger.info("Background task: Key count cache updated")
        except Exception as e:
            logger.error(f"Background task error: {e}")


# Start background task in a daemon thread
cache_update_thread = threading.Thread(target=update_key_count_cache_periodically, daemon=True)
cache_update_thread.start()
logger.info("Started background key count cache update task")

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

# Initialize key count cache on startup
with app.app_context():
    try:
        # Check if cache exists, if not initialize it
        if not library.get_cached_keycount():
            logger.info("Initializing key count cache on startup...")
            library.update_cached_keycount()
            logger.info(f"Key count cache initialized with {library.get_cached_keycount()} keys")

        # Initialize system user on startup
        from getwvkeys.user import FlaskUser

        system_user = FlaskUser.get_system_user(db)
        logger.info(f"System user initialized: {system_user.username} (ID: {system_user.id})")

        # Build rotation device configuration cache from system user devices
        wvds, prds = library.build_rotation_config_cache()
        logger.info(f"Rotation config initialized: {len(wvds)} WVDs, {len(prds)} PRDs")
    except Exception as e:
        logger.error(f"Failed to initialize on startup: {e}")


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


def get_real_ip():
    return request.headers.get("CF-Connecting-IP") or request.headers.get("X-Real-IP") or request.remote_addr


@login_manager.user_loader
def load_user(user_id):
    return FlaskUser.get(db, user_id)


@app.before_request
def start_timer():
    g.start_time = time.time()


@app.after_request
def log_request_info(response):
    real_ip = get_real_ip()
    try:
        duration = int((time.time() - g.start_time) * 1000)
    except Exception:
        duration = None

    if not request.path.startswith("/static") and not request.path in ["/favicon.ico"]:
        log_entry = TrafficLog(
            user_id=current_user.id if current_user.is_authenticated else None,
            path=request.path,
            timestamp=datetime.now(timezone.utc),
            ip=real_ip,
            user_agent=request.headers.get("User-Agent"),
            status_code=response.status_code,
            duration_ms=duration,
        )

        db.session.add(log_entry)
        db.session.commit()

    user_id = current_user.id if current_user.is_authenticated else "N/A"
    l = f'{real_ip} - - [{log_date_time_string()}] "{request.method} {request.path}" {response.status_code} - {user_id}'

    if request.data and len(request.data) > 0 and request.headers.get("Content-Type") == "application/json":
        l += f"\nRequest Data: {request.data.decode()}"

    logger.info(l)

    # add some headers
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-API-Key"
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
    # Check if cache should be refreshed (older than 1 hour)
    if library.should_refresh_cache(max_age_seconds=3600):
        library.update_cached_keycount()

    return str(library.get_cached_keycount())


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


@app.route("/upload/system/wvd", methods=["GET", "POST"])
@authentication_required()
def upload_system_wvd():
    if request.method == "POST":
        wvd = request.files["wvd"]
        enable_rotation = request.form.get("enable_rotation", "off")
        # Convert enable_rotation to boolean
        enable_rotation = enable_rotation == "on"
        wvd_base = base64.b64encode(wvd.stream.read()).decode()
        output = library.assign_system_wvd(wvd_base, enable_rotation)
        return render_template(
            "upload_complete.html",
            page_title="Success",
            device_hash=output,
            website_version=website_version,
            device_name="WVD",
        )
    elif request.method == "GET":
        return render_template(
            "upload_system.html",
            current_user=current_user,
            website_version=website_version,
            device_name="WVD",
        )


@app.route("/upload/system/prd", methods=["GET", "POST"])
@authentication_required()
def upload_system_prd():
    if request.method == "POST":
        prd = request.files["prd"]
        enable_rotation = request.form.get("enable_rotation", "off")
        # Convert enable_rotation to boolean
        enable_rotation = enable_rotation == "on"
        prd_base = base64.b64encode(prd.stream.read()).decode()
        output = library.assign_system_prd(prd_base, enable_rotation)
        return render_template(
            "upload_complete.html",
            page_title="Success",
            device_hash=output,
            website_version=website_version,
            device_name="PRD",
        )
    elif request.method == "GET":
        return render_template(
            "upload_system.html",
            current_user=current_user,
            website_version=website_version,
            device_name="PRD",
        )


@app.route("/api", methods=["GET", "POST"])
@authentication_required()
def api():
    if request.method == "GET":
        return render_template("api.html", current_user=current_user, website_version=website_version)
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
                device_hash = library.get_random_prd()
            elif drm_type.is_widevine():
                device_hash = library.get_random_wvd()
        else:
            # use the device hash to determine the drm system
            drm_type = library.get_device_drm_type(device_hash)
            logger.debug(f"[DEBUG] Detected DRM type from device hash: {drm_type}")

        if drm_type.is_widevine():
            service = Widevine(
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
            service = PlayReady(
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
        raise Forbidden("You must be verified to use this service. Please read the #rules channel.")
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


@app.route("/upload/database", methods=["GET", "POST"])
def upload_database():
    if request.method == "GET":
        return render_template(
            "upload_db.html",
            current_user=current_user,
            website_version=website_version,
        )

    if "database" not in request.files:
        return (
            render_template(
                "upload_db_result.html",
                error="No file uploaded",
                current_user=current_user,
                website_version=website_version,
            ),
            400,
        )

    file = request.files["database"]
    if file.filename == "":
        return (
            render_template(
                "upload_db_result.html",
                error="No file selected",
                current_user=current_user,
                website_version=website_version,
            ),
            400,
        )

    valid_extensions = [".db", ".sqlite", ".sqlite3", ".db3"]
    if not any(file.filename.lower().endswith(ext) for ext in valid_extensions):
        return (
            render_template(
                "upload_db_result.html",
                error="Invalid file type",
                current_user=current_user,
                website_version=website_version,
            ),
            400,
        )

    preview_mode = request.form.get("preview") == "on"

    try:
        filename = secure_filename(file.filename)
        temp_dir = tempfile.gettempdir()
        temp_path = os.path.join(temp_dir, filename)
        print(temp_path)
        file.save(temp_path)

        if preview_mode:
            result = library.validate_sqlite_database(temp_path)

            os.remove(temp_path)

            if not result["valid"]:
                return render_template("upload_db_result.html", error=result["error"]), 400

            return render_template(
                "upload_db_result.html",
                preview_mode=True,
                summary={
                    "total_tables": result["total_tables"],
                    "total_keys": result["total_keys"],
                    "imported_keys": 0,
                    "skipped_keys": 0,
                },
                tables=result["tables"],
                current_user=current_user,
                website_version=website_version,
            )
        else:
            import_worker = current_app.import_worker
            task_id = import_worker.create_task(current_user.id, filename, temp_path)

            os.remove(temp_path)

            return redirect(url_for("import_progress", task_id=task_id))

    except Exception as e:
        if "temp_path" in locals() and os.path.exists(temp_path):
            os.remove(temp_path)
        return (
            render_template(
                "upload_db_result.html", current_user=current_user, website_version=website_version, error=str(e)
            ),
            500,
        )


@app.route("/upload/database/progress/<task_id>")
def import_progress(task_id):
    """Show import progress page"""
    return render_template(
        "upload_db_progress.html",
        task_id=task_id,
        current_user=current_user,
        website_version=website_version,
    )


# error handlers
@app.errorhandler(DatabaseError)
def database_error(e: Exception):
    logger.exception(e)  # database errors should always be logged as they are unexpected
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
                "code": 410,
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


# routes that are removed
@app.route("/upload")
def upload():
    raise Gone("This route is no longer available, please use /upload/prd or /upload/wvd instead")


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


@app.route("/pywidevine", methods=["GET", "POST"])
def pywidevine():
    return redirect("/api", 307)


@app.route("/wv", methods=["GET", "POST"])
def wv():
    return redirect("/api", 307)


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


app.register_blueprint(api_import_blueprint, url_prefix="/api/import")
app.register_blueprint(api_remotecdm_blueprint, url_prefix="/api/remotecdm")
app.register_blueprint(me_blueprint, url_prefix="/me")


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


def run_migrations():
    alembic_cfg = Config("alembic.ini")
    command.upgrade(alembic_cfg, "head")


if __name__ == "__main__":
    main()
