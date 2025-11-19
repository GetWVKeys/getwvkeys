from flask import Blueprint, jsonify, request
from flask_login import current_user
from pywidevine import __version__ as pywidevine_version

from getwvkeys import config
from getwvkeys.decorators import (
    ensure_body_keys,
    optional_auth,
    remotecdm_require_cdmids,
    remotecdm_validate_cdmid,
)
from getwvkeys.shared import library

blueprint = Blueprint("api_remotecdm", __name__)


# pywidevine remotecdm implementation is kind of retarded, pretty sure cloudflare is going to overwrite this though
@blueprint.after_request
def add_server_header(response):
    response.headers["Server"] = f"pywidevine serve v{pywidevine_version}"

    return response


@blueprint.route("/")
@optional_auth()
def remote_cdm_ping():
    return jsonify({"status": 200, "message": "pong"})


@blueprint.route("/<cdm_id>", methods=["GET"])
@optional_auth()
@remotecdm_validate_cdmid()
def remote_cdm_config(cdm_id: str):
    if cdm_id == "widevine":
        return jsonify(
            {
                "device_name": "getwvkeys",
                "device_type": "ANDROID",  # not used
                "host": config.API_URL + "/api/remotecdm/widevine",
                "secret": current_user.api_key if current_user.is_authenticated else "getwvkeys",
                "security_level": 99,  # not used
                "system_id": 9999,  # not used
            }
        )
    else:
        return jsonify(
            {
                "device_name": "getwvkeys",
                "host": config.API_URL + "/api/remotecdm/playready",
                "secret": current_user.api_key if current_user.is_authenticated else "getwvkeys",
                "security_level": "999",  # not used
            }
        )


@blueprint.route("/<cdm_id>/<device_name>/open", methods=["GET"])
# @remotecdm_authentication_required()
@optional_auth()
@remotecdm_validate_cdmid()
def remote_cdm_open(cdm_id: str, device_name: str):
    return library.remote_cdm_open(cdm_id, device_name)


@blueprint.route("/<cdm_id>/<device_name>/close/<session_id>", methods=["GET"])
# @remotecdm_authentication_required()
@optional_auth()
@remotecdm_validate_cdmid()
def remote_cdm_close(cdm_id: str, device_name: str, session_id: str):
    session_id = bytes.fromhex(session_id)
    return library.remote_cdm_close(cdm_id, device_name, session_id)


@blueprint.route("/<cdm_id>/<device_name>/set_service_certificate", methods=["POST"])
# @remotecdm_authentication_required()
@optional_auth()
@remotecdm_validate_cdmid()
@remotecdm_require_cdmids(cdm_ids=["widevine"])
@ensure_body_keys(required_keys=["session_id", "certificate"])
def remote_cdm_set_service_certificate(cdm_id: str, device_name: str):

    event_data = request.get_json()
    (session_id, certificate) = (event_data["session_id"], event_data["certificate"])

    session_id = bytes.fromhex(session_id)

    return library.remote_cdm_set_service_certificate(cdm_id, device_name, session_id, certificate)


@blueprint.route("/<cdm_id>/<device_name>/get_service_certificate", methods=["POST"])
# @remotecdm_authentication_required()
@optional_auth()
@remotecdm_validate_cdmid()
@remotecdm_require_cdmids(cdm_ids=["widevine"])
@ensure_body_keys(required_keys=["session_id"])
def remote_cdm_get_service_certificate(cdm_id: str, device_name: str):
    event_data = request.get_json()
    session_id = event_data["session_id"]
    session_id = bytes.fromhex(session_id)

    return library.remote_cdm_get_service_certificate(cdm_id, device_name, session_id)


@blueprint.route("/<cdm_id>/<device_name>/get_license_challenge", methods=["POST"])
@blueprint.route("/<cdm_id>/<device_name>/get_license_challenge/<license_type>", methods=["POST"])
# @remotecdm_authentication_required()
@optional_auth()
@remotecdm_validate_cdmid()
@ensure_body_keys(required_keys=["session_id", "init_data"])
def remote_cdm_license_challenge(cdm_id: str, device_name: str, license_type: str = "STREAMING"):
    event_data = request.get_json()
    (session_id, init_data) = (event_data["session_id"], event_data["init_data"])
    session_id = bytes.fromhex(session_id)
    return library.remote_cdm_license_challenge(cdm_id, device_name, license_type, session_id, init_data)


@blueprint.route("/<cdm_id>/<device_name>/parse_license", methods=["POST"])
# @remotecdm_authentication_required()
@optional_auth()
@remotecdm_validate_cdmid()
@ensure_body_keys(required_keys=["session_id", "license_message"])
def remote_cdm_parse_license(cdm_id: str, device_name: str):
    event_data = request.get_json()
    (session_id, license_message) = (event_data["session_id"], event_data["license_message"])
    session_id = bytes.fromhex(session_id)
    return library.remote_cdm_parse_license(cdm_id, device_name, session_id, license_message)


@blueprint.route("/<cdm_id>/<device_name>/get_keys", methods=["POST"])
@blueprint.route("/<cdm_id>/<device_name>/get_keys/<key_type>", methods=["POST"])
# @remotecdm_authentication_required()
@optional_auth()
@remotecdm_validate_cdmid()
@ensure_body_keys(required_keys=["session_id"])
def remote_cdm_get_keys(cdm_id: str, device_name: str, key_type: str = "STREAMING"):
    event_data = request.get_json()
    session_id = event_data["session_id"]
    session_id = bytes.fromhex(session_id)
    return library.remote_cdm_get_keys(
        cdm_id, device_name, key_type, session_id, current_user.id if current_user.is_authenticated else None
    )
