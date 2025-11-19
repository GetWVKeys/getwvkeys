from flask import Blueprint, jsonify, render_template
from flask_login import current_user
from werkzeug.exceptions import BadRequest

from getwvkeys.decorators import authentication_required
from getwvkeys.shared import website_version

blueprint = Blueprint("me", __name__)


@blueprint.route("/")
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


@blueprint.route("/wvds/<id>", methods=["DELETE"])
@authentication_required()
def user_delete_wvd(id):
    if not id:
        raise BadRequest("No WVD ID provided")
    current_user.delete_wvd(id)
    return jsonify({"status_code": 200, "message": "WVD Deleted"})


@blueprint.route("/wvds", methods=["GET"])
@authentication_required()
def user_get_wvds():
    user_wvds = current_user.get_user_wvds()
    return jsonify({"status_code": 200, "message": user_wvds})


@blueprint.route("/prds/<id>", methods=["DELETE"])
@authentication_required()
def user_delete_prd(id):
    if not id:
        raise BadRequest("No PRD ID provided")
    current_user.delete_prd(id)
    return jsonify({"status_code": 200, "message": "PRD Deleted"})


@blueprint.route("/prds", methods=["GET"])
@authentication_required()
def user_get_prds():
    user_prds = current_user.get_user_prds()
    return jsonify({"status_code": 200, "message": user_prds})
