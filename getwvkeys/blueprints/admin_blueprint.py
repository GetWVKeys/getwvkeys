from flask import Blueprint, current_app, jsonify, render_template, request
from flask_login import current_user
from werkzeug.exceptions import BadRequest

from getwvkeys.decorators import authentication_required
from getwvkeys.models import WVD
from getwvkeys.models.PRD import PRD
from getwvkeys.models.Shared import db
from getwvkeys.shared import library, website_version
from getwvkeys.user import FlaskUser
from getwvkeys.utils import UserFlags, prd_to_dict, wvd_to_dict

blueprint = Blueprint("api_import", __name__)


@blueprint.route("/admin/system-devices")
@authentication_required(flags_required=UserFlags.ADMIN)
def admin_system_devices():
    return render_template(
        "admin_devices.html",
        current_user=current_user,
        website_version=website_version,
    )


@blueprint.route("/admin/api-system-devices", methods=["GET"])
@authentication_required(flags_required=UserFlags.ADMIN)
def admin_get_system_devices():
    try:
        system_user = FlaskUser.get_system_user(db)
        wvds = system_user.user_model.wvds
        prds = system_user.user_model.prds

        wvd_data = []
        for wvd in wvds:
            device = wvd.to_device()
            wvd_data.append(
                {
                    **wvd_to_dict(device),
                    "hash": wvd.hash,
                    "id": wvd.id,
                    "enabled_for_rotation": wvd.enabled_for_rotation,
                }
            )

        prd_data = []
        for prd in prds:
            device = prd.to_device()
            prd_data.append(
                {
                    **prd_to_dict(device),
                    "hash": prd.hash,
                    "id": prd.id,
                    "enabled_for_rotation": prd.enabled_for_rotation,
                }
            )

        return jsonify({"wvds": wvd_data, "prds": prd_data})
    except Exception as e:
        logger.error(f"Error getting system devices: {e}")
        return jsonify({"error": True, "message": str(e)}), 500


@blueprint.route("/admin/system-devices/<device_type>/<int:device_id>/rotation", methods=["PATCH"])
@authentication_required(flags_required=UserFlags.ADMIN)
def admin_toggle_device_rotation(device_type, device_id):
    try:
        event_data = request.get_json()
        enabled = event_data.get("enabled", False)

        device = library.set_device_rotation_status(device_id, device_type, enabled)

        # Rebuild rotation config cache
        library.build_rotation_config_cache()

        action = "enabled" if enabled else "disabled"
        return jsonify(
            {
                "message": f"{device_type.upper()} device rotation {action} successfully",
                "device_id": device_id,
                "enabled": enabled,
            }
        )
    except Exception as e:
        logger.error(f"Error toggling device rotation: {e}")
        return jsonify({"error": True, "message": str(e)}), 400


@blueprint.route("/admin/system-devices/<device_type>/<int:device_id>", methods=["DELETE"])
@authentication_required(flags_required=UserFlags.ADMIN)
def admin_delete_system_device(device_type, device_id):
    try:
        system_user = FlaskUser.get_system_user(db)

        if device_type.lower() == "wvd":
            device = WVD.query.filter_by(id=device_id, uploaded_by=system_user.id).first()
        elif device_type.lower() == "prd":
            device = PRD.query.filter_by(id=device_id, uploaded_by=system_user.id).first()
        else:
            raise BadRequest("Invalid device type")

        if not device:
            raise BadRequest("Device not found or not owned by system user")

        # Remove device from database
        db.session.delete(device)
        db.session.commit()

        # Rebuild rotation config cache
        library.build_rotation_config_cache()

        return jsonify({"message": f"{device_type.upper()} device deleted successfully", "device_id": device_id})
    except Exception as e:
        logger.error(f"Error deleting device: {e}")
        return jsonify({"error": True, "message": str(e)}), 400
        library.build_rotation_config_cache()

        return jsonify({"message": f"{device_type.upper()} device deleted successfully", "device_id": device_id})
    except Exception as e:
        logger.error(f"Error deleting device: {e}")
        return jsonify({"error": True, "message": str(e)}), 400
