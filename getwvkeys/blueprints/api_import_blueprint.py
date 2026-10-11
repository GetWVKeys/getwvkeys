from flask import Blueprint, current_app, jsonify

from getwvkeys.models.ImportTask import ImportTask
from getwvkeys.shared import library

blueprint = Blueprint("api_import", __name__)


@blueprint.route("/status/<task_id>")
def import_status(task_id):
    """API endpoint to get import task status"""
    status = library.get_import_task_status(task_id)

    return jsonify(status)


@blueprint.route("/worker/status")
def worker_status():
    status = current_app.import_worker.get_status()

    pending = ImportTask.query.filter_by(status="pending").count()
    running = ImportTask.query.filter_by(status="running").count()

    status.update({"pending_tasks": pending, "running_tasks": running})

    return jsonify(status)
