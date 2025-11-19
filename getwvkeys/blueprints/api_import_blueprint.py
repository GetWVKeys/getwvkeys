from flask import Blueprint, current_app, jsonify

from getwvkeys.models.ImportTask import ImportTask

blueprint = Blueprint("api_import", __name__)


@blueprint.route("/status/<task_id>")
def import_status(task_id):
    """API endpoint to get import task status"""
    from getwvkeys.libraries import Library
    from getwvkeys.models.Shared import db

    library = Library(db)
    status = library.get_import_task_status(task_id)

    return jsonify(status)


@blueprint.route("/worker/status")
def worker_status():
    status = current_app.import_worker.get_status()

    with current_app.app_context():
        pending = ImportTask.query.filter_by(status="pending").count()
        running = ImportTask.query.filter_by(status="running").count()

    status.update({"pending_tasks": pending, "running_tasks": running})

    return jsonify(status)
