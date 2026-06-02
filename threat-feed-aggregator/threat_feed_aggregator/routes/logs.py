from flask import Blueprint, render_template

from .auth import login_required

bp_logs = Blueprint("logs", __name__, url_prefix="/logs")


@bp_logs.route("/")
@login_required
def index():
    return render_template("logs.html")
