from flask import Blueprint, render_template

legal_bp = Blueprint("legal", __name__)


@legal_bp.route("/privacy")
def privacy_page():
    return render_template("privacy.html")


@legal_bp.route("/terms")
def terms_page():
    return render_template("terms.html")
