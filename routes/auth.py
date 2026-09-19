"""
Google OAuth 2.0 Authentication Blueprint for VulnWatch.

Provides:
  GET /auth/login      - Render login page
  GET /auth/google     - Initiate Google OAuth flow
  GET /auth/callback   - Handle OAuth token exchange & session setup
  GET /auth/logout     - Clear session and redirect home
  GET /profile         - Authenticated user profile & scan history
"""
import uuid
from datetime import datetime

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from database.db import get_session
from database.models import Scan, User

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_or_create_oauth():
    """Lazily build an Authlib OAuth registry bound to the current app config.

    Returns None (without raising) if Google credentials are not configured,
    so the app can still start and serve guest-only flows.
    """
    client_id = current_app.config.get("GOOGLE_CLIENT_ID", "")
    client_secret = current_app.config.get("GOOGLE_CLIENT_SECRET", "")
    if not client_id or not client_secret:
        return None

    try:
        from authlib.integrations.flask_client import OAuth  # type: ignore[import]
        oauth = OAuth(current_app)
        google = oauth.register(
            name="google",
            client_id=client_id,
            client_secret=client_secret,
            server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email profile"},
        )
        return google
    except Exception as exc:
        current_app.logger.warning("Google OAuth not available: %s", exc)
        return None


def _current_user():
    """Return the User model instance for the logged-in session, or None."""
    user_id = session.get("user_id")
    if not user_id:
        return None
    db = get_session()
    return db.query(User).filter_by(id=user_id).first()


def login_required(view):
    """Decorator that redirects to /auth/login if user is not authenticated."""
    from functools import wraps

    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("auth.login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


# ---------------------------------------------------------------------------
# Auth Routes
# ---------------------------------------------------------------------------

@auth_bp.route("/login")
def login():
    """Render the VulnWatch login/sign-in page."""
    # Already logged in? Send home
    if session.get("user_id"):
        return redirect(url_for("dashboard.index"))

    oauth_available = bool(
        current_app.config.get("GOOGLE_CLIENT_ID")
        and current_app.config.get("GOOGLE_CLIENT_SECRET")
    )

    # Determine current guest scan count for the badge
    guest_id = session.get("guest_id")
    guest_scan_count = 0
    if guest_id:
        db = get_session()
        guest_scan_count = (
            db.query(Scan).filter_by(guest_session_id=guest_id).count()
        )

    guest_limit = current_app.config.get("GUEST_SCAN_LIMIT", 3)

    return render_template(
        "login.html",
        oauth_available=oauth_available,
        guest_scan_count=guest_scan_count,
        guest_limit=guest_limit,
        next=request.args.get("next", "/"),
    )


@auth_bp.route("/google")
def google_login():
    """Initiate the Google OAuth 2.0 authorization code flow."""
    google = _get_or_create_oauth()
    if not google:
        flash("Google sign-in is not configured on this server.", "warning")
        return redirect(url_for("auth.login"))

    redirect_uri = current_app.config.get(
        "GOOGLE_REDIRECT_URI", url_for("auth.callback", _external=True)
    )
    return google.authorize_redirect(redirect_uri)


@auth_bp.route("/callback")
def callback():
    """Handle Google OAuth token exchange and create/update the User record."""
    google = _get_or_create_oauth()
    if not google:
        flash("Google sign-in is not configured on this server.", "warning")
        return redirect(url_for("auth.login"))

    try:
        token = google.authorize_access_token()
        user_info = token.get("userinfo") or google.userinfo()
    except Exception as exc:
        current_app.logger.warning("OAuth callback error: %s", exc)
        flash("Sign-in failed. Please try again.", "error")
        return redirect(url_for("auth.login"))

    google_id = str(user_info.get("sub", ""))
    email = str(user_info.get("email", ""))
    name = str(user_info.get("name", ""))
    picture = str(user_info.get("picture", ""))

    if not email:
        flash("Could not retrieve your email address from Google.", "error")
        return redirect(url_for("auth.login"))

    db = get_session()

    # Upsert user record
    user = db.query(User).filter_by(google_id=google_id).first()
    if not user:
        user = db.query(User).filter_by(email=email).first()

    if user:
        # Refresh profile info on every login
        user.google_id = google_id
        user.name = name
        user.picture = picture
    else:
        user = User(
            google_id=google_id,
            email=email,
            name=name,
            picture=picture,
            created_at=datetime.utcnow(),
        )
        db.add(user)

    db.commit()
    db.refresh(user)

    # Migrate guest scans to this user account
    guest_id = session.get("guest_id")
    if guest_id:
        db.query(Scan).filter_by(guest_session_id=guest_id).update(
            {"user_id": user.id, "guest_session_id": None}
        )
        db.commit()

    # Establish authenticated session
    session.clear()
    session["user_id"] = user.id
    session["user"] = {
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "picture": user.picture,
    }
    session.permanent = True

    next_url = request.args.get("next") or "/"
    return redirect(next_url)


@auth_bp.route("/logout")
def logout():
    """Clear the session and redirect to the home page."""
    session.clear()
    return redirect(url_for("dashboard.index"))


# ---------------------------------------------------------------------------
# Profile Route (accessible via /profile outside the /auth prefix)
# ---------------------------------------------------------------------------

profile_bp = Blueprint("profile", __name__)


@profile_bp.route("/profile")
@login_required
def view_profile():
    """Show the authenticated user's profile and their scan history."""
    user = _current_user()
    if not user:
        return redirect(url_for("auth.login"))

    db = get_session()
    user_scans = (
        db.query(Scan)
        .filter_by(user_id=user.id)
        .order_by(Scan.started_at.desc())
        .limit(50)
        .all()
    )

    total_scans = len(user_scans)
    total_findings = sum(
        s.critical_count + s.high_count + s.medium_count + s.low_count
        for s in user_scans
    )

    # Per-scan posture scores for sparkline
    scores = [
        max(0, min(100, 100 - (15 * s.critical_count + 8 * s.high_count
                               + 3 * s.medium_count + s.low_count)))
        for s in user_scans
    ]
    avg_posture = round(sum(scores) / len(scores)) if scores else 100

    return render_template(
        "profile.html",
        user=user,
        user_scans=user_scans,
        total_scans=total_scans,
        total_findings=total_findings,
        avg_posture=avg_posture,
    )
