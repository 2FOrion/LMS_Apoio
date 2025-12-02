from datetime import datetime, timedelta
from flask import redirect, url_for, flash
from flask_login import current_user

PRIVILEGED_ROLES = {"Admin","Owner"}

def is_privileged(user) -> bool:
    role = getattr(user, "role", None)
    roles = getattr(user, "roles", None)
    if role in PRIVILEGED_ROLES:
        return True
    if isinstance(roles, (list, tuple, set)) and any(r in PRIVILEGED_ROLES for r in roles):
        return True
    return False

def ensure_grace(user, days:int=7):
    if not getattr(user, "twofa_grace_until", None):
        user.twofa_grace_until = datetime.utcnow() + timedelta(days=days)
        return True
    return False

def enforce_privileged_2fa():
    """Redirect privileged users without 2FA after grace period to setup page."""
    if not current_user.is_authenticated:
        return None
    if not is_privileged(current_user):
        return None
    if getattr(current_user, "twofa_enabled", False):
        return None
    deadline = getattr(current_user, "twofa_grace_until", None)
    now = datetime.utcnow()
    if deadline and now > deadline:
        flash("2FA obrigatório para administradores. Ative para continuar.", "danger")
        return redirect(url_for("security_2fa_setup"))
    else:
        # still in grace; soft warning
        return None
