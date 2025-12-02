from functools import wraps
from flask import abort
from flask_login import current_user

def require_role(*roles):
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            # Works with: current_user.role (string) OR current_user.roles (list of strings)
            role = getattr(current_user, "role", None)
            roles_attr = getattr(current_user, "roles", None)
            ok = False
            if role and role in roles:
                ok = True
            if isinstance(roles_attr, (list, tuple, set)) and any(r in roles for r in roles_attr):
                ok = True
            if not ok:
                return abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return deco
