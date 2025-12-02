from flask import request
from flask_login import current_user
from models import db, AuditLog
import json

def audit(action, object_type=None, object_id=None, meta=None):
    try:
        user_id = getattr(current_user, "id", None)
    except Exception:
        user_id = None
    log = AuditLog(
        user_id=user_id,
        action=action,
        object_type=object_type,
        object_id=str(object_id) if object_id is not None else None,
        ip=request.remote_addr,
        user_agent=request.headers.get("User-Agent"),
        meta=json.dumps(meta or {})
    )
    db.session.add(log)
    db.session.commit()
