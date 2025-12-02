from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from models import db, PrivacyConsent, PrivacyRequest, AuditLog
import json
from datetime import datetime

privacy = Blueprint('privacy', __name__)

def log_privacy_request(user_id, kind, status):
    pr = PrivacyRequest(user_id=user_id, kind=kind, status=status)
    db.session.add(pr)
    db.session.commit()
    return pr.id

@privacy.get("/me/dados/export")
@login_required
def export_me():
    from models import User, Enrollment, Course, QuizAttempt, Certificate, VideoProgress, AuditLog
    u = User.query.get(current_user.id)
    cursos = (Enrollment.query.filter_by(user_id=current_user.id).all())
    def cdict(e):
        try:
            c = Course.query.get(e.course_id)
            return {"course_id": e.course_id, "course_name": getattr(c, "name", None), "enrolled_at": getattr(e, "created_at", None)}
        except Exception:
            return {"course_id": e.course_id}
    progresso = []
    for vp in VideoProgress.query.filter_by(user_id=current_user.id).all():
        progresso.append({"course_id": vp.course_id, "watched": bool(getattr(vp,"watched",False)), "seconds_watched": getattr(vp,"seconds_watched",0), "updated_at": getattr(vp,"updated_at",None)})
    tentativas = []
    for a in QuizAttempt.query.filter_by(user_id=current_user.id).all():
        tentativas.append({"course_id": a.course_id, "score": a.score, "passed": bool(a.passed), "submitted_at": a.submitted_at})
    certs = []
    for c in Certificate.query.filter_by(user_id=current_user.id).all():
        certs.append({"id": c.id, "course_id": c.course_id, "issued_at": getattr(c,"issued_at",None)})
    logs = []
    for l in AuditLog.query.filter_by(user_id=current_user.id).all():
        logs.append({"at": l.created_at, "action": l.action, "obj": f"{l.object_type}:{l.object_id}"})
    bundle = {
        "perfil": {"id": u.id, "name": u.name, "cpf": u.cpf},
        "cursos": [cdict(e) for e in cursos],
        "progresso": progresso,
        "quiz_attempts": tentativas,
        "certificados": certs,
        "logs": logs
    }
    return jsonify(bundle), 200


@privacy.post("/me/dados/delete")
@login_required
def request_delete():
    log_privacy_request(current_user.id, kind="eliminação", status="em_andamento")
    return jsonify({"ok": True, "message": "Solicitação registrada"}), 202

@privacy.post("/consent/analytics")
@login_required
def consent_analytics():
    granted = True
    pc = PrivacyConsent(
        user_id=current_user.id,
        version="v1",
        purpose="analytics",
        legal_basis="consentimento",
        granted=granted,
        granted_at=datetime.utcnow()
    )
    db.session.add(pc)
    db.session.commit()
    return jsonify({"ok": True})
