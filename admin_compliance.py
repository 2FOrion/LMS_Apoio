from flask import Blueprint, render_template, Response, request, jsonify
from flask_login import login_required, current_user

from models import (
    db,
    PrivacyConsent,
    PrivacyRequest,
    AuditLog,
    User
)

from policy import enforce_privileged_2fa, is_privileged
from rbac import require_role

import csv
import io
from datetime import datetime


admin_comp = Blueprint(
    "admin_comp",
    __name__,
    url_prefix="/admin/conformidade"
)


# ============================
# APLICAR 2FA EM TODO ACESSO
# ============================
@admin_comp.before_request
def _enforce():
    return enforce_privileged_2fa()


# ============================
# FUNÇÃO PADRÃO PARA REGISTRAR AUDITORIA
# ============================
def log_admin(action, object_type=None, object_id=None):
    entry = AuditLog(
        user_id=current_user.id if current_user.is_authenticated else None,
        action=action,
        object_type=object_type,
        object_id=object_id,
        ip_address=request.remote_addr,
        user_agent=request.headers.get("User-Agent")
    )
    db.session.add(entry)
    db.session.commit()


# ============================
# DASHBOARD DE CONFORMIDADE
# ============================
@admin_comp.get("/")
@login_required
@require_role("Admin", "Owner", "Gestor")
def dashboard():

    log_admin("visualizou o painel de conformidade")

    consents = PrivacyConsent.query.order_by(PrivacyConsent.granted_at.desc()).limit(500).all()
    requests = PrivacyRequest.query.order_by(PrivacyRequest.created_at.desc()).limit(500).all()
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(500).all()

    return render_template(
        "admin/conformidade.html",
        consents=consents,
        requests=requests,
        logs=logs
    )


# ============================
# EXPORTAÇÃO CSV
# ============================
@admin_comp.get("/export.csv")
@login_required
@require_role("Admin", "Owner", "Gestor")
def export_csv():

    log_admin("exportou CSV de conformidade")

    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")

    writer.writerow(["tipo", "user_id", "data", "detalhes"])

    # Consentimentos
    for c in PrivacyConsent.query.order_by(PrivacyConsent.granted_at.desc()).all():
        writer.writerow([
            "consentimento",
            c.user_id,
            str(c.granted_at),
            f"{c.purpose}/{c.legal_basis} -> {'OK' if c.granted else 'NEGADO'}"
        ])

    # Requisições LGPD
    for r in PrivacyRequest.query.order_by(PrivacyRequest.created_at.desc()).all():
        writer.writerow([
            "requisicao",
            r.user_id,
            str(r.created_at),
            f"{r.kind}/{r.status}"
        ])

    # Auditoria
    for l in AuditLog.query.order_by(AuditLog.created_at.desc()).all():
        writer.writerow([
            "audit",
            l.user_id,
            str(l.created_at),
            f"{l.action} | {l.object_type}:{l.object_id}"
        ])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=conformidade.csv"}
    )


# ============================
# EXPORTAÇÃO PDF
# ============================
@admin_comp.get("/relatorio.pdf")
@login_required
@require_role("Admin", "Owner", "Gestor")
def export_pdf():

    log_admin("gerou PDF de conformidade")

    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
        from reportlab.lib.units import cm
    except Exception:
        return Response("ReportLab não instalado.", mimetype="text/plain")

    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    y = height - 2 * cm

    consents = PrivacyConsent.query.order_by(PrivacyConsent.granted_at.desc()).limit(200).all()
    requests = PrivacyRequest.query.order_by(PrivacyRequest.created_at.desc()).limit(200).all()
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(200).all()

    def line(text):
        nonlocal y
        if y < 2 * cm:
            c.showPage()
            y = height - 2 * cm
        c.drawString(2 * cm, y, str(text)[:120])
        y -= 14

    c.setTitle("Relatório de Conformidade — LGPD")
    c.setFont("Helvetica-Bold", 14)
    line("Relatório de Conformidade — LGPD")

    c.setFont("Helvetica", 10)
    line(f"Gerado em: {datetime.now():%d/%m/%Y %H:%M}")

    # Consentimentos
    c.setFont("Helvetica-Bold", 12)
    line("Consentimentos")
    c.setFont("Helvetica", 10)
    for r in consents:
        line(f"User {r.user_id} | {r.purpose} / {r.legal_basis} | {r.granted_at} | {'OK' if r.granted else 'NEGADO'}")

    # Requisições LGPD
    c.setFont("Helvetica-Bold", 12)
    line("Requisições dos Titulares")
    c.setFont("Helvetica", 10)
    for r in requests:
        line(f"User {r.user_id} | {r.kind} | {r.status} | {r.created_at}")

    # Auditoria
    c.setFont("Helvetica-Bold", 12)
    line("Logs de Auditoria")
    c.setFont("Helvetica", 10)
    for log in logs:
        line(f"{log.created_at} | U{log.user_id} | {log.action} | {log.object_type}:{log.object_id}")

    c.showPage()
    c.save()

    pdf = buffer.getvalue()
    buffer.close()

    return Response(
        pdf,
        mimetype="application/pdf",
        headers={"Content-Disposition": "attachment; filename=conformidade.pdf"}
    )


# ============================
# LISTAR USUÁRIOS PRIVILEGIADOS SEM 2FA
# ============================
@admin_comp.get("/pending-2fa.json")
@login_required
@require_role("Admin", "Owner", "Gestor")
def pending_2fa():

    log_admin("verificou usuários privilegiados sem 2FA")

    rows = []
    for u in User.query.all():
        if is_privileged(u) and not getattr(u, "twofa_enabled", False):
            rows.append({
                "id": u.id,
                "name": getattr(u, "name", u.cpf),
                "deadline": getattr(u, "twofa_grace_until", None),
            })

    return jsonify(rows)
