from typing import Optional
import os
import csv
import random
from io import StringIO
from math import floor
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from urllib.parse import urlparse, parse_qs

from flask import (
    Flask, render_template, render_template_string, redirect,
    url_for, request, flash, send_file, abort, session, jsonify, Response
)


from flask_login import (
    LoginManager, login_user, login_required, logout_user, current_user
)

from passlib.hash import pbkdf2_sha256

from sqlalchemy.orm import joinedload
from sqlalchemy import inspect, text, or_

from flask_migrate import Migrate

# ===== Modelos =====
from models import (
    db, User, Company, Course, Enrollment, Certificate, Role,
    RoleRequirement, VideoProgress, QuizQuestion, QuizAttempt,
    LoginSession,
)
from utils import generate_certificate_pdf
from utils_2fa import ensure_secret, otpauth_uri, verify_otp, qr_via_google_charts
from admin_compliance import admin_comp
from utils_audit import audit
from privacy import privacy
from policy import ensure_grace, is_privileged


# =========================
# CONFIG DO APLICATIVO
# =========================
app = Flask(__name__)
app.register_blueprint(admin_comp)
app.register_blueprint(privacy)

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "apoio_lms_secret_key")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///database.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Inicializa o banco
db.init_app(app)

# =============== INICIALIZA FLASK-MIGRATE ===============
migrate = Migrate(app, db)

# Login Manager
login_manager = LoginManager(app)
login_manager.login_view = "login"

BR_TZ = ZoneInfo("America/Sao_Paulo")

# =========================
# Helpers de vídeo
# =========================
_YT_HOSTS = ("youtube.com", "youtu.be")

def is_url(s: str) -> bool:
    return bool(s and (s.startswith("http://") or s.startswith("https://")))

def youtube_embed(url: str) -> Optional[str]:
    if not is_url(url):
        return None
    u = urlparse(url)
    if not any(h in (u.netloc or "") for h in _YT_HOSTS):
        return None
    vid = ""
    if "youtu.be" in u.netloc:
        vid = (u.path or "/").split("/")[-1]
    elif "youtube.com" in u.netloc:
        q = parse_qs(u.query)
        vid = (q.get("v") or [""])[0]
    vid = (vid or "").strip()
    return f"https://www.youtube.com/embed/{vid}" if vid else None

def looks_like_youtube(url: str) -> bool:
    if not is_url(url):
        return False
    host = urlparse(url).netloc.lower()
    return any(h in host for h in _YT_HOSTS)
# =========================
# Função de auto-migração (corrige schema antigo)
# =========================

def ensure_admin_user():
    admin = User.query.filter_by(username="admin").first()
    if not admin:
        admin = User(
            username="admin",
            email="admin@example.com",
            name="Administrador",
            cpf="14232832793",
            role="admin",
        )
        admin.set_password("admin123")
        db.session.add(admin)
        db.session.commit()


def ensure_schema():
    """
    - Garante 'role.description'
    - Garante 'course.description'
    - Garante 'course.video_path'
    - Garante campos de progresso em video_progress
    - Garante colunas de 2FA na tabela user
    - Garante colunas de progresso na enrollment
    - Garante colunas opcionais em certificate
    - Cria tabelas se faltarem
    """
    insp = inspect(db.engine)
    db.create_all()

    # role.description
    if "role" in insp.get_table_names():
        cols = [c["name"] for c in insp.get_columns("role")]
        if "description" not in cols:
            db.session.execute(
                text("ALTER TABLE role ADD COLUMN description VARCHAR(255)")
            )
            db.session.commit()

    # course.description / course.video_path
    insp = inspect(db.engine)
    if "course" in insp.get_table_names():
        cols = [c["name"] for c in insp.get_columns("course")]
        if "description" not in cols:
            db.session.execute(
                text("ALTER TABLE course ADD COLUMN description TEXT")
            )
            db.session.commit()
        insp = inspect(db.engine)
        cols = [c["name"] for c in insp.get_columns("course")]
        if "video_path" not in cols:
            db.session.execute(
                text("ALTER TABLE course ADD COLUMN video_path VARCHAR(300)")
            )
            db.session.commit()

          # VIDEO_PROGRESS: garantir TODAS as colunas do models.py
    insp = inspect(db.engine)
    if "video_progress" in insp.get_table_names():
        cols = {c["name"] for c in insp.get_columns("video_progress")}

        def _vp_add(sql):
            try:
                db.session.execute(text(sql))
                db.session.commit()
            except Exception as e:
                print("[WARN] ensure_schema video_progress:", e)
                db.session.rollback()

        if "watched" not in cols:
            _vp_add("ALTER TABLE video_progress ADD COLUMN watched BOOLEAN DEFAULT 0")

        if "seconds_watched" not in cols:
            _vp_add("ALTER TABLE video_progress ADD COLUMN seconds_watched INTEGER DEFAULT 0")

        if "duration_seconds" not in cols:
            _vp_add("ALTER TABLE video_progress ADD COLUMN duration_seconds INTEGER DEFAULT 0")

        if "watched_percent" not in cols:
            _vp_add("ALTER TABLE video_progress ADD COLUMN watched_percent FLOAT DEFAULT 0.0")

        if "progress_pct" not in cols:
            _vp_add("ALTER TABLE video_progress ADD COLUMN progress_pct INTEGER DEFAULT 0")

        if "fully_watched" not in cols:
            _vp_add("ALTER TABLE video_progress ADD COLUMN fully_watched BOOLEAN DEFAULT 0")

        if "last_position" not in cols:
            _vp_add("ALTER TABLE video_progress ADD COLUMN last_position FLOAT DEFAULT 0.0")

        if "fraud_flag" not in cols:
            _vp_add("ALTER TABLE video_progress ADD COLUMN fraud_flag VARCHAR(255)")

        if "watched_at" not in cols:
            _vp_add("ALTER TABLE video_progress ADD COLUMN watched_at TIMESTAMP")

        if "updated_at" not in cols:
            _vp_add("ALTER TABLE video_progress ADD COLUMN updated_at TIMESTAMP")

    # USER: colunas para 2FA
    insp = inspect(db.engine)
    if "user" in insp.get_table_names():
        cols = {c["name"] for c in insp.get_columns("user")}
        if "twofa_enabled" not in cols:
            db.session.execute(
                text("ALTER TABLE user ADD COLUMN twofa_enabled BOOLEAN DEFAULT 0")
            )
        if "twofa_secret" not in cols:
            db.session.execute(
                text("ALTER TABLE user ADD COLUMN twofa_secret VARCHAR(64)")
            )
        if "twofa_recovery" not in cols:
            db.session.execute(
                text("ALTER TABLE user ADD COLUMN twofa_recovery VARCHAR(64)")
            )
        if "twofa_grace_until" not in cols:
            db.session.execute(
                text("ALTER TABLE user ADD COLUMN twofa_grace_until TIMESTAMP")
            )
        db.session.commit()

    # ENROLLMENT: progresso/conclusão (compatível com models.py)
    insp = inspect(db.engine)
    if "enrollment" in insp.get_table_names():
        cols = {c["name"] for c in insp.get_columns("enrollment")}

        if "status" not in cols:
            db.session.execute(
                text("ALTER TABLE enrollment ADD COLUMN status VARCHAR(32)")
            )
        if "completed_at" not in cols:
            db.session.execute(
                text("ALTER TABLE enrollment ADD COLUMN completed_at TIMESTAMP")
            )
        if "video_completed_at" not in cols:
            db.session.execute(
                text("ALTER TABLE enrollment ADD COLUMN video_completed_at TIMESTAMP")
            )
        if "quiz_completed_at" not in cols:
            db.session.execute(
                text("ALTER TABLE enrollment ADD COLUMN quiz_completed_at TIMESTAMP")
            )
        if "completion_pct" not in cols:
            db.session.execute(
                text("ALTER TABLE enrollment ADD COLUMN completion_pct INTEGER")
            )
        if "must_watch_video" not in cols:
            db.session.execute(
                text("ALTER TABLE enrollment ADD COLUMN must_watch_video BOOLEAN DEFAULT 1")
            )
        if "must_pass_quiz" not in cols:
            db.session.execute(
                text("ALTER TABLE enrollment ADD COLUMN must_pass_quiz BOOLEAN DEFAULT 1")
            )
        if "final_score" not in cols:
            db.session.execute(
                text("ALTER TABLE enrollment ADD COLUMN final_score INTEGER")
            )
        if "approved" not in cols:
            db.session.execute(
                text("ALTER TABLE enrollment ADD COLUMN approved BOOLEAN DEFAULT 0")
            )

        db.session.commit()

    # CERTIFICATE (opcionais)
    insp = inspect(db.engine)
    if "certificate" in insp.get_table_names():
        cols = {c["name"] for c in insp.get_columns("certificate")}
        if "file_path" not in cols:
            db.session.execute(
                text("ALTER TABLE certificate ADD COLUMN file_path VARCHAR(512)")
            )
        if "issued_at" not in cols:
            db.session.execute(
                text("ALTER TABLE certificate ADD COLUMN issued_at TIMESTAMP")
            )
        if "verify_url" not in cols:
            db.session.execute(
                text("ALTER TABLE certificate ADD COLUMN verify_url VARCHAR(512)")
            )
        db.session.commit()

# =========================
# Helpers
# =========================
PASSING_CORRECT = 7            # mínimo de acertos exigidos
MAX_QUIZ_ATTEMPTS = 3          # número máximo de tentativas
QUIZ_TIME_LIMIT_SECONDS = 3600 # 1 hora de limite no quiz

def _must_pass_score(num_questions: int) -> int:
    return num_questions if num_questions < PASSING_CORRECT else PASSING_CORRECT

def _digits(s: str) -> str:
    return "".join(ch for ch in (s or "") if ch.isdigit())


def _strip_port(ip: Optional[str]) -> Optional[str]:
    if not ip:
        return ip
    ip = ip.strip()
    if ip.startswith("[") and "]" in ip:
        ip = ip.split("]")[0].lstrip("[").strip()
        return ip or None
    if ":" in ip and ip.count(":") == 1:
        host, _port = ip.split(":")
        return host.strip()
    return ip

def _get_client_ip() -> Optional[str]:
    xfwd = request.headers.get("X-Forwarded-For", "") or request.headers.get("x-forwarded-for", "")
    if xfwd:
        first = xfwd.split(",")[0].strip()
        first = _strip_port(first)
        if first:
            return first
    xreal = _strip_port(request.headers.get("X-Real-IP"))
    if xreal:
        return xreal
    return _strip_port(request.remote_addr)

def _set_option_fields(obj, a=None, b=None, c=None, d=None):
    aliases = {
        "a": ["a", "option_a", "alt_a", "op_a"],
        "b": ["b", "option_b", "alt_b", "op_b"],
        "c": ["c", "option_c", "alt_c", "op_c"],
        "d": ["d", "option_d", "alt_d", "op_d"],
    }
    vals = {"a": a, "b": b, "c": c, "d": d}
    for key, val in vals.items():
        if val is None or val == "":
            continue
        for cand in aliases[key]:
            if hasattr(obj, cand):
                setattr(obj, cand, val)
                break

_OPTION_ALIASES = {
    "a": ("a", "option_a", "alt_a", "op_a"),
    "b": ("b", "option_b", "alt_b", "op_b"),
    "c": ("c", "option_c", "alt_c", "op_c"),
    "d": ("d", "option_d", "alt_d", "op_d"),
}

def _get_q_opt(q, k):
    for name in _OPTION_ALIASES[k]:
        if hasattr(q, name):
            val = getattr(q, name)
            if val:
                return val
    return None

def _build_view_options(q):
    opts = []
    for k in ("a", "b", "c", "d"):
        text = _get_q_opt(q, k)
        if text:
            opts.append((k, text))
    return opts

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@login_manager.unauthorized_handler
def _unauth():
    flash("Faça login para acessar.", "warning")
    return redirect(url_for("login"))

from typing import Optional  # se ainda não tiver, ajuda nos hints

def _is_valid_cpf(cpf: Optional[str]) -> bool:
    """
    Validação básica de CPF.
    Aceita string com ou sem máscara, mas usa só os dígitos.
    """
    if not cpf:
        return False

    cpf = _digits(cpf)

    # tem que ter 11 dígitos
    if len(cpf) != 11:
        return False

    # rejeita CPFs óbvios (11111111111, 00000000000, etc.)
    if cpf == cpf[0] * 11:
        return False

    def dv_calc(cpf_parcial: str) -> str:
        soma = sum(int(d) * peso for d, peso in zip(cpf_parcial, range(len(cpf_parcial)+1, 1, -1)))
        resto = soma % 11
        return "0" if resto < 2 else str(11 - resto)

    dv1 = dv_calc(cpf[:9])
    dv2 = dv_calc(cpf[:10])

    return cpf[-2:] == dv1 + dv2


# =========================
# Controle de sessões de login
# =========================

def _start_login_session(user: User):
    """Abre um registro de sessão de login e guarda o ID na sessão."""
    try:
        ls = LoginSession(
            user_id=user.id,
            login_at=datetime.now(BR_TZ),
            ip_address=(_get_client_ip() or "")[:64],
            user_agent=(request.headers.get("User-Agent", "") or "")[:256],
        )
        db.session.add(ls)
        db.session.commit()
        # guarda o id da sessão para ser encerrada depois no logout
        session["login_session_id"] = ls.id
    except Exception as e:
        print("[WARN] Falha ao registrar sessão de login:", e)
        db.session.rollback()


# =========================
# Autorização (papéis)
# =========================
def _role() -> str:
    """Retorna o papel atual do usuário em minúsculas."""
    return (current_user.role or "").lower().strip() if current_user.is_authenticated else ""


def is_admin_like() -> bool:
    """
    True se o usuário for admin, rh, rhdp, ti ou auditoria.
    Esses papéis têm acesso total ao sistema.
    """
    return _role() in {"admin", "rh", "rhdp", "ti", "auditoria"}


def admin_required():
    """Restringe acesso apenas a funções com acesso total."""
    if not current_user.is_authenticated or not is_admin_like():
        abort(403)


def instrutor_or_admin_required():
    """
    Acesso permitido para:
    - instrutor (para gerenciar vídeos/quiz)
    - admin, rh, rhdp, ti, auditoria (acesso total)
    """
    if not current_user.is_authenticated or _role() not in {
        "instrutor",
        "admin",
        "rh",
        "rhdp",
        "ti",
        "auditoria"
    }:
        abort(403)

def company_logo_for(company: Company | None) -> str:
    """
    Devolve a URL da logo da empresa (ou a padrão).
    Usado nos templates (dashboard, certificado etc.).
    """
    from flask import url_for

    # logo padrão do sistema
    default_logo = url_for("static", filename="img/Grupo_Apoio.png")

    if not company:
        return default_logo

    # se tiver logo_path no banco, usa
    if getattr(company, "logo_path", None):
        # se você algum dia salvar uma URL externa ali
        from app import is_url  # você já tem is_url definido
        if is_url(company.logo_path):
            return company.logo_path
        return url_for("static", filename=company.logo_path)

    # fallback baseado no nome (se quiser manter)
    name = (company.name or "").upper()
    if "APOIO" in name:
        fn = "img/apoio_logo.png"
    elif "WQ" in name:
        fn = "img/Wq.png"
    elif "APBVIX" in name:
        fn = "img/Apbvix.png"
    elif "INDUSTECH" in name:
        fn = "img/Industech.png"
    else:
        fn = "img/Grupo_Apoio.png"

    return url_for("static", filename=fn)

@app.context_processor
def inject_globals():
    return {
        "BR_TZ": BR_TZ,
        "Course": Course,
        "youtube_embed": youtube_embed,
        "looks_like_youtube": looks_like_youtube,
        "is_url": is_url,
        "sidebar_enrollments": sidebar_enrollments,
        "sidebar_next_action": sidebar_next_action,
        "is_admin_like": is_admin_like,
        "current_role": _role,
        # 👇 NOVO:
        "company_logo_for": company_logo_for,
    }


def _auto_enroll_required_courses(user: User) -> int:
    """
    Matricula o usuário em todos os cursos vinculados à função (RoleRequirement),
    respeitando:
    - cursos globais (company_id = NULL) -> entra para qualquer empresa
    - cursos com company_id -> entra só se for a mesma empresa do usuário
    Retorna quantas matrículas novas foram criadas.
    """
    if not user or not user.role:
        return 0

    # Função do usuário (case-insensitive)
    role_obj = Role.query.filter(Role.name.ilike(user.role)).first()
    if not role_obj or not role_obj.requirements:
        return 0

    # Cursos em que o usuário JÁ está matriculado
    existentes = {
        e.course_id
        for e in Enrollment.query.filter_by(user_id=user.id).all()
        if e.course_id
    }

    created = 0

    for rr in role_obj.requirements:
        course = rr.course
        if not course:
            continue

        # Se o curso for de empresa específica, só matricula quem é dessa empresa
        if course.company_id and user.company_id and course.company_id != user.company_id:
            continue

        # Se já tiver matrícula, pula
        if course.id in existentes:
            continue

        # Cria matrícula nova
        e = Enrollment(
            user_id=user.id,
            course_id=course.id,
            status="in_progress",   # ou "Em andamento", se preferir
            must_watch_video=True,
            must_pass_quiz=True,
            completion_pct=0,
        )
        db.session.add(e)
        created += 1

    return created

# =========================
# Helpers para sidebar (Meus Cursos)
# =========================
from typing import Optional

def _status_is_done(status: Optional[str]) -> bool:
    s = (status or "").strip().lower()
    return s in {"concluído", "concluido", "completed"}

def _status_is_in_progress(status: Optional[str]) -> bool:
    s = (status or "").strip().lower()
    return s in {"em andamento", "in_progress", "in progress"}

def sidebar_enrollments(include_pending_only: bool = True):
    if not current_user.is_authenticated:
        return []

    ens = (
        Enrollment.query
        .options(joinedload(Enrollment.course))
        .filter_by(user_id=current_user.id)
        .all()
    )

    def _key(e: Enrollment):
        done = _status_is_done(e.status)
        name = (e.course.name if e.course else "").lower()
        return (done, name)

    ens.sort(key=_key)

    if include_pending_only:
        ens = [e for e in ens if not _status_is_done(e.status)]
    return ens

def sidebar_next_action(enroll: Enrollment):
    if not enroll or not enroll.course_id:
        return ("dashboard", url_for("dashboard"))

    vp = VideoProgress.query.filter_by(
        user_id=current_user.id, course_id=enroll.course_id
    ).first()
    watched = bool(vp and (getattr(vp, "watched", False) or (getattr(vp, "progress_pct", 0) or 0) >= 95))

    if not watched:
        return ("video", url_for("curso_video", course_id=enroll.course_id))

    if not _status_is_done(enroll.status):
        return ("quiz", url_for("quiz", course_id=enroll.course_id))

    return ("done", url_for("dashboard"))

# =========================
# Progresso & Certificados
# =========================
VIDEO_WEIGHT = 0.6   # 60% vídeo
QUIZ_WEIGHT  = 0.4   # 40% quiz

def _video_pct(user_id:int, course_id:int) -> int:
    vps = VideoProgress.query.filter_by(user_id=user_id, course_id=course_id).all()
    if not vps:
        return 0
    vals = []
    for v in vps:
        p = getattr(v, "progress_pct", None)
        if p is None:
            p = 100 if getattr(v, "watched", False) else 0
        vals.append(max(0, min(100, int(round(p)))))
    return int(round(sum(vals)/len(vals)))

def _quiz_pct(user_id:int, course_id:int) -> int:
    atts = (QuizAttempt.query
            .filter_by(user_id=user_id, course_id=course_id)
            .order_by(QuizAttempt.score.desc())
            .all())
    if not atts:
        return 0
    return max(0, min(100, int(round(atts[0].score or 0))))

def compute_completion_pct(user_id:int, course_id:int) -> int:
    v = _video_pct(user_id, course_id)
    q = _quiz_pct(user_id, course_id)
    return int(round(min(100, (v*VIDEO_WEIGHT)+(q*QUIZ_WEIGHT))))

def ensure_certificate(enroll: Enrollment):
    exists = Certificate.query.filter_by(user_id=enroll.user_id, course_id=enroll.course_id).first()
    if exists:
        return None
    user   = User.query.get(enroll.user_id)
    course = Course.query.get(enroll.course_id)
    company = Company.query.get(getattr(user, "company_id", None)) if user else None
    if not (user and course and company):
        return None
    os.makedirs("generated", exist_ok=True)
    pdf_path = generate_certificate_pdf(
        user, company, course, enroll.completed_at or datetime.now(BR_TZ),
        out_dir="generated",
        ip_address=None, access_dt=None
    )
    cert = Certificate(
        user_id=user.id, course_id=course.id, company_id=company.id,
        file_path=pdf_path, issued_at=enroll.completed_at or datetime.now(BR_TZ)
    )
    db.session.add(cert)
    db.session.commit()
    return cert

def update_enrollment_progress(user_id:int, course_id:int) -> Enrollment:
    e = Enrollment.query.filter_by(user_id=user_id, course_id=course_id).first()
    if not e:
        e = Enrollment(user_id=user_id, course_id=course_id, status="Pendente")
        db.session.add(e); db.session.flush()

    pct = compute_completion_pct(user_id, course_id)
    if hasattr(e, "completion_pct"):
        e.completion_pct = pct

    if pct >= 100:
        e.status = "Concluído"
        if not getattr(e, "completed_at", None):
            e.completed_at = datetime.now(BR_TZ)
        db.session.commit()
        ensure_certificate(e)
    elif pct > 0:
        e.status = "Em andamento"
        if hasattr(e, "completed_at"):
            e.completed_at = None
        db.session.commit()
    else:
        e.status = e.status or "Pendente"
        db.session.commit()
    return e

# =========================
# Autenticação
# =========================
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":

        # ---- Coleta dados ----
        raw_cpf = (request.form.get("cpf") or "")
        cpf = _digits(raw_cpf)
        password = request.form.get("password") or ""

        # ---- Busca usuário no banco ----
        user = User.query.filter_by(cpf=cpf).first()

        # ---- Verifica senha ----
        if user and password and pbkdf2_sha256.verify(password, user.password_hash):

            # ---------------------------------------
            # 1) PERÍODO DE GRAÇA PARA 2FA (Privilegiados)
            # ---------------------------------------
            try:
                if is_privileged(user) and not getattr(user, "twofa_enabled", False):
                    if ensure_grace(user, days=7):
                        db.session.commit()
            except Exception:
                pass

            # ---------------------------------------
            # 2) SE POSSUI 2FA → REDIRECIONA PARA TELA DE OTP
            # ---------------------------------------
            if getattr(user, "twofa_enabled", False):
                session["otp_user_id"] = user.id
                flash("Digite o código do autenticador para concluir o login.", "info")
                return redirect(url_for("login_otp"))

            # ---------------------------------------
            # 3) PRIMEIRO ACESSO → TROCA DE SENHA OBRIGATÓRIA
            # ---------------------------------------
            if getattr(user, "first_login", False):
                session["change_pass_user"] = user.id
                return redirect(url_for("change_password_first"))

            # ---------------------------------------
            # 4) LOGIN NORMAL
            # ---------------------------------------
            login_user(user)

            # 🔹 Auto-matrícula de cursos obrigatórios pela função/cargo
            try:
                created = _auto_enroll_required_courses(user)
                if created:
                    db.session.commit()
                    print(f"[INFO] Auto-matriculamos {created} curso(s) para {user.name}.")
            except Exception as e:
                print("[WARN] Falha ao auto-matricular cursos obrigatórios:", e)
                db.session.rollback()

            # ---- Inicia sessão para RELATÓRIO DE LOGIN ----
            try:
                _start_login_session(user)
            except Exception as e:
                print("[WARN] Falha ao iniciar sessão de login:", e)

            # ---- Auditoria ----
            try:
                audit("login", object_type="User", object_id=getattr(user, "id", None))
            except Exception:
                pass

            return redirect(url_for("dashboard"))

        # Se chegou aqui é porque CPF/senha não conferem
        flash("CPF ou senha incorretos.", "danger")

    # GET ou POST com erro cai aqui
    return render_template("login.html")



# =========================
# LOGOUT / FIM DE SESSÃO
# =========================
from datetime import datetime

@app.route("/logout")
@login_required
def logout():
    """
    Encerra a sessão de login (para o relatório) e faz logout do usuário.
    Mesmo que dê erro ao gravar a sessão, o logout do Flask-Login acontece.
    """
    try:
        _end_login_session()
    except Exception as e:
        print("[WARN] Falha ao encerrar sessão:", e)

    logout_user()
    flash("Você saiu da sua conta.", "info")
    return redirect(url_for("login"))


def _end_login_session():
    """Fecha o registro de sessão de login usado no relatório de acessos."""
    # pega e já remove o id da sessão da session do Flask
    ls_id = session.pop("login_session_id", None)
    if not ls_id:
        return

    try:
        ls = LoginSession.query.get(ls_id)
        if not ls:
            return

        # se ainda não tiver logout_at, registra agora
        if not ls.logout_at:
            ls.logout_at = datetime.now(BR_TZ)

        # calcula/atualiza a duração em segundos
        if ls.login_at and ls.logout_at:
            ls.duration_seconds = int(
                (ls.logout_at - ls.login_at).total_seconds()
            )

        db.session.commit()
    except Exception as e:
        print("[WARN] Falha ao encerrar sessão de login:", e)
        db.session.rollback()

# =========================
# Dashboard do usuário
# =========================
@app.route("/dashboard")
@login_required
def dashboard():
    try:
        # ----- 1) Carrega matrículas do usuário (empresa dele + cursos globais) -----
        base_q = (
            Enrollment.query
            .options(joinedload(Enrollment.course))
            .join(Course, Course.id == Enrollment.course_id)
            .filter(Enrollment.user_id == current_user.id)
        )

        # Filtra por empresa do usuário OU curso global (company_id IS NULL)
        if getattr(current_user, "company_id", None):
            base_q = base_q.filter(
                or_(
                    Course.company_id == current_user.company_id,
                    Course.company_id.is_(None),
                )
            )
        else:
            # se o usuário não tiver empresa definida, mostra só cursos globais
            base_q = base_q.filter(Course.company_id.is_(None))

        enrollments = base_q.all()

        # ----- 2) Atualiza progresso (defensivo: não derruba o dashboard) -----
        for e in enrollments:
            try:
                if e.course_id:
                    update_enrollment_progress(current_user.id, e.course_id)
            except Exception as err:
                print(f"[WARN] Falha ao atualizar progresso do curso {e.course_id}: {err}")

        # recarrega as matrículas já com o progresso atualizado
        enrollments = base_q.all()

        def _norm_status(s: str | None) -> str:
            return (s or "").strip().lower()

        # ----- 3) Contadores de status -----
        concluidos = sum(
            1 for e in enrollments
            if _norm_status(e.status) in {"concluído", "concluido", "completed"}
        )
        andamento = sum(
            1 for e in enrollments
            if _norm_status(e.status) in {"em andamento", "in_progress", "in progress"}
        )

        # ----- 4) Certificados do usuário -----
        certificados_lista = (
            Certificate.query
            .options(joinedload(Certificate.course))
            .filter_by(user_id=current_user.id)
            .order_by(Certificate.issued_at.desc())
            .all()
        )
        certificados = len(certificados_lista)

        # ----- 5) Cursos ainda não matriculados (empresa do usuário + globais) -----
        enrolled_ids = [e.course_id for e in enrollments if e.course_id]

        cursos_q = Course.query

        if getattr(current_user, "company_id", None):
            cursos_q = cursos_q.filter(
                or_(
                    Course.company_id == current_user.company_id,
                    Course.company_id.is_(None),
                )
            )
        else:
            cursos_q = cursos_q.filter(Course.company_id.is_(None))

        if enrolled_ids:
            cursos_q = cursos_q.filter(~Course.id.in_(enrolled_ids))

        cursos_disponiveis = (
            cursos_q
            .order_by(Course.name.asc())
            .all()
        )

        # ----- 6) Renderiza dashboard -----
        return render_template(
            "dashboard.html",
            enrollments=enrollments,
            concluidos=concluidos,
            andamento=andamento,
            certificados=certificados,
            certificados_lista=certificados_lista,
            cursos_disponiveis=cursos_disponiveis,
            periodo_atual="2025/2",
            catalogo_cursos=True,
            historico_certificados=True,
        )

    except Exception as e:
        print(f"[ERRO] Falha ao carregar dashboard: {e}")
        flash("Erro ao carregar seu painel. Tente novamente mais tarde.", "danger")
        return redirect(url_for("login"))

# =========================
# DOWNLOAD DO CERTIFICADO
# =========================
@app.route("/certificado/<int:certificate_id>/download")
@login_required
def download_certificado(certificate_id):
    cert = Certificate.query.get_or_404(certificate_id)

    # Agora Admin, RH, RHDP, TI e Auditoria podem baixar
    if cert.user_id != current_user.id and not is_admin_like():
        abort(403)

    if not cert.file_path or not os.path.exists(cert.file_path):
        flash("Arquivo de certificado não encontrado. Reemita o certificado.", "warning")
        return redirect(url_for("dashboard"))

    return send_file(cert.file_path, as_attachment=True, download_name=os.path.basename(cert.file_path))

@app.route("/certificados/<int:id>/baixar")
@login_required
def baixar_certificado(id):
    return download_certificado(id)

# =========================
# STREAM de VÍDEO local
# =========================
@app.route("/curso/<int:course_id>/stream")
@login_required
def stream_video(course_id):
    course = Course.query.get_or_404(course_id)
    if is_url(course.video_path):
        flash("Este vídeo é externo (YouTube). Abra pela página do curso.", "info")
        return redirect(url_for("curso_video", course_id=course.id))
    if not course.video_path or not os.path.exists(course.video_path):
        flash("Vídeo não encontrado. Verifique o 'video_path' do curso.", "warning")
        return redirect(url_for("dashboard"))
    return send_file(course.video_path, mimetype="video/mp4", conditional=True)

## =========================
# PÁGINA do VÍDEO + marcar como assistido
# =========================
@app.route("/curso/<int:course_id>/video", methods=["GET", "POST"])
@login_required
def curso_video(course_id):
    course = Course.query.get_or_404(course_id)

    # Só pode acessar cursos da própria empresa (se tiver company_id)
    if getattr(course, "company_id", None) and getattr(current_user, "company_id", None):
        if course.company_id != current_user.company_id:
            abort(403)

    # Garante matrícula
    enrollment = Enrollment.query.filter_by(
        user_id=current_user.id,
        course_id=course_id
    ).first()
    if not enrollment:
        flash("Você não está matriculado neste curso.", "danger")
        return redirect(url_for("dashboard"))

    # Busca/cria progresso de vídeo
    vp = VideoProgress.query.filter_by(
        user_id=current_user.id,
        course_id=course_id
    ).first()
    if not vp:
        vp = VideoProgress(
            user_id=current_user.id,
            course_id=course_id,
            watched=False,
            fully_watched=False,
            seconds_watched=0
        )
        # Se o modelo tiver progress_pct, garante que começa em 0
        if hasattr(VideoProgress, "progress_pct"):
            vp.progress_pct = 0
        db.session.add(vp)
        db.session.commit()

    # POST = vídeo terminou (ou clicou em "Marcar como assistido")
    if request.method == "POST":
        vp.watched = True
        if hasattr(vp, "fully_watched"):
            vp.fully_watched = True
        if hasattr(vp, "progress_pct"):
            vp.progress_pct = 100
        if hasattr(vp, "watched_at") and not getattr(vp, "watched_at", None):
            vp.watched_at = datetime.now(BR_TZ)
        db.session.commit()

        # Atualiza progresso da matrícula (vídeo + quiz)
        update_enrollment_progress(current_user.id, course_id)

        flash("🎬 Vídeo marcado como assistido! Quiz liberado.", "success")
        return redirect(url_for("quiz", course_id=course.id))

    # GET = só mostra o player
    return render_template("curso_video.html", course=course, progress=vp)


# =========================
# INÍCIO DO CURSO (decide se vai para vídeo ou direto pro quiz)
# =========================
@app.route("/curso/<int:course_id>/inicio")
@login_required
def curso_inicio(course_id):
    course = Course.query.get_or_404(course_id)

    # Verifica matrícula
    enrollment = Enrollment.query.filter_by(
        user_id=current_user.id,
        course_id=course_id
    ).first()
    if not enrollment:
        flash("Você não está matriculado neste curso.", "danger")
        return redirect(url_for("dashboard"))

    # Verifica se o vídeo já foi assistido
    vp = VideoProgress.query.filter_by(
        user_id=current_user.id,
        course_id=course_id
    ).first()

    watched = bool(
        vp and (
            getattr(vp, "watched", False)
            or getattr(vp, "fully_watched", False)
            or (getattr(vp, "progress_pct", 0) >= 95)
        )
    )

    # Se NÃO viu o vídeo → manda para o vídeo
    if not watched:
        return redirect(url_for("curso_video", course_id=course_id))

    # Se já viu → manda direto para o quiz
    return redirect(url_for("quiz", course_id=course_id))
# =========================
# QUIZ por NR + certificação
# =========================
def _emitir_certificado_para(
    user: User,
    company: Company,
    course: Course,
    when: datetime,
    *,
    ip_address: Optional[str] = None,
    access_dt: Optional[datetime] = None
):
    os.makedirs("generated", exist_ok=True)

    pdf_path = generate_certificate_pdf(
        user, company, course, when,
        out_dir="generated",
        ip_address=ip_address,
        access_dt=access_dt
    )

    cert = Certificate(
        user_id=user.id,
        course_id=course.id,
        company_id=company.id,
        file_path=pdf_path,
        issued_at=when
    )

    db.session.add(cert)

@app.route("/quiz/<int:course_id>", methods=["GET", "POST"])
@login_required
def quiz(course_id):
    course = Course.query.get_or_404(course_id)

    # Garante matrícula
    enroll = Enrollment.query.filter_by(
        user_id=current_user.id,
        course_id=course.id
    ).first()
    if not enroll:
        flash("Você não está matriculado neste curso.", "warning")
        return redirect(url_for("dashboard"))

    # Garante que assistiu o vídeo antes do quiz
    progress = VideoProgress.query.filter_by(
        user_id=current_user.id,
        course_id=course.id
    ).first()
    if not progress or not progress.watched:
        flash("Assista o vídeo do curso antes de iniciar o quiz.", "warning")
        return redirect(url_for("curso_video", course_id=course.id))

    # Carrega questões
    questions = (QuizQuestion.query
                 .filter_by(course_id=course.id)
                 .order_by(QuizQuestion.id.asc())
                 .all())
    if not questions:
        flash("Este curso ainda não possui questões cadastradas.", "info")
        return redirect(url_for("dashboard"))

    # 👉 Embaralha a ordem das perguntas a cada vez que o aluno entra no quiz
    random.shuffle(questions)

    # Prepara opções para o template
    for q in questions:
        q._view_options = _build_view_options(q)

    # Quantidade mínima de acertos
    must_hit = _must_pass_score(len(questions))

    # --- Controle de tentativas ---
    user_is_staff = is_admin_like() or _role() == "instrutor"

    attempts_qs = (QuizAttempt.query
                   .filter_by(user_id=current_user.id, course_id=course.id)
                   .order_by(QuizAttempt.id.desc()))
    attempts = attempts_qs.all()
    attempts_used = len([a for a in attempts if not a.blocked])

    # Se já esgotou tentativas (e não é staff), bloqueia
    if not user_is_staff and attempts_used >= MAX_QUIZ_ATTEMPTS:
        flash("Você atingiu o limite de 3 tentativas neste curso. Procure o RH/TI.", "danger")
        return redirect(url_for("dashboard"))

    # Deadline para o timer do front (1h a partir de agora)
    now = datetime.now(BR_TZ)
    deadline = now + timedelta(seconds=QUIZ_TIME_LIMIT_SECONDS)
    deadline_iso = deadline.isoformat()

    # --- POST: corrigir tentativa ---
    if request.method == "POST":
        # Reconta tentativas logo antes de salvar, por segurança
        attempts_used = len([
            a for a in attempts_qs.all()
            if not a.blocked
        ])
        if not user_is_staff and attempts_used >= MAX_QUIZ_ATTEMPTS:
            flash("Limite de tentativas atingido. Tentativa não registrada.", "danger")
            return redirect(url_for("dashboard"))

        correct = 0
        for q in questions:
            ans = (request.form.get(f"q{q.id}") or "").strip().lower()
            if ans == (q.correct or "").strip().lower():
                correct += 1

        score_pct = floor((correct / len(questions)) * 100)
        passed = (correct >= must_hit)

        # Cria registro da tentativa com info de auditoria/anti-fraude
        qa = QuizAttempt(
            user_id=current_user.id,
            course_id=course.id,
            score=score_pct,
            passed=passed,
            attempt_number=attempts_used + 1,
            time_limit_seconds=QUIZ_TIME_LIMIT_SECONDS,
            blocked=False,
            start_time=now,
            end_time=now,
            ip_address=(_get_client_ip() or "")[:64],
            user_agent=(request.headers.get("User-Agent", "") or "")[:256],
        )

        db.session.add(qa)

        # Garante enrollment (defensivo, na prática já existe)
        if not enroll:
            enroll = Enrollment(
                user_id=current_user.id,
                course_id=course.id,
                status="in_progress",
            )
            db.session.add(enroll)
            db.session.flush()

        # Atualiza progresso (vídeo + quiz) e, se for o caso, emite certificado
        e = update_enrollment_progress(current_user.id, course.id)

        # Feedback para o aluno
        if passed:
            if (e.status or "").lower() in {"concluído", "concluido", "completed"}:
                flash(
                    f"✅ Aprovado! Você acertou {correct}/{len(questions)} ({score_pct}%). "
                    f"Certificado emitido!",
                    "success"
                )
            else:
                flash(
                    f"✅ Aprovado! Você acertou {correct}/{len(questions)} ({score_pct}%). "
                    f"Conclua o vídeo para liberar o certificado.",
                    "success"
                )
        else:
            restante = max(0, MAX_QUIZ_ATTEMPTS - (attempts_used + 1))
            extra = f" Você ainda possui {restante} tentativa(s)." if not user_is_staff else ""
            flash(
                f"❌ Reprovado. Você acertou {correct}/{len(questions)} ({score_pct}%). "
                f"É necessário acertar pelo menos {must_hit}.{extra}",
                "danger"
            )

        return redirect(url_for("dashboard"))

    # --- GET: renderiza o quiz com contador, tentativas, etc. ---
    return render_template(
        "quiz.html",
        course=course,
        questions=questions,
        must_hit=must_hit,
        attempts_used=attempts_used,
        max_attempts=MAX_QUIZ_ATTEMPTS,
        user_is_staff=user_is_staff,
        deadline_iso=deadline_iso,
    )

# =========================
# Compat: finalizar_quiz
# =========================
@app.route("/quiz/<int:course_id>/finalizar", methods=["GET", "POST"])
@login_required
def finalizar_quiz(course_id):
    flash("Use a página do quiz para responder e finalizar.", "info")
    return redirect(url_for("quiz", course_id=course_id))

# =========================
# Painel ADMIN / RH / RHDP / TI / AUDITORIA
# =========================

def admin_like_required():
    """Permissão para: admin, rh, rhdp, ti, auditoria."""
    if not current_user.is_authenticated:
        abort(403)

    role = (current_user.role or "").lower()

    if role not in {"admin", "rh", "rhdp", "ti", "auditoria"}:
        flash("Você não tem permissão para acessar esta área.", "danger")
        return redirect(url_for("dashboard"))
    return True


@app.route("/admin")
@login_required
def admin_home():
    admin_like_required()
    return redirect(url_for("admin_empresas"))


@app.route("/rh", endpoint="rh_home")
@login_required
def rh_home():
    admin_like_required()
    return redirect(url_for("admin_usuarios"))

# =========================
# RELATÓRIO DE LOGIN (ADM/RH/RHDP/TI/AUDITORIA)
# =========================

def _fmt_duration(seconds):
    if not seconds:
        return "0h 00m"

    h = seconds // 3600
    m = (seconds % 3600) // 60

    return f"{h}h {m:02d}m"

@app.route("/admin/logins")
@login_required
def admin_logins():
    # Controle de acesso (admin, rh, rhdp, ti, auditoria)
    admin_required()

    # ----------------------------------------
    # Carrega empresas 1x (evita query repetida)
    # ----------------------------------------
    companies = {c.id: c.name for c in Company.query.all()}

    sessions = (
        LoginSession.query
        .join(User, LoginSession.user_id == User.id)
        .add_columns(
            User.id.label("uid"),
            User.name.label("user_name"),
            User.cpf.label("cpf"),
            User.company_id.label("company_id"),
            LoginSession.login_at,
            LoginSession.logout_at,
            LoginSession.duration_seconds,
            LoginSession.ip_address,
            LoginSession.user_agent,
        )
        .order_by(LoginSession.login_at.desc())
        .all()
    )

    grouped = {}

    for row in sessions:
        uid = row.uid

        # Cria bloco do usuário se ainda não existir
        if uid not in grouped:
            grouped[uid] = {
                "user_name": row.user_name,
                "cpf": row.cpf,
                "company": companies.get(row.company_id, "-"),
                "total_acessos": 0,
                "primeiro_login": None,
                "ultimo_login": None,
                "tempo_total": 0,
                "ult_ip": "-",
                "ult_browser": "-",
                "sessions": []
            }

        g = grouped[uid]
        g["total_acessos"] += 1

        # Primeiro login
        if not g["primeiro_login"] or (row.login_at and row.login_at < g["primeiro_login"]):
            g["primeiro_login"] = row.login_at

        # Último login
        if not g["ultimo_login"] or (row.login_at and row.login_at > g["ultimo_login"]):
            g["ultimo_login"] = row.login_at
            g["ult_ip"] = row.ip_address or "-"
            g["ult_browser"] = row.user_agent or "-"

        # Soma do tempo total
        if row.duration_seconds:
            g["tempo_total"] += row.duration_seconds

        g["sessions"].append(row)

    # Converte dict → lista e ordena por nome do usuário
    grupos_ordenados = sorted(grouped.values(), key=lambda x: x["user_name"].lower())

    return render_template("admin/logins.html", grupos=grupos_ordenados, fmt=_fmt_duration)

@app.route("/admin/logins/export")
@login_required
def admin_logins_export():
    admin_required()

    sessions = (
        LoginSession.query
        .join(User, LoginSession.user_id == User.id)
        .add_columns(
            User.name.label("user_name"),
            User.cpf.label("cpf"),
            User.company_id.label("company_id"),
            LoginSession.login_at,
            LoginSession.logout_at,
            LoginSession.duration_seconds,
            LoginSession.ip_address,
            LoginSession.user_agent,
        )
        .order_by(LoginSession.login_at.desc())
        .all()
    )

    output = StringIO()
    writer = csv.writer(output, delimiter=";")

    writer.writerow([
        "Nome", "CPF", "Empresa",
        "Login em", "Logout em",
        "Tempo Online (segundos)",
        "IP", "Navegador"
    ])

    for row in sessions:
        empresa = Company.query.get(row.company_id).name if row.company_id else "-"
        writer.writerow([
            row.user_name,
            row.cpf,
            empresa,
            row.login_at.strftime("%d/%m/%Y %H:%M:%S") if row.login_at else "-",
            row.logout_at.strftime("%d/%m/%Y %H:%M:%S") if row.logout_at else "-",
            row.duration_seconds or 0,
            row.ip_address or "-",
            row.user_agent or "-",
        ])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=relatorio_logins.csv"}
    )

# =========================
# VISUALIZAR CERTIFICADOS (ADM/RH/TI)
# =========================
@app.route("/admin/usuarios/<int:usuario_id>/certificados")
@login_required
def admin_usuarios_certificados(usuario_id):
    # Libera Admin, RH, RHDP, TI e Auditoria
    if not current_user.is_authenticated or not is_admin_like():
        abort(403)

    user = User.query.get_or_404(usuario_id)

    certificados = (
        Certificate.query
        .options(joinedload(Certificate.course))
        .filter_by(user_id=user.id)
        .order_by(Certificate.issued_at.desc())
        .all()
    )

    return render_template("admin/usuarios_certificados.html",
                           user=user,
                           certificados=certificados)

# logo abaixo das outras rotas /admin/usuarios...

@app.route("/admin/usuarios/<int:usuario_id>/provas")
@login_required
def admin_usuario_quiz_attempts(usuario_id):
    # mesma regra de permissão de certificados/logins
    if not current_user.is_authenticated or not is_admin_like():
        abort(403)

    user = User.query.get_or_404(usuario_id)

    # carrega as tentativas de quiz desse usuário
    attempts = (
        QuizAttempt.query
        .filter_by(user_id=user.id)
        .order_by(QuizAttempt.submitted_at.desc())
        .all()
    )

    return render_template(
        "admin/usuarios_provas.html",
        user=user,
        attempts=attempts,
    )

@app.route("/cursos", endpoint="cursos")
@login_required
def _cursos_alias():
    admin_required()
    return redirect(url_for("admin_cursos"))

@app.route("/nrs", endpoint="nrs")
@login_required
def _nrs_alias():
    admin_required()
    return redirect(url_for("admin_cursos"))

# ---- EMPRESAS (ADM/RH/TI) ----
@app.route("/admin/empresas", methods=["GET"])
@login_required
def admin_empresas():
    admin_required()
    empresas = Company.query.order_by(Company.id.asc()).all()
    return render_template("admin/empresas.html", empresas=empresas)

@app.route("/admin/empresas/add", methods=["POST"])
@login_required
def add_empresa():
    admin_required()
    name = (request.form.get("name") or "").strip()
    city_state = (request.form.get("city_state") or "Serra/ES").strip()
    if not name:
        flash("Nome da empresa é obrigatório.", "warning")
        return redirect(url_for("admin_empresas"))
    cpy = Company(name=name, city_state=city_state)
    db.session.add(cpy)
    db.session.commit()
    flash("Empresa criada com sucesso.", "success")
    return redirect(url_for("admin_empresas"))

@app.route("/admin/empresas/<int:empresa_id>/edit", methods=["GET", "POST"])
@login_required
def edit_empresa(empresa_id):
    admin_required()
    empresa = Company.query.get_or_404(empresa_id)
    if request.method == "POST":
        empresa.name = (request.form.get("name") or empresa.name).strip()
        empresa.city_state = (request.form.get("city_state") or empresa.city_state).strip()
        db.session.commit()
        flash("Empresa atualizada.", "success")
        return redirect(url_for("admin_empresas"))

    return render_template_string(r"""
    {% extends "base.html" %}
    {% block title %}Editar Empresa • LMS Apoio Engenharia{% endblock %}
    {% block content %}
    <h4 class="mb-4">Editar Empresa #{{ empresa.id }}</h4>
    <form method="post" class="card p-3 shadow-sm">
      <div class="row g-2">
        <div class="col-md-6">
          <label class="form-label">Nome</label>
          <input type="text" class="form-control" name="name" value="{{ empresa.name }}" required>
        </div>
        <div class="col-md-4">
          <label class="form-label">Cidade/UF</label>
          <input type="text" class="form-control" name="city_state" value="{{ empresa.city_state }}" required>
        </div>
        <div class="col-md-2 d-flex align-items-end">
          <button class="btn btn-primary w-100">Salvar</button>
        </div>
      </div>
    </form>
    {% endblock %}
    """, empresa=empresa)

@app.route("/admin/empresas/<int:empresa_id>/delete", methods=["GET"])
@login_required
def delete_empresa(empresa_id):
    admin_required()
    empresa = Company.query.get_or_404(empresa_id)
    if empresa.users or empresa.courses:
        flash("Não é possível excluir: empresa possui vínculos.", "warning")
        return redirect(url_for("admin_empresas"))
    db.session.delete(empresa)
    db.session.commit()
    flash("Empresa excluída.", "success")
    return redirect(url_for("admin_empresas"))

# ---- CURSOS (ADM/RH/TI) ----
@app.route("/admin/cursos", methods=["GET"])
@login_required
def admin_cursos():
    admin_required()
    cursos = Course.query.options(joinedload(Course.company)).order_by(Course.id.asc()).all()
    empresas = Company.query.order_by(Company.name.asc()).all()
    return render_template("admin/cursos.html", cursos=cursos, empresas=empresas)

@app.route("/admin/cursos/add", methods=["POST"])
@login_required
def add_curso():
    admin_required()
    name = (request.form.get("name") or "").strip()
    duration_hours = int(request.form.get("duration_hours") or 0)
    validity_months = int(request.form.get("validity_months") or 0)

    # permite empresa específica OU curso global (todas as empresas)
    company_raw = (request.form.get("company_id") or "").strip()
    company_id = int(company_raw) if company_raw.isdigit() and int(company_raw) > 0 else None

    description = (request.form.get("description") or "").strip()

    # agora company_id NÃO é obrigatório (pode ser None = global)
    if not (name and duration_hours > 0):
        flash("Preencha os campos obrigatórios.", "warning")
        return redirect(url_for("admin_cursos"))

    c = Course(
        name=name,
        duration_hours=duration_hours,
        validity_months=validity_months or 24,
        company_id=company_id,          # None = curso disponível para todas as empresas
        description=description or None
    )
    db.session.add(c)
    db.session.commit()
    flash("Curso criado com sucesso.", "success")
    return redirect(url_for("admin_cursos"))


@app.route("/admin/cursos/<int:curso_id>/edit", methods=["GET", "POST"])
@login_required
def edit_curso(curso_id):
    admin_required()
    c = Course.query.get_or_404(curso_id)
    empresas = Company.query.order_by(Company.name.asc()).all()

    if request.method == "POST":
        c.name = (request.form.get("name") or c.name).strip()
        c.duration_hours = int(request.form.get("duration_hours") or c.duration_hours or 0)
        c.validity_months = int(request.form.get("validity_months") or c.validity_months or 0)

        # 🔹 mesma lógica de "Todas as empresas" usada no add_curso
        company_raw = (request.form.get("company_id") or "").strip()
        if company_raw and company_raw.isdigit() and int(company_raw) > 0:
            c.company_id = int(company_raw)
        else:
            c.company_id = None   # curso global

        c.description = (request.form.get("description") or "").strip() or None

        # 🔹 NOVO: salva o link/caminho do vídeo (YouTube ou arquivo local)
        c.video_path = (request.form.get("video_path") or "").strip() or None

        db.session.commit()
        flash("Curso atualizado.", "success")
        return redirect(url_for("admin_cursos"))

    # Tela de edição
    return render_template_string(r"""
    {% extends "base.html" %}
    {% block title %}Editar Curso • LMS Apoio Engenharia{% endblock %}
    {% block content %}
    <h4 class="mb-3">Editar Curso #{{ c.id }}</h4>
    <form method="post" class="card p-3 shadow-sm">
      <div class="row g-2 align-items-end">
        <div class="col-md-5">
          <label class="form-label">Nome do Curso</label>
          <input type="text" class="form-control" name="name" value="{{ c.name }}" required>
        </div>
        <div class="col-md-2">
          <label class="form-label">Duração (h)</label>
          <input type="number" class="form-control" name="duration_hours"
                 value="{{ c.duration_hours or 0 }}" min="1" required>
        </div>
        <div class="col-md-2">
          <label class="form-label">Validade (meses)</label>
          <input type="number" class="form-control" name="validity_months"
                 value="{{ c.validity_months or 0 }}" min="0">
        </div>
        <div class="col-md-3">
          <label class="form-label">Empresa</label>
          <select class="form-select" name="company_id">
            <!-- opção global -->
            <option value="" {% if not c.company_id %}selected{% endif %}>
              Todas as empresas
            </option>
            <!-- empresas específicas -->
            {% for emp in empresas %}
              <option value="{{ emp.id }}" {% if emp.id == c.company_id %}selected{% endif %}>
                {{ emp.name }}
              </option>
            {% endfor %}
          </select>
        </div>

        <div class="col-12 mt-2">
          <label class="form-label">Descrição do curso</label>
          <textarea name="description" class="form-control" rows="3"
                    placeholder="Resumo/objetivos do curso...">{{ c.description or '' }}</textarea>
        </div>

        <!-- 🔹 NOVA ÁREA: LINK DO VÍDEO -->
        <div class="col-12 mt-2">
          <label class="form-label">Vídeo do curso (YouTube ou caminho local)</label>
          <input type="text"
                 name="video_path"
                 class="form-control"
                 placeholder="https://www.youtube.com/watch?v=...  ou  C:\videos\NR12.mp4"
                 value="{{ c.video_path or '' }}">
          <div class="form-text">
            Informe uma URL do YouTube ou o caminho de um arquivo .mp4 no servidor.
          </div>
        </div>

        <div class="col-12 text-end mt-3">
          <a class="btn btn-outline-secondary" href="{{ url_for('admin_cursos') }}">Cancelar</a>
          <button class="btn btn-primary">Salvar</button>
        </div>
      </div>
    </form>
    {% endblock %}
    """, c=c, empresas=empresas)



@app.route("/admin/cursos/<int:curso_id>/delete", methods=["GET"])
@login_required
def delete_curso(curso_id):
    admin_required()
    c = Course.query.get_or_404(curso_id)
    if Enrollment.query.filter_by(course_id=c.id).first() or Certificate.query.filter_by(course_id=c.id).first():
        flash("Não é possível excluir: curso possui matrículas ou certificados vinculados.", "warning")
        return redirect(url_for("admin_cursos"))
    db.session.delete(c)
    db.session.commit()
    flash("Curso excluído.", "success")
    return redirect(url_for("admin_cursos"))


# ---- VÍDEOS (ADM/RH/TI/INSTRUTOR) ----
@app.route("/admin/cursos/videos", methods=["GET", "POST"])
@login_required
def admin_cursos_videos():
    instrutor_or_admin_required()
    cursos = Course.query.order_by(Course.name.asc()).all()
    if request.method == "POST":
        updated = 0
        for c in cursos:
            new_v = (request.form.get(f"video_{c.id}") or "").strip()
            if (c.video_path or "") != new_v:
                c.video_path = new_v or None
                updated += 1
        db.session.commit()
        flash(f"Vídeos atualizados para {updated} curso(s).", "success")
        return redirect(url_for("admin_cursos_videos"))

    return render_template_string(r"""
    {% extends "base.html" %}
    {% block title %}Vincular vídeos • Cursos (NRs){% endblock %}
    {% block content %}
    <div class="card shadow-sm">
      <div class="card-body">
        <h5 class="mb-3">Vincular vídeos aos Cursos (NRs)</h5>
        <p class="text-muted">
          Preencha com <strong>URL do YouTube</strong> (ex.: https://www.youtube.com/watch?v=XXXX)
          ou caminho local (ex.: <code>C:\videos\NR35.mp4</code>). O player é escolhido automaticamente.
        </p>
        <form method="post">
          <div class="table-responsive">
            <table class="table align-middle">
              <thead>
                <tr>
                  <th style="width: 56px;">ID</th>
                  <th>Curso</th>
                  <th style="width: 40%;">URL/Caminho do Vídeo</th>
                  <th>Empresa</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {% for c in cursos %}
                <tr>
                  <td>{{ c.id }}</td>
                  <td>{{ c.name }}</td>
                  <td>
                    <input type="text" name="video_{{ c.id }}" class="form-control"
                           placeholder="https://www.youtube.com/watch?v=..."
                           value="{{ c.video_path or '' }}">
                  </td>
                  <td>{{ c.company.name if c.company else '-' }}</td>
                  <td>
                    <a class="btn btn-sm btn-outline-primary"
                       href="{{ url_for('admin_quiz', course_id=c.id) }}">Quiz</a>
                  </td>
                </tr>
                {% endfor %}
              </tbody>
            </table>
          </div>
          <div class="text-end">
            <a href="{{ url_for('admin_cursos') }}" class="btn btn-outline-secondary">Voltar</a>
            <button class="btn btn-primary">Salvar alterações</button>
          </div>
        </form>
      </div>
    </div>
    {% endblock %}
    """, cursos=cursos)


# =========================
# QUIZ — CRUD (ADM/RH/TI/INSTRUTOR)
# =========================
@app.route("/admin/cursos/<int:course_id>/quiz", methods=["GET", "POST"], endpoint="admin_quiz")
@login_required
def admin_quiz(course_id):
    instrutor_or_admin_required()
    course = Course.query.get_or_404(course_id)

    if request.method == "POST":
        text_ = (request.form.get("text") or "").strip()
        a = (request.form.get("a") or "").strip()
        b = (request.form.get("b") or "").strip()
        c = (request.form.get("c") or "").strip()
        d = (request.form.get("d") or "").strip()
        correct = (request.form.get("correct") or "").strip().lower()

        if not text_ or not a or not b or correct not in {"a", "b", "c", "d"}:
            flash("Preencha enunciado, A, B e marque o gabarito (A–D).", "warning")
            return redirect(url_for("admin_quiz", course_id=course.id))

        q = QuizQuestion(course_id=course.id, text=text_, correct=correct)
        _set_option_fields(q, a=a, b=b, c=(c or None), d=(d or None))
        db.session.add(q)
        db.session.commit()
        flash("Questão criada.", "success")
        return redirect(url_for("admin_quiz", course_id=course.id))

    questions = (
        QuizQuestion.query
        .filter_by(course_id=course.id)
        .order_by(QuizQuestion.id.asc())
        .all()
    )

    return render_template_string(r"""
    {% extends "base.html" %}
    {% block title %}Quiz • {{ course.name }}{% endblock %}
    {% block content %}
    <div class="d-flex justify-content-between align-items-center mb-3">
      <h4 class="mb-0">Quiz — {{ course.name }}</h4>
      <div>
        <a class="btn btn-outline-secondary btn-sm" href="{{ url_for('admin_cursos_videos') }}">Voltar</a>
        <a class="btn btn-primary btn-sm" target="_blank" href="{{ url_for('quiz', course_id=course.id) }}">Testar como aluno</a>
      </div>
    </div>

    <div class="row g-3">
      <div class="col-lg-6">
        <div class="card shadow-sm">
          <div class="card-body">
            <h6 class="mb-3">Nova questão</h6>
            <form method="post">
              <div class="mb-2">
                <label class="form-label">Enunciado</label>
                <textarea name="text" class="form-control" rows="3" required></textarea>
              </div>
              <div class="row g-2">
                <div class="col-12 col-md-6">
                  <label class="form-label">Alternativa A</label>
                  <input name="a" class="form-control" required>
                </div>
                <div class="col-12 col-md-6">
                  <label class="form-label">Alternativa B</label>
                  <input name="b" class="form-control" required>
                </div>
                <div class="col-12 col-md-6">
                  <label class="form-label">Alternativa C</label>
                  <input name="c" class="form-control">
                </div>
                <div class="col-12 col-md-6">
                  <label class="form-label">Alternativa D</label>
                  <input name="d" class="form-control">
                </div>
              </div>
              <div class="mt-2">
                <label class="form-label">Gabarito</label>
                <select class="form-select" name="correct" required>
                  <option value="">-- selecione --</option>
                  <option value="a">A</option>
                  <option value="b">B</option>
                  <option value="c">C</option>
                  <option value="d">D</option>
                </select>
              </div>
              <div class="text-end mt-3">
                <button class="btn btn-primary">Adicionar</button>
              </div>
            </form>
          </div>
        </div>
      </div>

      <div class="col-lg-6">
        <div class="card shadow-sm">
          <div class="card-body">
            <h6 class="mb-3">Questões cadastradas ({{ questions|length }})</h6>
            {% if questions %}
              <div class="list-group">
                {% for q in questions %}
                  <div class="list-group-item">
                    <div class="d-flex justify-content-between align-items-start">
                      <div>
                        <div class="fw-semibold">{{ loop.index }}. {{ q.text }}</div>
                        <div class="small text-muted mt-1">
                          A) {{ q.alt_a }}<br>
                          B) {{ q.alt_b }}{% if q.alt_c %}<br>C) {{ q.alt_c }}{% endif %}{% if q.alt_d %}<br>D) {{ q.alt_d }}{% endif %}
                          <div class="mt-1">
                            Gabarito: <span class="badge bg-success">{{ (q.correct or '').upper() }}</span>
                          </div>
                        </div>
                      </div>
                      <div class="ms-2">
                        <a class="btn btn-sm btn-outline-primary"
                           href="{{ url_for('admin_quiz_edit', course_id=course.id, qid=q.id) }}">Editar</a>
                        <a class="btn btn-sm btn-outline-danger"
                           href="{{ url_for('admin_quiz_delete', course_id=course.id, qid=q.id) }}"
                           onclick="return confirm('Excluir esta questão?');">Excluir</a>
                      </div>
                    </div>
                  </div>
                {% endfor %}
              </div>
            {% else %}
              <div class="text-muted">Nenhuma questão ainda.</div>
            {% endif %}
          </div>
        </div>
      </div>
    </div>
    {% endblock %}
    """, course=course, questions=questions)

@app.route("/admin/cursos/<int:course_id>/quiz/<int:qid>/edit", methods=["GET", "POST"], endpoint="admin_quiz_edit")
@login_required
def admin_quiz_edit(course_id, qid):
    instrutor_or_admin_required()
    course = Course.query.get_or_404(course_id)
    q = QuizQuestion.query.filter_by(id=qid, course_id=course.id).first_or_404()

    if request.method == "POST":
        q.text = (request.form.get("text") or q.text).strip()
        _set_option_fields(
            q,
            a=(request.form.get("a") or ""),
            b=(request.form.get("b") or ""),
            c=(request.form.get("c") or ""),
            d=(request.form.get("d") or "")
        )
        corr = (request.form.get("correct") or "").strip().lower()
        if corr not in {"a","b","c","d"}:
            flash("Gabarito inválido (use A, B, C ou D).", "warning")
            return redirect(url_for("admin_quiz_edit", course_id=course.id, qid=q.id))
        q.correct = corr
        db.session.commit()
        flash("Questão atualizada.", "success")
        return redirect(url_for("admin_quiz", course_id=course.id))

    return render_template_string(r"""
    {% extends "base.html" %}{% block title %}Editar Questão • {{ course.name }}{% endblock %}
    {% block content %}
    <h4 class="mb-3">Editar Questão — {{ course.name }}</h4>
    <form method="post" class="card p-3 shadow-sm">
      <div class="mb-2">
        <label class="form-label">Enunciado</label>
        <textarea name="text" class="form-control" rows="3" required>{{ q.text }}</textarea>
      </div>
      <div class="row g-2">
        <div class="col-12 col-md-6">
          <label class="form-label">Alternativa A</label>
          <input name="a" class="form-control" value="{{ q.alt_a or '' }}" required>
        </div>
        <div class="col-12 col-md-6">
          <label class="form-label">Alternativa B</label>
          <input name="b" class="form-control" value="{{ q.alt_b or '' }}" required>
        </div>
        <div class="col-12 col-md-6">
          <label class="form-label">Alternativa C</label>
          <input name="c" class="form-control" value="{{ q.alt_c or '' }}">
        </div>
        <div class="col-12 col-md-6">
          <label class="form-label">Alternativa D</label>
          <input name="d" class="form-control" value="{{ q.alt_d or '' }}">
        </div>
      </div>
      <div class="mt-2">
        <label class="form-label">Gabarito</label>
        <select class="form-select" name="correct" required>
          {% for k in ['a','b','c','d'] %}
            <option value="{{ k }}" {% if (q.correct or '')==k %}selected{% endif %}>{{ k|upper }}</option>
          {% endfor %}
        </select>
      </div>
      <div class="text-end mt-3">
        <a class="btn btn-outline-secondary" href="{{ url_for('admin_quiz', course_id=course.id) }}">Cancelar</a>
        <button class="btn btn-primary">Salvar</button>
      </div>
    </form>
    {% endblock %}
    """, course=course, q=q)


@app.route("/admin/cursos/<int:course_id>/quiz/<int:qid>/delete", methods=["GET"], endpoint="admin_quiz_delete")
@login_required
def admin_quiz_delete(course_id, qid):
    instrutor_or_admin_required()
    course = Course.query.get_or_404(course_id)
    q = QuizQuestion.query.filter_by(id=qid, course_id=course.id).first_or_404()
    db.session.delete(q)
    db.session.commit()
    flash("Questão excluída.", "success")
    return redirect(url_for("admin_quiz", course_id=course.id))

# =========================
# USUÁRIOS (ADM/RH/TI)
# =========================
@app.route("/admin/usuarios", methods=["GET"])
@login_required
def admin_usuarios():
    admin_required()
    usuarios = User.query.options(joinedload(User.company)).order_by(User.id.asc()).all()
    empresas = Company.query.order_by(Company.name.asc()).all()
    roles = Role.query.order_by(Role.name.asc()).all()
    return render_template("admin/usuarios.html", usuarios=usuarios, empresas=empresas, roles=roles)

@app.route("/admin/usuarios/add", methods=["GET", "POST"])
@login_required
def add_usuario():
    admin_required()

    # Usuário não deve acessar via GET → volta para lista
    if request.method == "GET":
        return redirect(url_for("admin_usuarios"))

    # ---------------------------------------
    # COLETAR CAMPOS
    # ---------------------------------------
    name = (request.form.get("name") or "").strip()
    cpf = _digits(request.form.get("cpf") or "")
    password = request.form.get("password") or ""
    company_id = int(request.form.get("company_id") or 0)
    role_name = (
        request.form.get("role") or
        request.form.get("role_name") or
        "employee"
    ).strip()

    # ---------------------------------------
    # VALIDAÇÕES
    # ---------------------------------------

    # Campos obrigatórios
    if not (name and cpf and password and company_id > 0):
        flash("Preencha todos os campos.", "warning")
        return redirect(url_for("admin_usuarios"))

    # CPF válido estruturalmente?
    if not _is_valid_cpf(cpf):
        flash("CPF inválido. Verifique os números digitados.", "warning")
        return redirect(url_for("admin_usuarios"))

    # CPF já cadastrado no sistema?
    if User.query.filter_by(cpf=cpf).first():
        flash("Já existe usuário com esse CPF.", "warning")
        return redirect(url_for("admin_usuarios"))

    # ---------------------------------------
    # CRIA USUÁRIO
    # ---------------------------------------
    u = User(
        name=name,
        cpf=cpf,
        password_hash=pbkdf2_sha256.hash(password),
        role=role_name,
        company_id=company_id
    )

    db.session.add(u)
    db.session.flush()  # garante que u.id exista

    # Matrículas automáticas conforme a função
    created = _auto_enroll_required_courses(u)

    db.session.commit()

    # ---------------------------------------
    # MENSAGEM FINAL
    # ---------------------------------------
    if created:
        flash(f"Usuário criado e {created} matrícula(s) gerada(s) automaticamente.", "success")
    else:
        flash("Usuário criado.", "success")

    return redirect(url_for("admin_usuarios"))

# ============================================================
# EDITAR USUÁRIO
# ============================================================
@app.route("/admin/usuarios/<int:usuario_id>/edit", methods=["GET", "POST"])
@login_required
def edit_usuario(usuario_id):
    admin_required()

    u = User.query.get_or_404(usuario_id)
    empresas = Company.query.order_by(Company.name.asc()).all()
    roles = Role.query.order_by(Role.name.asc()).all()

    if request.method == "POST":
        u.name = (request.form.get("name") or u.name).strip()
        new_cpf = _digits(request.form.get("cpf") or u.cpf)

        # -------------------------------
        # VALIDAR CPF NA EDIÇÃO
        # -------------------------------
        if not _is_valid_cpf(new_cpf):
            flash("CPF inválido. Verifique os números digitados.", "warning")
            return redirect(url_for("edit_usuario", usuario_id=u.id))

        # -------------------------------
        # OUTRO USUÁRIO JÁ USA ESTE CPF?
        # -------------------------------
        exists = User.query.filter(
            User.cpf == new_cpf,
            User.id != u.id
        ).first()
        if exists:
            flash("CPF já utilizado por outro usuário.", "warning")
            return redirect(url_for("edit_usuario", usuario_id=u.id))

        old_role = u.role
        u.cpf = new_cpf

        # -------------------------------
        # ATUALIZAR SENHA (se enviada)
        # -------------------------------
        new_password = request.form.get("password") or ""
        if new_password.strip():
            u.password_hash = pbkdf2_sha256.hash(new_password)

        # -------------------------------
        # ATUALIZAR EMPRESA E FUNÇÃO
        # -------------------------------
        u.company_id = int(request.form.get("company_id") or u.company_id or 0)
        u.role = (request.form.get("role") or u.role or "employee").strip()

        db.session.flush()

        # Se a função mudou → cria matrículas automáticas extras
        created = 0
        if u.role != old_role:
            created = _auto_enroll_required_courses(u)

        db.session.commit()

        flash(
            ("Usuário atualizado. %d nova(s) matrícula(s) criada(s) pela nova função." % created)
            if created else
            "Usuário atualizado.",
            "success"
        )
        return redirect(url_for("admin_usuarios"))

    # GET → renderiza a página
    return render_template_string(r"""
    {% extends "base.html" %}{% block title %}Editar Usuário • LMS Apoio Engenharia{% endblock %}
    {% block content %}
    <h4 class="mb-4">Editar Usuário #{{ u.id }}</h4>
    <form method="post" class="card p-3 shadow-sm">
      <div class="row g-2">
        <div class="col-md-4">
          <label class="form-label">Nome</label>
          <input type="text" class="form-control" name="name" value="{{ u.name }}" required>
        </div>
        <div class="col-md-3">
          <label class="form-label">CPF</label>
          <input type="text" class="form-control" name="cpf" value="{{ u.cpf }}" required>
        </div>
        <div class="col-md-3">
          <label class="form-label">Nova Senha (opcional)</label>
          <input type="password" class="form-control" name="password" placeholder="deixe em branco para manter">
        </div>
        <div class="col-md-2">
          <label class="form-label">Função</label>
          <select class="form-select" name="role" required>
            {% for r in roles %}
              <option value="{{ r.name }}" {% if r.name|lower == (u.role or '')|lower %}selected{% endif %}>{{ r.name }}</option>
            {% endfor %}
          </select>
        </div>
        <div class="col-md-4">
          <label class="form-label">Empresa</label>
          <select class="form-select" name="company_id" required>
            {% for emp in empresas %}
              <option value="{{ emp.id }}" {% if emp.id == u.company_id %}selected{% endif %}>{{ emp.name }}</option>
            {% endfor %}
          </select>
        </div>
        <div class="col-md-2 d-flex align-items-end">
          <button class="btn btn-primary w-100">Salvar</button>
        </div>
      </div>
    </form>
    {% endblock %}
    """, u=u, empresas=empresas, roles=roles)

@app.route("/admin/usuarios/<int:usuario_id>/delete", methods=["GET"])
@login_required
def delete_usuario(usuario_id):
    admin_required()
    u = User.query.get_or_404(usuario_id)
    if Enrollment.query.filter_by(user_id=u.id).first() or Certificate.query.filter_by(user_id=u.id).first():
        flash("Não é possível excluir: usuário possui matrículas/certificados.", "warning")
        return redirect(url_for("admin_usuarios"))
    db.session.delete(u)
    db.session.commit()
    flash("Usuário excluído.", "success")
    return redirect(url_for("admin_usuarios"))

# ---- FUNÇÕES (CARGOS) + NRs (ADM/RH/TI) ----
@app.route("/admin/funcoes", methods=["GET", "POST"])
@login_required
def admin_funcoes():
    admin_required()

    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        description = (request.form.get("description") or request.form.get("descricao") or "").strip()
        if not name:
            flash("Informe o nome da função.", "warning")
            return redirect(url_for("admin_funcoes"))
        if Role.query.filter(Role.name.ilike(name)).first():
            flash("Essa função já existe.", "warning")
            return redirect(url_for("admin_funcoes"))

        role = Role(name=name, description=description)
        db.session.add(role)
        db.session.flush()

        sel_cursos = {int(x) for x in request.form.getlist("course_ids") if x.isdigit()}
        for cid in sel_cursos:
            db.session.add(RoleRequirement(role_id=role.id, course_id=cid))

        db.session.commit()
        flash("Função criada com sucesso.", "success")
        return redirect(url_for("admin_funcoes"))

    q = (request.args.get("q") or "").strip()
    page = max(int(request.args.get("page", 1) or 1), 1)
    per_page = 12

    query = Role.query
    if q:
        like = f"%{q}%"
        query = query.filter(or_(Role.name.ilike(like), Role.description.ilike(like)))

    pagination = query.order_by(Role.name.asc()).paginate(page=page, per_page=per_page, error_out=False)
    funcoes = pagination.items

    cursos = Course.query.order_by(Course.name.asc()).all()

    return render_template("admin_funcoes.html",
                           funcoes=funcoes,
                           q=q,
                           pagination=pagination,
                           cursos=cursos)

@app.route("/admin/funcoes/<int:role_id>/edit", methods=["GET", "POST"], endpoint="edit_funcao")
@login_required
def edit_funcao(role_id):
    admin_required()
    role = Role.query.options(joinedload(Role.requirements)).get_or_404(role_id)
    cursos = Course.query.order_by(Course.name.asc()).all()

    if request.method == "POST":
        role.name = (request.form.get("name") or role.name).strip()
        role.description = (request.form.get("description") or request.form.get("descricao") or role.description or "").strip()

        sel_ids = {int(x) for x in request.form.getlist("course_ids") if x.isdigit()}
        for rr in list(role.requirements):
            if rr.course_id not in sel_ids:
                db.session.delete(rr)
        existing = {rr.course_id for rr in role.requirements}
        for cid in sel_ids - existing:
            db.session.add(RoleRequirement(role_id=role.id, course_id=cid))

        db.session.commit()
        flash("Função atualizada.", "success")
        return redirect(url_for("admin_funcoes"))

    selected_ids = {rr.course_id for rr in role.requirements}
    return render_template_string(r"""
    {% extends "base.html" %}
    {% block title %}Editar Função • LMS Apoio Engenharia{% endblock %}
    {% block content %}
    <h4 class="mb-3">Editar Função #{{ role.id }}</h4>
    <form method="post" class="card p-3 shadow-sm">
      <div class="row g-2 align-items-end mb-3">
        <div class="col-md-4">
          <label class="form-label">Nome</label>
          <input type="text" class="form-control" name="name" value="{{ role.name }}" required>
        </div>
        <div class="col-md-8">
          <label class="form-label">Descrição (opcional)</label>
          <input type="text" class="form-control" name="descricao" value="{{ role.description or '' }}">
        </div>
      </div>
      <div class="mb-2">
        <label class="form-label">NRs / Cursos exigidos</label>
        <div class="row">
          {% for c in cursos %}
            <div class="col-12 col-md-6 col-lg-4">
              <div class="form-check">
                <input class="form-check-input" type="checkbox" name="course_ids" value="{{ c.id }}"
                       id="c{{ c.id }}" {% if c.id in selected_ids %}checked{% endif %}>
                <label class="form-check-label" for="c{{ c.id }}">{{ c.name }}</label>
              </div>
            </div>
          {% endfor %}
        </div>
      </div>
      <div class="text-end">
        <a class="btn btn-outline-secondary" href="{{ url_for('admin_funcoes') }}">Cancelar</a>
        <button class="btn btn-primary">Salvar</button>
      </div>
    </form>
    {% endblock %}
    """, role=role, cursos=cursos, selected_ids=selected_ids)

@app.route("/admin/funcoes/<int:role_id>/delete", methods=["GET"])
@login_required
def delete_funcao(role_id):
    admin_required()
    role = Role.query.get_or_404(role_id)
    if (role.name or "").lower() in {"admin", "employee"}:
        flash("Funções padrão não podem ser removidas.", "warning")
        return redirect(url_for("admin_funcoes"))
    db.session.delete(role)
    db.session.commit()
    flash("Função excluída.", "success")
    return redirect(url_for("admin_funcoes"))

# Sua rota de vencimentos
@app.route("/admin/vencimentos")
@login_required
def admin_vencimentos():
    admin_required()

    today = datetime.now(BR_TZ).date()

    # Só matrículas concluídas
    concluidos = (
        Enrollment.query
        .filter(Enrollment.status.in_(["Concluído", "concluido", "completed"]))
        .order_by(Enrollment.user_id.asc())
        .all()
    )

    grupos_map = {}

    for e in concluidos:
        user = User.query.get(e.user_id)
        course = Course.query.get(e.course_id)
        if not user or not course:
            continue

        company = Company.query.get(user.company_id) if user.company_id else None

        # Data de conclusão
        concluido_em = e.completed_at.date() if e.completed_at else None

        # Data de vencimento (aproxima 1 mês = 30 dias)
        if concluido_em and course.validity_months:
            vence_em = concluido_em + timedelta(days=30 * course.validity_months)
        else:
            vence_em = None

        # Dias restantes
        dias_rest = (vence_em - today).days if vence_em else None

        # Status / cor do badge
        status_text, status_class = get_status(dias_rest)

        # Agrupa por usuário
        g = grupos_map.setdefault(
            user.id,
            {
                "user_name": user.name,
                "cpf": user.cpf,
                "company": company.name if company else "-",
                "cursos": [],
            }
        )

        g["cursos"].append({
            "course_name": course.name,
            "concluido_em": concluido_em,
            "vence_em": vence_em,
            "dias_restantes": dias_rest,
            "status_text": status_text,
            "status_class": status_class,
        })

    # Ordena usuários por nome
    grupos = sorted(grupos_map.values(), key=lambda g: g["user_name"].lower())
    # E cursos de cada usuário pelo que vence primeiro
    for g in grupos:
        g["cursos"].sort(
            key=lambda r: (r["dias_restantes"] is None, r["dias_restantes"] or 99999)
        )

    return render_template("admin/vencimentos.html", grupos=grupos)

def get_status(dias_restantes: Optional[int]):
    """
    Retorna (texto, classe_bootstrap) para o status de vencimento.
    Ajuste as regras conforme sua regra de negócio.
    """
    if dias_restantes is None:
        return ("Sem validade", "secondary")

    if dias_restantes < 0:
        return ("Vencido", "danger")

    if dias_restantes <= 30:
        return ("Vence em breve", "warning")

    return ("Válido", "success")



# Sua nova rota de exportação
@app.route('/admin/vencimentos/export')
@login_required
def admin_vencimentos_export():
    admin_required()

    today = datetime.now(BR_TZ).date()

    # Só matrículas concluídas
    concluidos = (
        Enrollment.query
        .filter(Enrollment.status.in_(["Concluído", "concluido", "completed"]))
        .order_by(Enrollment.user_id.asc())
        .all()
    )

    # Gerar o CSV
    output = StringIO()
    writer = csv.writer(output)
    
    # Escrever o cabeçalho do CSV
    writer.writerow([
        "Nome", "CPF", "Curso", "Concluído em", "Vence em", "Dias Restantes", "Status"
    ])
    
    # Processar e escrever os dados no CSV
    for e in concluidos:
        user = User.query.get(e.user_id)
        course = Course.query.get(e.course_id)
        if not user or not course:
            continue

        # Data de conclusão e vencimento
        concluido_em = e.completed_at.date() if e.completed_at else None
        if concluido_em and course.validity_months:
            vence_em = concluido_em + timedelta(days=30 * course.validity_months)
        else:
            vence_em = None
        
        dias_rest = (vence_em - today).days if vence_em else None
        
        # Status do curso
        status_text, status_class = get_status(dias_rest)  # Utilizando a função já definida

        # Escrever linha no CSV
        writer.writerow([
            user.name,
            user.cpf,
            course.name,
            concluido_em.strftime('%d/%m/%Y') if concluido_em else "-",
            vence_em.strftime('%d/%m/%Y') if vence_em else "-",
            dias_rest if dias_rest is not None else "-",
            status_text
        ])
    
    # Rewind para o início do arquivo antes de enviar
    output.seek(0)

    # Enviar o arquivo CSV como resposta
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=vencimentos_cursos.csv"}
    )


# =========================
# CLI
# =========================
@app.cli.command("migrate:roles")
def migrate_roles():
    with app.app_context():
        ensure_schema()
        print("• Schema verificado/ajustado.")

@app.cli.command("initdb")
def initdb():
    with app.app_context():
        db.create_all()
        ensure_schema()

        # ---------------------------------
        # EMPRESA PADRÃO (Apoio Engenharia)
        # ---------------------------------
        if not Company.query.first():
            apoio = Company(name="Apoio Engenharia", city_state="Serra/ES")
            db.session.add(apoio)
            db.session.commit()

        # ---------------------------------
        # EMPRESAS EXTRAS (APBVIX / WQ / INDUSTECH)
        # ---------------------------------
        empresas_extra = [
            ("APBVIX",      "Serra/ES"),  # APBVIX INDUSTRIA E COMERCIO...
            ("WQ SERVICOS", "Serra/ES"),  # WQ SERVICOS INDUSTRIAIS LTDA
            ("INDUSTECH",   "Serra/ES"),  # INDUSTECH COMERCIO E SERVICOS...
        ]

        for nome, cidade_uf in empresas_extra:
            if not Company.query.filter(Company.name.ilike(nome)).first():
                db.session.add(Company(name=nome, city_state=cidade_uf))

        db.session.flush()  # garante IDs de empresas

        # ---------------------------------
        # ADMIN PADRÃO (seu usuário)
        # ---------------------------------
        if not User.query.filter_by(cpf="14232832793").first():
            admin = User(
                name="Flávio Eliezer",
                cpf="14232832793",
                password_hash=pbkdf2_sha256.hash("admin"),
                role="admin",
                company_id=Company.query.first().id  # primeira empresa (Apoio)
            )
            db.session.add(admin)

        # ---------------------------------
        # Normaliza usuários que tenham "RH/DP" para "rhdp"
        # ---------------------------------
        for u in User.query.filter(User.role.ilike("rh/dp")).all():
            u.role = "rhdp"

        # ---------------------------------
        # PAPÉIS NECESSÁRIOS (idempotente)
        # ---------------------------------
        required_roles = [
            ("ADMIN",    "Acesso total ao painel"),
            ("CEO",      "Acesso total ao painel"),
            ("CFO",      "Acesso total ao painel"),
            ("employee", "Colaborador padrão"),
            ("RH",       "Recursos Humanos"),
            ("DP",       "Departamento Pessoal / DP"),
            ("TI",       "Tecnologia da Informação"),
            ("INSTRUTOR","Gerencia vídeos e quizzes"),
        ]
        for name, desc in required_roles:
            if not Role.query.filter(Role.name.ilike(name)).first():
                db.session.add(Role(name=name, description=desc))

        # ---------------------------------
        # CURSOS DEMO (somente se não houver nenhum curso)
        # ---------------------------------
        if not Course.query.first():
            cid = Company.query.first().id
            cursos = [
                Course(
                    name="NR-12 - Segurança em Máquinas e Equipamentos",
                    company_id=cid,
                    duration_hours=4,
                    validity_months=24,
                    video_path=r"C:\videos\NR12.mp4"
                ),
                Course(
                    name="NR-18 - Montador de Andaimes",
                    company_id=cid,
                    duration_hours=4,
                    validity_months=24,
                    video_path=r"C:\videos\NR18.mp4"
                ),
                Course(
                    name="NR-33 - Espaços Confinados",
                    company_id=cid,
                    duration_hours=16,
                    validity_months=12,
                    video_path=r"C:\videos\NR33.mp4"
                ),
                Course(
                    name="NR-35 - Trabalho em Altura",
                    company_id=cid,
                    duration_hours=8,
                    validity_months=24,
                    video_path="https://www.youtube.com/watch?v=dQw4w9WgXcQ"
                ),
            ]
            db.session.add_all(cursos)

        db.session.commit()
        print("✅ Banco inicializado, empresas, papéis e admin garantidos.")


@app.cli.command("seed:users")
def seed_users():
    """Cria/garante empresa, papéis e usuários de exemplo (idempotente)."""
    with app.app_context():
        db.create_all()
        ensure_schema()

        # Empresa
        company = Company.query.filter_by(name="Apoio Engenharia").first()
        if not company:
            company = Company(name="Apoio Engenharia", city_state="Serra/ES")
            db.session.add(company)
            db.session.commit()

        # Papéis
        needed_roles = [
            ("admin",     "Acesso total ao painel"),
            ("employee",  "Colaborador padrão"),
            ("rh",        "Recursos Humanos"),
            ("rhdp",      "Recursos Humanos / DP"),
            ("ti",        "Tecnologia da Informação"),
            ("instrutor", "Gerencia vídeos e quizzes"),
            ("mecanico",  "Mecânico"),
            ("Montador de Andaimes", None),
            ("Eletricista",           None),
        ]
        for name, desc in needed_roles:
            if not Role.query.filter(Role.name.ilike(name)).first():
                db.session.add(Role(name=name, description=desc))
        db.session.commit()

        # Usuários (cpf -> senha)
        users_wanted = [
            ("Administrador", "00000000000", "admin",     "admin"),
            ("Rita RH",       "11111111111", "rh",        "rh123"),
            ("Paulo RH/DP",   "22222222222", "rhdp",      "rhdp123"),
            ("Tadeu TI",      "33333333333", "ti",        "ti123"),
            ("Ivan Instrutor","44444444444", "instrutor", "instrutor123"),
            ("Mário Mecânico","55555555555", "mecanico",  "mecanico123"),
            ("Colaborador",   "66666666666", "employee",  "colab123"),
        ]

        created = 0
        for name, cpf, role, pwd in users_wanted:
            cpf_digits = "".join(ch for ch in cpf if ch.isdigit())
            u = User.query.filter_by(cpf=cpf_digits).first()
            if not u:
                u = User(
                    name=name,
                    cpf=cpf_digits,
                    password_hash=pbkdf2_sha256.hash(pwd),
                    role=role,
                    company_id=company.id
                )
                db.session.add(u)
                db.session.flush()
                _auto_enroll_required_courses(u)
                created += 1
        db.session.commit()

        # Cursos demo (se ainda não tiver)
        if not Course.query.first():
            cid = company.id
            demo = [
                Course(name="NR-12 - Segurança em Máquinas e Equipamentos", company_id=cid, duration_hours=4,  validity_months=24, video_path=r"C:\videos\NR12.mp4"),
                Course(name="NR-18 - Montador de Andaimes",                  company_id=cid, duration_hours=4,  validity_months=24, video_path=r"C:\videos\NR18.mp4"),
                Course(name="NR-33 - Espaços Confinados",                     company_id=cid, duration_hours=16, validity_months=12, video_path=r"C:\videos\NR33.mp4"),
                Course(name="NR-35 - Trabalho em Altura",                     company_id=cid, duration_hours=8,  validity_months=24, video_path="https://www.youtube.com/watch?v=dQw4w9WgXcQ"),
            ]
            db.session.add_all(demo)
            db.session.commit()

        print(f"✅ Seed concluído. Usuários criados agora: {created}")
        print("Use: flask --app app.py users:list para conferir.")

@app.cli.command("fix:roles")
def fix_roles():
    """Normaliza papéis conhecidos (ex.: 'RH/DP' -> 'rhdp')."""
    with app.app_context():
        changed = 0
        for u in User.query.filter(User.role.ilike("rh/dp")).all():
            u.role = "rhdp"; changed += 1
        db.session.commit()
        print(f"✅ Papéis normalizados: {changed} usuário(s) ajustado(s).")

@app.cli.command("users:list")
def list_users():
    with app.app_context():
        users = User.query.order_by(User.id.asc()).all()
        if not users:
            print("Nenhum usuário. Rode: flask --app app.py initdb")
            return
        print(f"{'ID':<4} {'NOME':<25} {'CPF':<14} {'ROLE':<12} {'EMPRESA'}")
        print("-"*80)
        for u in users:
            empresa = Company.query.get(u.company_id).name if u.company_id else "-"
            print(f"{u.id:<4} {u.name[:25]:<25} {u.cpf:<14} {u.role:<12} {empresa}")

# =========================
# DEMO
# =========================
@app.route("/demo/matricular")
@login_required
def demo_matricular():
    admin_required()
    courses = Course.query.all()
    created = 0
    for c in courses:
        if not Enrollment.query.filter_by(user_id=current_user.id, course_id=c.id).first():
            db.session.add(Enrollment(user_id=current_user.id, course_id=c.id, status="Pendente"))
            created += 1
    db.session.commit()
    flash(f"{created} matrículas criadas para {current_user.name}.", "success")
    return redirect(url_for("dashboard"))

@app.route("/api/company-by-cpf", methods=["GET"])
def api_company_by_cpf():

    """
    Retorna a logo e o nome da empresa de acordo com o CPF digitado
    (sem precisar autenticar).
    """
    cpf = _digits(request.args.get("cpf") or "")
    if not cpf:
        return jsonify(ok=False, error="cpf obrigatório"), 400

    user = User.query.filter_by(cpf=cpf).first()
    if not user or not getattr(user, "company_id", None):
        # Se não achar usuário, volta só com a logo padrão do sistema
        default_logo = url_for("static", filename="img/Grupo_Apoio.png")
        return jsonify(ok=True, logo=default_logo, company_name=None)

    company = Company.query.get(user.company_id)

    # Se você tiver um campo logo_path na tabela Company, usa ele.
    # Senão, cai no padrão.
    logo_path = getattr(company, "logo_path", None) or "img/Grupo_Apoio.png"

    # Se for URL externa, usa direto; se for caminho relativo, usa static
    if is_url(logo_path):
        logo_url = logo_path
    else:
        logo_url = url_for("static", filename=logo_path)

    return jsonify(
        ok=True,
        logo=logo_url,
        company_name=company.name if company else None
    )

# =========================
# APIs de Progresso (player/quiz)
# =========================
@app.route("/api/progresso/video", methods=["POST"])
@login_required
def api_progresso_video():

    data = request.get_json(force=True, silent=True) or {}
    course_id = int(data.get("course_id") or 0)
    pct = max(0, min(100, int(data.get("progress_pct") or 0)))
    if not course_id:
        return {"ok": False, "error": "course_id obrigatório"}, 400
    vp = VideoProgress.query.filter_by(user_id=current_user.id, course_id=course_id).first()
    if not vp:
        vp = VideoProgress(user_id=current_user.id, course_id=course_id)
        db.session.add(vp)
    if hasattr(vp, "progress_pct"):
        vp.progress_pct = pct
    vp.watched = (pct >= 95)
    if vp.watched and not getattr(vp, "watched_at", None):
        vp.watched_at = datetime.now(BR_TZ)
    db.session.commit()
    e = update_enrollment_progress(current_user.id, course_id)
    return {"ok": True, "completion_pct": getattr(e, "completion_pct", None), "status": e.status}

@app.route("/api/progresso/quiz", methods=["POST"])
@login_required
def api_progresso_quiz():
    data = request.get_json(force=True, silent=True) or {}
    course_id = int(data.get("course_id") or 0)
    if not course_id:
        return {"ok": False, "error": "course_id obrigatório"}, 400
    e = update_enrollment_progress(current_user.id, course_id)
    return {"ok": True, "completion_pct": getattr(e, "completion_pct", None), "status": e.status}

# =========================
# Errors
# =========================
@app.errorhandler(403)
def _403(e):
    return render_template_string(r"""
    {% extends "base.html" %}{% block title %}Acesso negado{% endblock %}
    {% block content %}
      <div class="alert alert-danger">Você não tem permissão para acessar este recurso.</div>
      <a class="btn btn-primary" href="{{ url_for('dashboard') }}">Voltar</a>
    {% endblock %}
    """), 403

@app.errorhandler(404)
def _404(e):
    return render_template_string(r"""
    {% extends "base.html" %}{% block title %}Não encontrado{% endblock %}
    {% block content %}
      <div class="alert alert-warning">Recurso não encontrado.</div>
      <a class="btn btn-primary" href="{{ url_for('dashboard') }}">Voltar</a>
    {% endblock %}
    """), 404

# === Security headers (ISO/IEC 27002-aligned) + CSP liberando CDN/YT/QR ===
@app.after_request
def add_security_headers(resp):
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

    # ⬇⬇⬇ AQUI É O PONTO IMPORTANTE: 'unsafe-inline' em script-src
    csp = (
        "default-src 'self'; "
        "img-src 'self' data: https: https://chart.googleapis.com https://*.googleapis.com; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "font-src 'self' https://cdn.jsdelivr.net; "
        "frame-src 'self' https://www.youtube.com https://www.youtube-nocookie.com; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )
    resp.headers.setdefault("Content-Security-Policy", csp)
    return resp

@app.get("/politica-privacidade")
def politica_privacidade():
    return render_template("politica_privacidade.html")

# === 2FA Setup & Disable ===
@app.route("/security/2fa/setup", methods=["GET","POST"])
@login_required
def security_2fa_setup():
    if not current_user.twofa_secret:
        secret = ensure_secret()
    else:
        secret = current_user.twofa_secret
    otpauth = otpauth_uri(current_user.name or current_user.cpf, secret)
    qr_url = qr_via_google_charts(otpauth)
    if request.method == "POST":
        otp = (request.form.get("otp") or "").strip()
        if verify_otp(secret, otp):
            current_user.twofa_secret = secret
            current_user.twofa_enabled = True
            db.session.commit()
            audit("2fa_enabled", object_type="User", object_id=current_user.id)
            flash("2FA ativado com sucesso.", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Código inválido. Tente novamente.", "danger")
    return render_template("security/2fa_setup.html", secret=secret, qr_url=qr_url)

@app.route("/security/2fa/disable")
@login_required
def security_2fa_disable():
    current_user.twofa_enabled = False
    current_user.twofa_secret = None
    db.session.commit()
    audit("2fa_disabled", object_type="User", object_id=current_user.id)
    flash("2FA desativado.", "warning")
    return redirect(url_for("dashboard"))

@app.route("/login/otp", methods=["GET", "POST"])
def login_otp():
    # Usuário só deve chegar aqui se tiver passado pelo login e tiver 2FA habilitado
    uid = session.get("otp_user_id")
    if not uid:
        return redirect(url_for("login"))

    user = User.query.get(uid)
    if not user or not getattr(user, "twofa_enabled", False):
        # Algo incoerente: sem usuário ou 2FA desativado
        session.pop("otp_user_id", None)
        flash("Sessão inválida. Faça login novamente.", "warning")
        return redirect(url_for("login"))

    if request.method == "POST":
        otp = (request.form.get("otp") or "").strip()

        if verify_otp(user.twofa_secret, otp):
            # Limpa flag de 2FA pendente
            session.pop("otp_user_id", None)

            # Faz login definitivo
            login_user(user)

            # Registra sessão de login para o relatório
            try:
                _start_login_session(user)
            except Exception as e:
                print("[WARN] Falha ao iniciar sessão de login (2FA):", e)

            # Auditoria de login concluído com 2FA
            try:
                audit("login", object_type="User", object_id=user.id)
            except Exception as e:
                print("[WARN] Falha ao registrar auditoria de login (2FA):", e)

            return redirect(url_for("dashboard"))
        else:
            flash("Código 2FA inválido.", "danger")

    return render_template("security/2fa_prompt.html")

# =========================
# Troca obrigatória de senha no primeiro login
# =========================
@app.route("/change_password_first", methods=["GET", "POST"])
def change_password_first():
    user_id = session.get("change_pass_user")
    if not user_id:
        flash("Sessão expirada. Faça login novamente.", "warning")
        return redirect(url_for("login"))

    user = User.query.get_or_404(user_id)

    if request.method == "POST":
        new = request.form.get("new_password") or ""
        conf = request.form.get("confirm_password") or ""

        if new != conf:
            flash("As senhas não conferem.", "danger")
            return redirect(url_for("change_password_first"))

        if len(new) < 6:
            flash("A senha deve ter pelo menos 6 caracteres.", "warning")
            return redirect(url_for("change_password_first"))

        user.password_hash = pbkdf2_sha256.hash(new)
        user.first_login = False
        db.session.commit()

        # Libera login agora que senha foi trocada
        session.pop("change_pass_user", None)
        login_user(user)

        flash("Senha atualizada com sucesso!", "success")
        return redirect(url_for("dashboard"))

    return render_template("change_password_first.html")


# =========================
# Run
# =========================
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        ensure_schema()
    app.run(debug=True)
