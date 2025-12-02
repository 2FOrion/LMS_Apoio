from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from sqlalchemy import UniqueConstraint, CheckConstraint, Index

db = SQLAlchemy()

# =====================
# EMPRESAS
# =====================
class Company(db.Model):
    __tablename__ = "company"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    city_state = db.Column(db.String(80), default="Serra/ES")

    # Caminho da logo relativa à pasta static (ex: "img/apoio_logo.png")
    logo_path = db.Column(db.String(255), nullable=True)

    users = db.relationship("User", backref="company", lazy=True, cascade="all, delete-orphan")
    courses = db.relationship("Course", backref="company", lazy=True, cascade="all, delete-orphan")


# =====================
# FUNÇÕES / CARGOS
# =====================
class Role(db.Model):
    __tablename__ = "role"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(40), unique=True, nullable=False)
    description = db.Column(db.String(255))

    requirements = db.relationship("RoleRequirement", back_populates="role", lazy=True, cascade="all, delete-orphan")


# =====================
# USUÁRIOS
# =====================
class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)

    # você salva só dígitos (11), mas deixa 14 pra ser compatível com bases antigas
    cpf = db.Column(db.String(14), unique=True, nullable=False, index=True)

    name = db.Column(db.String(150), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(40), default="employee")
    company_id = db.Column(db.Integer, db.ForeignKey("company.id"), nullable=False)

    # Primeiro acesso
    first_login = db.Column(db.Boolean, default=True)

    # 2FA
    twofa_enabled = db.Column(db.Boolean, default=False)
    twofa_secret = db.Column(db.String(64))
    twofa_recovery = db.Column(db.String(64))
    twofa_grace_until = db.Column(db.DateTime)

    # Relacionamentos
    enrollments = db.relationship("Enrollment", back_populates="user", lazy=True, cascade="all, delete-orphan")
    certificates = db.relationship("Certificate", back_populates="user", lazy=True, cascade="all, delete-orphan")
    quiz_attempts = db.relationship("QuizAttempt", back_populates="user", lazy=True, cascade="all, delete-orphan")
    video_progress = db.relationship("VideoProgress", back_populates="user", lazy=True, cascade="all, delete-orphan")
    login_sessions = db.relationship("LoginSession", back_populates="user", lazy=True, cascade="all, delete-orphan")

    # LGPD
    privacy_consents = db.relationship("PrivacyConsent", back_populates="user", lazy=True, cascade="all, delete-orphan")
    privacy_requests = db.relationship("PrivacyRequest", back_populates="user", lazy=True, cascade="all, delete-orphan")
    audit_logs = db.relationship("AuditLog", back_populates="user", lazy=True, cascade="all, delete-orphan")


# =====================
# CURSOS
# =====================
class Course(db.Model):
    __tablename__ = "course"
    id = db.Column(db.Integer, primary_key=True)

    # Pode ser nulo → curso válido para todas as empresas
    company_id = db.Column(
        db.Integer,
        db.ForeignKey("company.id"),
        nullable=True
    )

    name = db.Column(db.String(200), nullable=False)
    duration_hours = db.Column(db.Integer, default=8)
    validity_months = db.Column(db.Integer, default=24)
    description = db.Column(db.Text)

    # vídeo (YouTube ou caminho local)
    video_path = db.Column(db.String(300))

    # 🔹 NOVO: caminho do arquivo de apostila (PDF) no servidor
    # pode ser algo como "apostilas/NR12.pdf"
    apostila_path = db.Column(db.String(512))

    enrollments = db.relationship("Enrollment", back_populates="course", lazy=True, cascade="all, delete-orphan")
    certificates = db.relationship("Certificate", back_populates="course", lazy=True, cascade="all, delete-orphan")
    quiz_questions = db.relationship("QuizQuestion", back_populates="course", lazy=True, cascade="all, delete-orphan")
    quiz_attempts = db.relationship("QuizAttempt", back_populates="course", lazy=True, cascade="all, delete-orphan")
    video_progress = db.relationship("VideoProgress", back_populates="course", lazy=True, cascade="all, delete-orphan")
    requirements = db.relationship("RoleRequirement", back_populates="course", lazy=True, cascade="all, delete-orphan")


# =====================
# FUNÇÃO x CURSO
# =====================
class RoleRequirement(db.Model):
    __tablename__ = "role_requirement"
    id = db.Column(db.Integer, primary_key=True)
    role_id = db.Column(db.Integer, db.ForeignKey("role.id"), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey("course.id"), nullable=False)

    role = db.relationship("Role", back_populates="requirements")
    course = db.relationship("Course", back_populates="requirements")

    __table_args__ = (UniqueConstraint("role_id", "course_id", name="uq_role_course"),)


# =====================
# MATRÍCULAS
# =====================
class Enrollment(db.Model):
    __tablename__ = "enrollment"
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    course_id = db.Column(db.Integer, db.ForeignKey("course.id"), nullable=False, index=True)

    status = db.Column(db.String(20), default="in_progress")
    completed_at = db.Column(db.DateTime)

    video_completed_at = db.Column(db.DateTime)
    quiz_completed_at = db.Column(db.DateTime)
    completion_pct = db.Column(db.Integer)

    must_watch_video = db.Column(db.Boolean, default=True)
    must_pass_quiz = db.Column(db.Boolean, default=True)

    final_score = db.Column(db.Integer)
    approved = db.Column(db.Boolean, default=False)

    user = db.relationship("User", back_populates="enrollments")
    course = db.relationship("Course", back_populates="enrollments")

    __table_args__ = (UniqueConstraint("user_id", "course_id", name="uq_enrollment_user_course"),)


# =====================
# CERTIFICADOS
# =====================
class Certificate(db.Model):
    __tablename__ = "certificate"
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    company_id = db.Column(db.Integer, db.ForeignKey("company.id"), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey("course.id"), nullable=False, index=True)

    file_path = db.Column(db.String(512), nullable=False)
    issued_at = db.Column(db.DateTime, default=datetime.utcnow)
    verify_url = db.Column(db.String(512))

    user = db.relationship("User", back_populates="certificates")
    course = db.relationship("Course", back_populates="certificates")


# =====================
# QUIZ – PERGUNTAS
# =====================
class QuizQuestion(db.Model):
    __tablename__ = "quiz_question"
    id = db.Column(db.Integer, primary_key=True)
    course_id = db.Column(db.Integer, db.ForeignKey("course.id"), nullable=False, index=True)

    text = db.Column(db.Text, nullable=False)
    alt_a = db.Column(db.Text, nullable=False)
    alt_b = db.Column(db.Text, nullable=False)
    alt_c = db.Column(db.Text)
    alt_d = db.Column(db.Text)
    correct = db.Column(db.String(1), nullable=False)

    course = db.relationship("Course", back_populates="quiz_questions")


# =====================
# QUIZ – TENTATIVAS
# =====================
class QuizAttempt(db.Model):
    __tablename__ = "quiz_attempt"
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    course_id = db.Column(db.Integer, db.ForeignKey("course.id"), nullable=False, index=True)

    score = db.Column(db.Integer, nullable=False)
    passed = db.Column(db.Boolean, default=False)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)

    start_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    end_time = db.Column(db.DateTime)

    ip_address = db.Column(db.String(64))
    user_agent = db.Column(db.String(256))

    attempt_number = db.Column(db.Integer, default=1)
    time_limit_seconds = db.Column(db.Integer, default=3600)

    blocked = db.Column(db.Boolean, default=False)
    fraud_reason = db.Column(db.String(255))
    locked_until = db.Column(db.DateTime)

    user = db.relationship("User", back_populates="quiz_attempts")
    course = db.relationship("Course", back_populates="quiz_attempts")

    __table_args__ = (
        CheckConstraint("score >= 0 AND score <= 100"),
        Index("ix_quiz_attempt_user_course_time", "user_id", "course_id", "submitted_at"),
    )


# =====================
# PROGRESSO DO VÍDEO
# =====================
class VideoProgress(db.Model):
    __tablename__ = "video_progress"
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    course_id = db.Column(db.Integer, db.ForeignKey("course.id"), nullable=False, index=True)

    watched = db.Column(db.Boolean, default=False)
    seconds_watched = db.Column(db.Integer, default=0)
    duration_seconds = db.Column(db.Integer, default=0)
    watched_percent = db.Column(db.Float, default=0.0)
    progress_pct = db.Column(db.Integer, default=0)

    fully_watched = db.Column(db.Boolean, default=False)
    last_position = db.Column(db.Float, default=0.0)
    fraud_flag = db.Column(db.String(255))

    watched_at = db.Column(db.DateTime)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = db.relationship("User", back_populates="video_progress")
    course = db.relationship("Course", back_populates="video_progress")

    __table_args__ = (
        UniqueConstraint("user_id", "course_id"),
        CheckConstraint("seconds_watched >= 0"),
    )


# =====================
# LOGIN SESSIONS
# =====================
class LoginSession(db.Model):
    __tablename__ = "login_session"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)

    login_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    logout_at = db.Column(db.DateTime)
    duration_seconds = db.Column(db.Integer)

    ip_address = db.Column(db.String(64))
    user_agent = db.Column(db.String(256))

    user = db.relationship("User", back_populates="login_sessions")


# =====================
# LGPD – CONSENTIMENTOS
# =====================
class PrivacyConsent(db.Model):
    __tablename__ = "privacy_consent"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)

    purpose = db.Column(db.String(120), nullable=False)
    legal_basis = db.Column(db.String(80), nullable=False)
    granted = db.Column(db.Boolean, default=True)
    granted_at = db.Column(db.DateTime, default=datetime.utcnow)

    ip_address = db.Column(db.String(64))
    user_agent = db.Column(db.String(256))
    extra = db.Column(db.Text)

    user = db.relationship("User", back_populates="privacy_consents")


# =====================
# LGPD – REQUISIÇÕES
# =====================
class PrivacyRequest(db.Model):
    __tablename__ = "privacy_request"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)

    kind = db.Column(db.String(40), nullable=False)
    status = db.Column(db.String(40), default="aberta")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)

    details = db.Column(db.Text)
    resolution = db.Column(db.Text)

    user = db.relationship("User", back_populates="privacy_requests")


# =====================
# LGPD – LOG DE AUDITORIA
# =====================
class AuditLog(db.Model):
    __tablename__ = "audit_log"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), index=True)

    action = db.Column(db.String(120), nullable=False)
    object_type = db.Column(db.String(80))
    object_id = db.Column(db.Integer)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    ip = db.Column(db.String(64))
    user_agent = db.Column(db.String(256))
    meta = db.Column(db.Text)

    user = db.relationship("User", back_populates="audit_logs")
