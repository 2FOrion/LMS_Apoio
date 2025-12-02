from passlib.hash import pbkdf2_sha256
from app import app, db, User, Company, Course

with app.app_context():
    db.create_all()

    comp = Company.query.filter_by(name="Apoio Engenharia").first()
    if not comp:
        comp = Company(name="Apoio Engenharia", city_state="Serra/ES")
        db.session.add(comp)
        db.session.commit()

    admin = User.query.filter_by(cpf="00000000000").first()
    if not admin:
        admin = User(
            name="Administrador",
            cpf="00000000000",
            password_hash=pbkdf2_sha256.hash("admin"),
            role="admin",
            company_id=comp.id
        )
        db.session.add(admin)

    if not Course.query.first():
        cursos = [
            Course(name="NR-12 - Segurança em Máquinas e Equipamentos", company_id=comp.id, duration_hours=4, validity_months=24),
            Course(name="NR-18 - Montador de Andaimes", company_id=comp.id, duration_hours=4, validity_months=24),
            Course(name="NR-33 - Espaços Confinados", company_id=comp.id, duration_hours=16, validity_months=12),
            Course(name="NR-35 - Trabalho em Altura", company_id=comp.id, duration_hours=8, validity_months=24),
        ]
        db.session.add_all(cursos)

    db.session.commit()
    print("✅ Admin criado (se não existia). Login: CPF 00000000000 / Senha admin")