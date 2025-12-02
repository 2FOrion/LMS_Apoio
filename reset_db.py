import os
from passlib.hash import pbkdf2_sha256
from app import app, db
from models import User, Company, Course, Enrollment, Certificate

DB_FILE = "database.db"

def purge_data():
    deleted = {}
    with app.app_context():
        deleted["Certificate"] = Certificate.query.delete()
        deleted["Enrollment"]  = Enrollment.query.delete()
        deleted["Course"]      = Course.query.delete()
        deleted["User"]        = User.query.delete()
        deleted["Company"]     = Company.query.delete()
        db.session.commit()
    return deleted

def drop_and_recreate():
    with app.app_context():
        db.drop_all()
        db.create_all()

def seed_defaults():
    with app.app_context():
        comp = Company.query.first()
        if not comp:
            comp = Company(name="Apoio Engenharia", city_state="Serra/ES")
            db.session.add(comp)
            db.session.commit()

        if not User.query.filter_by(cpf="00000000000").first():
            admin = User(
                name="Administrador",
                cpf="00000000000",
                password_hash=pbkdf2_sha256.hash("admin"),
                role="admin",
                company_id=comp.id,
            )
            db.session.add(admin)

        if not Course.query.first():
            cursos = [
                Course(name="NR-12 - Segurança em Máquinas e Equipamentos", company_id=comp.id, duration_hours=4,  validity_months=24),
                Course(name="NR-18 - Montador de Andaimes",                  company_id=comp.id, duration_hours=4,  validity_months=24),
                Course(name="NR-33 - Espaços Confinados",                    company_id=comp.id, duration_hours=16, validity_months=12),
                Course(name="NR-35 - Trabalho em Altura",                    company_id=comp.id, duration_hours=8,  validity_months=24),
            ]
            db.session.add_all(cursos)

        db.session.commit()
        print("✅ Seed aplicado: empresa, admin e cursos padrão criados (se não existiam).")

def remove_file():
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
        print(f"🗑️  Arquivo removido: {DB_FILE}")
    else:
        print(f"ℹ️  Arquivo {DB_FILE} não encontrado. Nada a fazer.")

def main():
    import argparse
    ap = argparse.ArgumentParser(description="Reset do banco de dados (purge/drop/seed).")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--purge", action="store_true", help="Apaga todos os registros (mantém as tabelas).")
    g.add_argument("--drop", action="store_true", help="Dropa e recria as tabelas (vazio).")
    g.add_argument("--remove-file", action="store_true", help="Apaga o arquivo database.db (SQLite).")
    ap.add_argument("--seed", action="store_true", help="Após limpar, repovoar com empresa/admin/cursos.")
    args = ap.parse_args()

    if args.remove_file:
        remove_file()
        if args.seed:
            print("⚠️  --seed é ignorado com --remove-file. Rode o app e use 'python -m flask --app app.py initdb' ou execute novamente com --drop/--purge --seed.")
        return

    if args.purge:
        deleted = purge_data()
        print("🧹 Purge concluído:", deleted)
    elif args.drop:
        drop_and_recreate()
        print("🧨 Drop & recreate concluído.")

    if args.seed:
        seed_defaults()

if __name__ == "__main__":
    main()