from app import app, db
from sqlalchemy import inspect, text

def migrate_quiz_attempt():
    with app.app_context():
        insp = inspect(db.engine)
        cols = {c["name"] for c in insp.get_columns("quiz_attempt")}
        print("Colunas atuais em quiz_attempt:", cols)

        def add_col(name, sqltype):
            if name not in cols:
                print(f"Adicionando coluna {name}...")
                db.session.execute(text(f"ALTER TABLE quiz_attempt ADD COLUMN {name} {sqltype}"))
            else:
                print(f"Coluna {name} já existe, pulando.")

        add_col("start_time", "TIMESTAMP")
        add_col("end_time", "TIMESTAMP")
        add_col("ip_address", "VARCHAR(64)")
        add_col("user_agent", "VARCHAR(256)")
        add_col("attempt_number", "INTEGER")
        add_col("time_limit_seconds", "INTEGER")
        add_col("blocked", "BOOLEAN")
        add_col("fraud_reason", "VARCHAR(255)")
        add_col("locked_until", "TIMESTAMP")

        print("Ajustando valores antigos...")
        db.session.execute(text(
            "UPDATE quiz_attempt "
            "SET start_time = submitted_at "
            "WHERE start_time IS NULL AND submitted_at IS NOT NULL"
        ))

        db.session.commit()
        print("✅ Migração concluída com sucesso!")

if __name__ == "__main__":
    migrate_quiz_attempt()
