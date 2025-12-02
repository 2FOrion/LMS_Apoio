from app import app, db
from sqlalchemy import inspect, text

def migrate_quiz_attempt():
    with app.app_context():
        insp = inspect(db.engine)

        # Confere se a tabela existe
        tables = insp.get_table_names()
        if "quiz_attempt" not in tables:
            print("❌ Tabela 'quiz_attempt' não existe nesse banco.")
            return

        cols = {c["name"] for c in insp.get_columns("quiz_attempt")}
        print("Colunas atuais em quiz_attempt:", cols)

        def add_col(name, sqltype):
            if name in cols:
                print(f"✔ Coluna {name} já existe, pulando.")
                return
            sql = f"ALTER TABLE quiz_attempt ADD COLUMN {name} {sqltype}"
            print(f"➕ Adicionando coluna {name}: {sql}")
            db.session.execute(text(sql))

        # Mesmas colunas do seu models.QuizAttempt
        add_col("start_time", "TIMESTAMP")
        add_col("end_time", "TIMESTAMP")
        add_col("ip_address", "VARCHAR(64)")
        add_col("user_agent", "VARCHAR(256)")
        add_col("attempt_number", "INTEGER")
        add_col("time_limit_seconds", "INTEGER")
        add_col("blocked", "BOOLEAN")
        add_col("fraud_reason", "VARCHAR(255)")
        add_col("locked_until", "TIMESTAMP")

        # Opcional: preencher start_time para registros antigos
        print("⏱ Ajustando start_time para tentativas antigas (se houver)...")
        db.session.execute(text(
            "UPDATE quiz_attempt "
            "SET start_time = submitted_at "
            "WHERE start_time IS NULL AND submitted_at IS NOT NULL"
        ))

        db.session.commit()

        # Mostra colunas após migração
        cols_after = {c["name"] for c in insp.get_columns("quiz_attempt")}
        print("✅ Migração concluída. Colunas agora:", cols_after)

if __name__ == "__main__":
    migrate_quiz_attempt()
