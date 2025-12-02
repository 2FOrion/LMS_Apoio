LMS Apoio Engenharia — Kit de Banco de Dados

Arquivos:
- database.db (SQLite) com tabelas criadas + cursos base
- seed_admin.py → cria ADMIN (CPF 00000000000 / Senha admin) e cursos, se não existirem
- reset_db.py  → limpar/dropar/seedar o banco
- templates_usuarios.csv → modelo CSV para importar usuários

Como usar (Windows/PowerShell):
1) Copie 'database.db' para a pasta do seu projeto (onde está app.py).
2) (Opcional) Rode:  python seed_admin.py
3) Inicie o app:     python app.py
4) Login admin: CPF 00000000000 / Senha admin