from flask import Flask, request, jsonify, session, redirect, url_for
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
from datetime import datetime, timedelta, timezone
import hmac
import os
import secrets
from pathlib import Path

from .database import get_db_connection, init_db
from .auth import (
    hash_password,
    verify_password,
    encrypt_password,
    decrypt_password,
    generate_secure_password,
    generate_access_token,
)

SRC_ROOT = Path(__file__).resolve().parents[1]
FRONTEND_DIR = SRC_ROOT / "frontend"

app = Flask(
    __name__,
    template_folder=str(FRONTEND_DIR),
    static_folder=str(FRONTEND_DIR),
    static_url_path="",
)
is_production = os.environ.get("FLASK_ENV", "").lower() == "production"
secret_key = os.environ.get("SECRET_KEY")
if is_production and not secret_key:
    raise RuntimeError("SECRET_KEY must be configured in production")

app.secret_key = secret_key or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE=os.environ.get("SESSION_COOKIE_SAMESITE", "Lax"),
    SESSION_COOKIE_SECURE=is_production,
    PERMANENT_SESSION_LIFETIME=timedelta(seconds=int(os.environ.get("SESSION_TIMEOUT", 7 * 24 * 60 * 60))),
)

allowed_origins = [origin.strip() for origin in os.environ.get("CORS_ORIGINS", "").split(",") if origin.strip()]
if allowed_origins:
    CORS(app, origins=allowed_origins, supports_credentials=True)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),
)

CSRF_HEADER = "X-CSRF-Token"
CSRF_EXEMPT_PATHS = {
    "/api/csrf-token",
    "/api/login",
    "/api/register",
    "/api/generate-password",
}


@app.before_request
def validate_csrf():
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return None
    public_note_access = request.path.startswith("/api/notes/access/")
    if not request.path.startswith("/api/") or request.path in CSRF_EXEMPT_PATHS or public_note_access:
        return None

    expected = session.get("_csrf_token")
    supplied = request.headers.get(CSRF_HEADER)
    if not expected or not supplied or not hmac.compare_digest(expected, supplied):
        return jsonify({"error": "CSRF validation failed"}), 403
    return None


@app.get("/api/csrf-token")
def csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return jsonify({"csrf_token": token})


# Middleware para verificar autenticação
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Não autenticado"}), 401
        return f(*args, **kwargs)

    return decorated_function


@app.get("/api/user-info")
@login_required
def user_info():
    """Return the non-sensitive identity details needed by the dashboard."""
    return jsonify({"username": session["username"]}), 200


# ==================== ROTAS DE AUTENTICAÇÃO ====================


@app.route("/")
def index():
    """Página inicial"""
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login_page"))


@app.route("/login", methods=["GET"])
def login_page():
    """Página de login"""
    return app.send_static_file("login.html")


@app.route("/register", methods=["GET"])
def register_page():
    """Página de registro"""
    return app.send_static_file("register.html")


@app.route("/dashboard", methods=["GET"])
@login_required
def dashboard():
    """Página do dashboard"""
    return app.send_static_file("dashboard.html")


@app.route("/api/register", methods=["POST"])
@limiter.limit("10 per minute")
def register():
    """Registra um novo usuário"""
    try:
        data = request.get_json(silent=True) or {}
        username = data.get("username", "").strip()
        email = data.get("email", "").strip()
        password = data.get("password", "")
        password_confirm = data.get("password_confirm", "")

        # Validações
        if not username or len(username) < 3:
            return jsonify({"error": "Usuário deve ter pelo menos 3 caracteres"}), 400

        if not email or "@" not in email:
            return jsonify({"error": "Email inválido"}), 400

        if len(password) < 6:
            return jsonify({"error": "Senha deve ter pelo menos 6 caracteres"}), 400

        if password != password_confirm:
            return jsonify({"error": "Senhas não conferem"}), 400

        # Verificar se usuário já existe
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email))

        if cursor.fetchone():
            conn.close()
            return jsonify({"error": "Usuário ou email já existe"}), 400

        # Criar novo usuário
        password_hash = hash_password(password)
        cursor.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)", (username, email, password_hash)
        )
        conn.commit()
        conn.close()

        return jsonify({"message": "Usuário registrado com sucesso!"}), 201

    except Exception:
        app.logger.exception("Request failed")
        return jsonify({"error": "Erro interno do servidor"}), 500


@app.route("/api/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    """Faz login do usuário"""
    try:
        data = request.get_json(silent=True) or {}
        username = data.get("username", "")
        password = data.get("password", "")

        if not username or not password:
            return jsonify({"error": "Usuário e senha são obrigatórios"}), 400

        # Verificar credenciais
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password_hash FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if not user or not verify_password(password, user["password_hash"]):
            return jsonify({"error": "Usuário ou senha inválidos"}), 401

        # Criar sessão
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session.permanent = True

        return jsonify({"message": "Login realizado com sucesso!"}), 200

    except Exception:
        app.logger.exception("Request failed")
        return jsonify({"error": "Erro interno do servidor"}), 500


@app.route("/api/logout", methods=["POST"])
@limiter.limit("20 per minute")
def logout():
    """Faz logout do usuário"""
    session.clear()
    return jsonify({"message": "Logout realizado com sucesso!"}), 200


# ==================== ROTAS DO GERADOR DE SENHAS ====================


@app.route("/api/generate-password", methods=["POST"])
@limiter.limit("60 per minute")
def generate_password():
    """Gera uma senha segura"""
    try:
        data = request.get_json(silent=True) or {}
        length = int(data.get("length", 16))
        use_uppercase = data.get("use_uppercase", True)
        use_lowercase = data.get("use_lowercase", True)
        use_digits = data.get("use_digits", True)
        use_special = data.get("use_special", True)

        # Validar comprimento
        if length < 2 or length > 128:
            return jsonify({"error": "Comprimento deve estar entre 2 e 128"}), 400

        password = generate_secure_password(
            length=length,
            use_uppercase=use_uppercase,
            use_lowercase=use_lowercase,
            use_digits=use_digits,
            use_special=use_special,
        )

        return jsonify({"password": password}), 200

    except Exception:
        app.logger.exception("Request failed")
        return jsonify({"error": "Erro interno do servidor"}), 500


# ==================== ROTAS DE CREDENCIAIS ====================


@app.route("/api/credentials", methods=["GET"])
@login_required
def get_credentials():
    """Obtém todas as credenciais do usuário"""
    try:
        user_id = session["user_id"]
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, site_name, login, email, created_at, updated_at FROM credentials WHERE user_id = ? ORDER BY created_at DESC",
            (user_id,),
        )
        credentials = [dict(c) for c in cursor.fetchall()]
        conn.close()

        return jsonify({"credentials": credentials}), 200

    except Exception:
        app.logger.exception("Request failed")
        return jsonify({"error": "Erro interno do servidor"}), 500


@app.route("/api/credentials", methods=["POST"])
@limiter.limit("30 per minute")
@login_required
def add_credential():
    """Adiciona uma nova credencial"""
    try:
        user_id = session["user_id"]
        data = request.get_json(silent=True) or {}
        site_name = data.get("site_name", "").strip()
        login = data.get("login", "").strip()
        email = data.get("email", "").strip()
        password = data.get("password", "")
        master_password = data.get("master_password", "")

        if not site_name:
            return jsonify({"error": "Nome do site é obrigatório"}), 400

        if not password:
            return jsonify({"error": "Senha é obrigatória"}), 400

        if not master_password:
            return jsonify({"error": "Senha mestre é obrigatória"}), 400

        # Encriptar a senha com a senha mestre
        encrypted_password = encrypt_password(password, master_password)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO credentials (user_id, site_name, login, email, password_encrypted) VALUES (?, ?, ?, ?, ?)",
            (user_id, site_name, login, email, encrypted_password),
        )
        conn.commit()
        credential_id = cursor.lastrowid
        conn.close()

        return jsonify({"message": "Credencial salva com sucesso!", "id": credential_id}), 201

    except Exception:
        app.logger.exception("Request failed")
        return jsonify({"error": "Erro interno do servidor"}), 500


@app.route("/api/credentials/<int:credential_id>", methods=["GET"])
@login_required
def get_credential(credential_id):
    """Obtém uma credencial específica com a senha descriptografada"""
    try:
        user_id = session["user_id"]
        data = request.get_json(silent=True) or {}
        master_password = data.get("master_password", "")

        if not master_password:
            return jsonify({"error": "Senha mestre é obrigatória"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM credentials WHERE id = ? AND user_id = ?", (credential_id, user_id))
        credential = cursor.fetchone()
        conn.close()

        if not credential:
            return jsonify({"error": "Credencial não encontrada"}), 404

        # Descriptografar senha
        password = decrypt_password(credential["password_encrypted"], master_password)

        if password is None:
            return jsonify({"error": "Senha mestre incorreta"}), 401

        return (
            jsonify(
                {
                    "id": credential["id"],
                    "site_name": credential["site_name"],
                    "login": credential["login"],
                    "email": credential["email"],
                    "password": password,
                    "created_at": credential["created_at"],
                    "updated_at": credential["updated_at"],
                }
            ),
            200,
        )

    except Exception:
        app.logger.exception("Request failed")
        return jsonify({"error": "Erro interno do servidor"}), 500


@app.route("/api/credentials/<int:credential_id>", methods=["PUT"])
@login_required
def update_credential(credential_id):
    """Atualiza uma credencial"""
    try:
        user_id = session["user_id"]
        data = request.get_json(silent=True) or {}
        site_name = data.get("site_name", "").strip()
        login = data.get("login", "").strip()
        email = data.get("email", "").strip()
        password = data.get("password")
        master_password = data.get("master_password", "")

        if not master_password:
            return jsonify({"error": "Senha mestre é obrigatória"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM credentials WHERE id = ? AND user_id = ?", (credential_id, user_id))
        credential = cursor.fetchone()

        if not credential:
            conn.close()
            return jsonify({"error": "Credencial não encontrada"}), 404

        # Encriptar nova senha se fornecida
        if password:
            encrypted_password = encrypt_password(password, master_password)
        else:
            encrypted_password = credential["password_encrypted"]

        cursor.execute(
            "UPDATE credentials SET site_name = ?, login = ?, email = ?, password_encrypted = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?",
            (site_name, login, email, encrypted_password, credential_id, user_id),
        )
        conn.commit()
        conn.close()

        return jsonify({"message": "Credencial atualizada com sucesso!"}), 200

    except Exception:
        app.logger.exception("Request failed")
        return jsonify({"error": "Erro interno do servidor"}), 500


@app.route("/api/credentials/<int:credential_id>", methods=["DELETE"])
@login_required
def delete_credential(credential_id):
    """Deleta uma credencial"""
    try:
        user_id = session["user_id"]

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM credentials WHERE id = ? AND user_id = ?", (credential_id, user_id))
        conn.commit()
        conn.close()

        return jsonify({"message": "Credencial deletada com sucesso!"}), 200

    except Exception:
        app.logger.exception("Request failed")
        return jsonify({"error": "Erro interno do servidor"}), 500


# ==================== ROTAS DE NOTAS SEGURAS ====================


@app.route("/api/notes", methods=["GET"])
@login_required
def get_notes():
    """Obtém todas as notas do usuário"""
    try:
        user_id = session["user_id"]
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, title, access_token, access_token_expires_at, access_token_revoked_at, created_at, updated_at FROM secure_notes WHERE user_id = ? ORDER BY created_at DESC",
            (user_id,),
        )
        notes = [dict(n) for n in cursor.fetchall()]
        conn.close()

        return jsonify({"notes": notes}), 200

    except Exception:
        app.logger.exception("Request failed")
        return jsonify({"error": "Erro interno do servidor"}), 500


@app.route("/api/notes", methods=["POST"])
@limiter.limit("30 per minute")
@login_required
def add_note():
    """Cria uma nova nota segura"""
    try:
        user_id = session["user_id"]
        data = request.get_json(silent=True) or {}
        title = data.get("title", "").strip()
        content = data.get("content", "")
        note_password = data.get("note_password", "")

        if not title:
            return jsonify({"error": "Título é obrigatório"}), 400

        if not content:
            return jsonify({"error": "Conteúdo é obrigatório"}), 400

        if not note_password:
            return jsonify({"error": "Senha da nota é obrigatória"}), 400

        # Notes are protected by their own password so public sharing does not
        # depend on the owner's session or master password.
        encrypted_content = encrypt_password(content, note_password)
        note_password_hash = hash_password(note_password)
        access_token = generate_access_token()
        access_token_expires_at = (
            datetime.now(timezone.utc).replace(tzinfo=None)
            + timedelta(days=int(os.environ.get("PUBLIC_NOTE_TTL_DAYS", 7)))
        ).isoformat(sep=" ")

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO secure_notes (user_id, title, content_encrypted, note_password_hash, access_token, access_token_expires_at) VALUES (?, ?, ?, ?, ?, ?)",
            (user_id, title, encrypted_content, note_password_hash, access_token, access_token_expires_at),
        )
        conn.commit()
        note_id = cursor.lastrowid
        conn.close()

        return (
            jsonify(
                {
                    "message": "Nota criada com sucesso!",
                    "id": note_id,
                    "access_token": access_token,
                    "access_token_expires_at": access_token_expires_at,
                }
            ),
            201,
        )

    except Exception:
        app.logger.exception("Request failed")
        return jsonify({"error": "Erro interno do servidor"}), 500


@app.route("/api/notes/<int:note_id>", methods=["GET"])
@limiter.limit("30 per minute")
@login_required
def get_note(note_id):
    """Obtém uma nota específica"""
    try:
        user_id = session["user_id"]
        data = request.get_json(silent=True) or {}
        note_password = data.get("note_password", "")

        if not note_password:
            return jsonify({"error": "Senha da nota é obrigatória"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM secure_notes WHERE id = ? AND user_id = ?", (note_id, user_id))
        note = cursor.fetchone()
        conn.close()

        if not note:
            return jsonify({"error": "Nota não encontrada"}), 404

        # Verificar senha da nota
        if not verify_password(note_password, note["note_password_hash"]):
            return jsonify({"error": "Senha da nota incorreta"}), 401

        # The note password is the encryption key for both private and public access.
        content = decrypt_password(note["content_encrypted"], note_password)
        if content is None:
            return jsonify({"error": "Nota indisponível ou criada com formato antigo"}), 410

        return (
            jsonify(
                {
                    "id": note["id"],
                    "title": note["title"],
                    "content": content,
                    "access_token": note["access_token"],
                    "created_at": note["created_at"],
                    "updated_at": note["updated_at"],
                }
            ),
            200,
        )

    except Exception:
        app.logger.exception("Request failed")
        return jsonify({"error": "Erro interno do servidor"}), 500


@app.route("/api/notes/<int:note_id>", methods=["PUT"])
@limiter.limit("30 per minute")
@login_required
def update_note(note_id):
    """Atualiza uma nota"""
    try:
        user_id = session["user_id"]
        data = request.get_json(silent=True) or {}
        title = data.get("title", "").strip()
        content = data.get("content", "")
        note_password = data.get("note_password", "")
        new_note_password = data.get("new_note_password") or note_password

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM secure_notes WHERE id = ? AND user_id = ?", (note_id, user_id))
        note = cursor.fetchone()

        if not note:
            conn.close()
            return jsonify({"error": "Nota não encontrada"}), 404

        if not note_password or not verify_password(note_password, note["note_password_hash"]):
            conn.close()
            return jsonify({"error": "Senha da nota incorreta"}), 401

        # Encriptar novo conteúdo se fornecido
        if content:
            encrypted_content = encrypt_password(content, new_note_password)
        elif new_note_password != note_password:
            current_content = decrypt_password(note["content_encrypted"], note_password)
            if current_content is None:
                conn.close()
                return jsonify({"error": "Nota criada com formato antigo; recrie-a"}), 410
            encrypted_content = encrypt_password(current_content, new_note_password)
        else:
            encrypted_content = note["content_encrypted"]

        # Atualizar senha se fornecida
        note_password_hash = hash_password(new_note_password)

        cursor.execute(
            "UPDATE secure_notes SET title = ?, content_encrypted = ?, note_password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?",
            (title, encrypted_content, note_password_hash, note_id, user_id),
        )
        conn.commit()
        conn.close()

        return jsonify({"message": "Nota atualizada com sucesso!"}), 200

    except Exception:
        app.logger.exception("Request failed")
        return jsonify({"error": "Erro interno do servidor"}), 500


@app.route("/api/notes/<int:note_id>", methods=["DELETE"])
@limiter.limit("30 per minute")
@login_required
def delete_note(note_id):
    """Deleta uma nota"""
    try:
        user_id = session["user_id"]

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM secure_notes WHERE id = ? AND user_id = ?", (note_id, user_id))
        conn.commit()
        conn.close()

        return jsonify({"message": "Nota deletada com sucesso!"}), 200

    except Exception:
        app.logger.exception("Request failed")
        return jsonify({"error": "Erro interno do servidor"}), 500


@app.route("/api/notes/<int:note_id>/revoke-access", methods=["POST"])
@limiter.limit("20 per minute")
@login_required
def revoke_note_access(note_id):
    """Revoke a public note token without deleting the note."""
    try:
        user_id = session["user_id"]
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE secure_notes SET access_token_revoked_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?",
            (note_id, user_id),
        )
        conn.commit()
        changed = cursor.rowcount
        conn.close()
        if not changed:
            return jsonify({"error": "Nota não encontrada"}), 404
        return jsonify({"message": "Acesso público revogado com sucesso"}), 200
    except Exception:
        app.logger.exception("Failed to revoke public note access")
        return jsonify({"error": "Erro interno do servidor"}), 500


# ==================== ROTAS DE ACESSO A NOTAS (VIA URL) ====================


@app.route("/note/<access_token>", methods=["GET"])
def view_note_public(access_token):
    """Acessa uma nota via URL pública"""
    return app.send_static_file("note-access.html")


@app.route("/api/notes/access/<access_token>", methods=["POST"])
@limiter.limit("20 per minute")
def access_note_with_token(access_token):
    """Obtém uma nota pelo token de acesso"""
    try:
        note_password = (request.get_json(silent=True) or {}).get("note_password", "")

        if not note_password:
            return jsonify({"error": "Senha da nota é obrigatória"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM secure_notes WHERE access_token = ? AND access_token_revoked_at IS NULL AND access_token_expires_at > CURRENT_TIMESTAMP",
            (access_token,),
        )
        note = cursor.fetchone()
        conn.close()

        if not note:
            return jsonify({"error": "Nota não encontrada"}), 404

        # Verificar senha da nota
        if not verify_password(note_password, note["note_password_hash"]):
            return jsonify({"error": "Senha da nota incorreta"}), 401

        content = decrypt_password(note["content_encrypted"], note_password)
        if content is None:
            return jsonify({"error": "Nota criada com formato antigo; recrie-a"}), 410

        return (
            jsonify({"id": note["id"], "title": note["title"], "content": content, "created_at": note["created_at"]}),
            200,
        )

    except Exception:
        app.logger.exception("Request failed")
        return jsonify({"error": "Erro interno do servidor"}), 500


# ==================== TRATAMENTO DE ERROS ====================


@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Página não encontrada"}), 404


@app.errorhandler(500)
def server_error(error):
    return jsonify({"error": "Erro interno do servidor"}), 500


if __name__ == "__main__":
    # Inicializar banco de dados
    init_db()

    # Iniciar aplicação
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug, host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", 5000)))
