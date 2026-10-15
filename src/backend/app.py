from flask import Flask, request, jsonify, session, redirect, url_for, g
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
from . import database as db
from . import vault
from sqlalchemy import select, func
from urllib.parse import urlsplit
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
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,
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
def local_request_boundary():
    # Host validation blocks DNS rebinding. The origin check also protects
    # login/register, whose unauthenticated requests cannot use session CSRF.
    if urlsplit(request.host_url).hostname not in {"127.0.0.1", "localhost"}:
        return jsonify({"error": "Janus aceita apenas acesso local."}), 403
    if request.path.startswith("/api/") and request.is_json:
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"error": "Envie um objeto JSON válido."}), 400
        for field in (
            "username",
            "email",
            "password",
            "password_confirm",
            "master_password",
            "current_password",
            "new_password",
            "site_name",
            "login",
            "title",
            "content",
            "note_password",
            "new_note_password",
        ):
            if field in data and not isinstance(data[field], str):
                return jsonify({"error": f"O campo {field} deve ser texto."}), 400
    origin = request.headers.get("Origin")
    if origin and request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        parsed = urlsplit(origin)
        if parsed.scheme not in {"http", "https"} or parsed.netloc != request.host:
            return jsonify({"error": "Origem não autorizada."}), 403


@app.after_request
def private_responses(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.errorhandler(vault.VaultError)
def vault_error(error):
    return jsonify({"error": str(error)}), error.status


@app.teardown_request
def close_request_connections(error):
    for connection in g.pop("db_connections", []):
        connection.close()


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

        # A login never unlocks the vault or preserves an older unlock.
        vault.lock(session.get("vault_token"))
        session.clear()
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
    vault.lock(session.get("vault_token"))
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


# ==================== COFRE LOCAL ====================


@app.get("/api/vault/status")
@login_required
def vault_status():
    with vault.mutex, db.engine.connect() as conn:
        configured = vault._metadata(conn, session["user_id"]) is not None
        try:
            vault.key_for(conn, session["user_id"], session.get("vault_token"), touch=False)
            unlocked = True
        except vault.VaultError:
            unlocked = False
    return jsonify({"configured": configured, "unlocked": unlocked, "timeout": vault.TIMEOUT})


@app.post("/api/vault/unlock")
@limiter.limit("5 per minute")
@login_required
def unlock_vault():
    data = request.get_json(silent=True) or {}
    legacy = data.get("legacy_passwords")
    if legacy is not None and (
        not isinstance(legacy, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in legacy.items())
    ):
        raise vault.VaultError("Mapa de recuperação inválido.")
    token = vault.unlock(session["user_id"], data.get("master_password"), legacy)
    vault.lock(session.get("vault_token"))
    session["vault_token"] = token
    return jsonify({"message": "Cofre desbloqueado.", "timeout": vault.TIMEOUT})


@app.post("/api/vault/lock")
@login_required
def lock_vault():
    vault.lock(session.pop("vault_token", None))
    return jsonify({"message": "Cofre bloqueado."})


@app.post("/api/vault/change-password")
@limiter.limit("5 per minute")
@login_required
def change_vault_password():
    data = request.get_json(silent=True) or {}
    current = data.get("current_password")
    if not isinstance(current, str) or not current:
        raise vault.VaultError("Informe a senha mestra atual.")
    vault.change_password(session["user_id"], session.get("vault_token"), current, data.get("new_password"))
    session.pop("vault_token", None)
    return jsonify({"message": "Senha mestra alterada. Desbloqueie novamente."})


@app.post("/api/vault/export")
@limiter.limit("10 per minute")
@login_required
def export_vault():
    response = jsonify(vault.export_backup(session["user_id"], session.get("vault_token")))
    response.headers["Content-Disposition"] = 'attachment; filename="janus-backup.janus"'
    return response


@app.post("/api/vault/restore")
@limiter.limit("5 per minute")
@login_required
def restore_vault():
    data = request.get_json(silent=True) or {}
    password = data.get("master_password")
    if not isinstance(password, str) or not password:
        raise vault.VaultError("Informe a senha mestra do backup.")
    restored = vault.restore_backup(session["user_id"], data.get("backup"), password)
    session.pop("vault_token", None)
    return jsonify({"message": "Backup restaurado. Desbloqueie com a senha mestra do backup.", **restored})


def credential_operation(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        with vault.mutex, vault.transaction(session["user_id"]) as conn:
            key = vault.key_for(conn, session["user_id"], session.get("vault_token"))
            # Passwords belong only on unlock/change endpoints. Reject old clients
            # instead of silently ignoring a potentially mistyped master password.
            data = request.get_json(silent=True) or {}
            if "master_password" in data:
                raise vault.VaultError("Desbloqueie o cofre em /api/vault/unlock antes de operar.")
            if request.method in {"PUT", "DELETE"} or (
                request.method == "POST" and not request.path.endswith("/reveal")
            ):
                vault.automatic_backup(conn, session["user_id"], key)
            return function(conn, key, *args, **kwargs)

    return wrapped


def owned_credential(conn, credential_id):
    row = (
        conn.execute(
            select(db.credentials).where(
                db.credentials.c.id == credential_id, db.credentials.c.user_id == session["user_id"]
            )
        )
        .mappings()
        .first()
    )
    if row is None:
        raise vault.VaultError("Credencial não encontrada.", 404)
    return row


@app.get("/api/credentials")
@login_required
@credential_operation
def get_credentials(conn, key):
    rows = vault._credentials(conn, session["user_id"])
    return jsonify(
        {"credentials": [{k: v for k, v in row.items() if k not in {"password_encrypted", "user_id"}} for row in rows]}
    )


@app.post("/api/credentials")
@limiter.limit("30 per minute")
@login_required
@credential_operation
def add_credential(conn, key):
    data = request.get_json(silent=True) or {}
    site = data.get("site_name", "")
    password = data.get("password")
    if not isinstance(site, str) or not site.strip() or not isinstance(password, str) or not password:
        raise vault.VaultError("Nome do site e senha são obrigatórios.")
    result = conn.execute(
        db.credentials.insert().values(
            user_id=session["user_id"],
            site_name=site.strip(),
            login=data.get("login", ""),
            email=data.get("email", ""),
            password_encrypted=vault.seal(password, key),
        )
    )
    return jsonify({"message": "Credencial salva.", "id": result.inserted_primary_key[0]}), 201


@app.get("/api/credentials/<int:credential_id>")
@login_required
@credential_operation
def get_credential(conn, key, credential_id):
    row = owned_credential(conn, credential_id)
    return jsonify({k: v for k, v in row.items() if k not in {"password_encrypted", "user_id"}})


@app.post("/api/credentials/<int:credential_id>/reveal")
@limiter.limit("30 per minute")
@login_required
@credential_operation
def reveal_credential(conn, key, credential_id):
    row = owned_credential(conn, credential_id)
    return jsonify(
        {
            **{k: v for k, v in row.items() if k not in {"password_encrypted", "user_id"}},
            "password": vault.unseal(row["password_encrypted"], key),
        }
    )


@app.put("/api/credentials/<int:credential_id>")
@login_required
@credential_operation
def update_credential(conn, key, credential_id):
    row = owned_credential(conn, credential_id)
    vault.unseal(row["password_encrypted"], key)  # Never overwrite undetected corruption.
    data = request.get_json(silent=True) or {}
    values = {field: data.get(field, row[field]) for field in ("site_name", "login", "email")}
    if not isinstance(values["site_name"], str) or not values["site_name"].strip():
        raise vault.VaultError("Nome do site é obrigatório.")
    if "password" in data:
        if not isinstance(data["password"], str) or not data["password"]:
            raise vault.VaultError("Senha não pode ser vazia.")
        values["password_encrypted"] = vault.seal(data["password"], key)
    values["updated_at"] = func.current_timestamp()
    conn.execute(
        db.credentials.update()
        .where(db.credentials.c.id == credential_id, db.credentials.c.user_id == session["user_id"])
        .values(**values)
    )
    return jsonify({"message": "Credencial atualizada."})


@app.delete("/api/credentials/<int:credential_id>")
@login_required
@credential_operation
def delete_credential(conn, key, credential_id):
    owned_credential(conn, credential_id)
    conn.execute(
        db.credentials.delete().where(
            db.credentials.c.id == credential_id, db.credentials.c.user_id == session["user_id"]
        )
    )
    return jsonify({"message": "Credencial deletada."})


def note_vault_required(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        with vault.mutex:
            with db.engine.connect() as conn:
                key = vault.key_for(conn, session["user_id"], session.get("vault_token"))
                if request.method in {"POST", "PUT", "DELETE"} and not request.path.endswith("/reveal"):
                    vault.automatic_backup(conn, session["user_id"], key)
            return function(*args, **kwargs)

    return wrapped


# ==================== ROTAS DE NOTAS SEGURAS ====================


@app.route("/api/notes", methods=["GET"])
@login_required
@note_vault_required
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
@note_vault_required
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


@app.route("/api/notes/<int:note_id>/reveal", methods=["POST"])
@limiter.limit("30 per minute")
@login_required
@note_vault_required
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
@note_vault_required
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

        current_content = decrypt_password(note["content_encrypted"], note_password)
        if current_content is None:
            conn.close()
            return jsonify({"error": "Nota corrompida ou formato não suportado; nenhum dado foi alterado"}), 409

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
@note_vault_required
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
@note_vault_required
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
    host = os.environ.get("HOST", "127.0.0.1")
    if host not in {"127.0.0.1", "localhost"}:
        raise RuntimeError("Janus must bind to the loopback interface")
    app.run(debug=debug, host=host, port=int(os.environ.get("PORT", 5000)))
