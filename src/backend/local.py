"""Per-user paths, independent named vaults and atomic local configuration."""

import json
import os
import re
import tempfile
from pathlib import Path

from platformdirs import user_data_dir


def home():
    path = Path(os.environ.get("JANUS_HOME", user_data_dir("Janus", appauthor=False))).expanduser()
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path


def vault_path(name="default", create=False):
    if not isinstance(name, str) or re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name) is None:
        raise ValueError("Use 1 a 64 letras, números, hífens ou sublinhados no nome do cofre")
    folder = home() / "vaults"
    folder.mkdir(exist_ok=True, mode=0o700)
    path = folder / f"{name}.db"
    if create:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
    return path


def list_vaults():
    folder = home() / "vaults"
    return sorted(path.stem for path in folder.glob("*.db")) if folder.exists() else []


def settings():
    defaults = {"vault_timeout": 300, "backup_interval": 3600, "backup_retention": 10, "port": 5000}
    path = home() / "config.json"
    if path.exists():
        defaults.update(json.loads(path.read_text()))
    return defaults


def save_settings(data):
    allowed = {
        "vault_timeout": (30, 3600),
        "backup_interval": (0, 86400),
        "backup_retention": (1, 1000),
        "port": (1024, 65535),
    }
    if not isinstance(data, dict) or set(data) - set(allowed):
        raise ValueError("Configurações desconhecidas")
    result = settings()
    for key, value in data.items():
        lower, upper = allowed[key]
        if type(value) is not int or not lower <= value <= upper:
            raise ValueError(f"Valor inválido para {key}")
        result[key] = value
    descriptor, temporary = tempfile.mkstemp(dir=home(), prefix=".settings-")
    try:
        with os.fdopen(descriptor, "w") as output:
            json.dump(result, output)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, home() / "config.json")
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return result


def install_routes(app, login_required, operation):
    from flask import jsonify, request
    from . import vault

    @app.route("/api/local/settings", methods=["GET", "PUT"])
    @login_required
    @operation
    def local_settings(conn, key):
        if request.method == "GET":
            return jsonify(settings())
        try:
            result = save_settings(request.get_json())
        except ValueError as exc:
            raise vault.VaultError(str(exc)) from exc
        vault.TIMEOUT = result["vault_timeout"]
        os.environ["JANUS_BACKUP_INTERVAL"] = str(result["backup_interval"])
        os.environ["JANUS_BACKUP_RETENTION"] = str(result["backup_retention"])
        return jsonify(result)

    @app.route("/api/local/vaults", methods=["GET", "POST"])
    @login_required
    @operation
    def local_vaults(conn, key):
        if request.method == "POST":
            try:
                vault_path((request.get_json() or {}).get("name"), create=True)
            except (ValueError, FileExistsError) as exc:
                raise vault.VaultError("Nome inválido ou cofre já existente.") from exc
        return jsonify({"vaults": list_vaults(), "current": os.environ.get("JANUS_VAULT", "default")})

    @app.post("/api/local/shutdown")
    @login_required
    @operation
    def local_shutdown(conn, key):
        callback = app.config.get("SHUTDOWN_CALLBACK")
        if callback is None:
            raise vault.VaultError("Inicie pelo inicializador Janus para encerrar pela interface.", 409)
        for token in list(vault._sessions):
            vault.lock(token)
        callback()
        return jsonify({"message": "Janus encerrado."})
