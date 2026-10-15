"""Packaged local launcher: named vaults, single instance and controlled shutdown."""

import argparse
import json
import os
import threading
import webbrowser

from . import local


def main(argv=None):
    parser = argparse.ArgumentParser(description="Janus — cofre local")
    parser.add_argument("--vault", default="default", help="Nome do cofre local")
    parser.add_argument("--port", type=int)
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--list-vaults", action="store_true")
    parser.add_argument("--create-vault", metavar="NAME")
    parser.add_argument("--version", action="version", version="Janus 0.3.0")
    args = parser.parse_args(argv)
    if args.list_vaults:
        print("\n".join(local.list_vaults()))
        return
    if args.create_vault:
        print(local.vault_path(args.create_vault, create=True))
        return
    local.vault_path(args.vault)
    config = local.settings()
    os.environ["JANUS_VAULT"] = args.vault
    if not any(os.environ.get(name) for name in ("DATABASE", "DATABASE_URL", "DB_PATH")):
        # Preserve an existing source-tree DB; never silently move/delete it.
        from pathlib import Path

        legacy = Path(__file__).resolve().parents[2] / "database.db"
        chosen = legacy if args.vault == "default" and legacy.exists() else local.vault_path(args.vault)
        os.environ["DATABASE"] = str(chosen)
    os.environ.setdefault("JANUS_BACKUP_DIR", str(local.home() / "backups" / args.vault))
    os.environ.setdefault("JANUS_BACKUP_INTERVAL", str(config["backup_interval"]))
    os.environ.setdefault("JANUS_BACKUP_RETENTION", str(config["backup_retention"]))
    os.environ.setdefault("VAULT_TIMEOUT", str(config["vault_timeout"]))
    host = os.environ.get("HOST", "127.0.0.1")
    if host not in {"127.0.0.1", "localhost"}:
        parser.error("Janus only binds to loopback")
    port = args.port or int(os.environ.get("PORT", config["port"]))
    if not 1024 <= port <= 65535:
        parser.error("Port must be between 1024 and 65535")
    # OS file lock prevents two processes opening the same named vault on
    # different ports. The file is not removed while another process may hold it.
    lock_path = local.home() / f"{args.vault}.lock"
    lockfile = open(lock_path, "a+b")
    try:
        if os.name == "nt":
            import msvcrt

            lockfile.seek(0)
            lockfile.write(b"0")
            lockfile.flush()
            lockfile.seek(0)
            msvcrt.locking(lockfile.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(lockfile.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        lockfile.close()
        parser.error("Este cofre já está aberto em outro processo Janus")
    from waitress import create_server
    from .database import init_db
    from .app import app
    from . import vault

    init_db()
    try:
        server = create_server(app, host="127.0.0.1", port=port, threads=4)
    except OSError:
        lockfile.close()
        parser.error("Porta em uso. Escolha --port; o Janus não abrirá outro processo por engano")

    def stop_server():
        server.task_dispatcher.shutdown(cancel_pending=True, timeout=2)
        for channel in list(server._map.values()):
            channel.close()
        server.close()

    app.config["SHUTDOWN_CALLBACK"] = lambda: threading.Timer(0.3, stop_server).start()
    instance = local.home() / f"{args.vault}.instance.json"
    instance.write_text(json.dumps({"pid": os.getpid(), "port": port, "vault": args.vault}))
    if os.name != "nt":
        instance.chmod(0o600)
    print(f"Janus 0.3.0 — {args.vault} — http://127.0.0.1:{port}", flush=True)
    if not args.no_browser:
        webbrowser.open(f"http://127.0.0.1:{port}/login")
    try:
        server.run()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
        with vault.mutex:
            for token in list(vault._sessions):
                vault.lock(token)
        instance.unlink(missing_ok=True)
        lockfile.close()


if __name__ == "__main__":
    main()
