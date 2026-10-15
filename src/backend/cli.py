"""Offline CLI. Passwords use getpass, never command-line arguments or env vars."""

import argparse
import getpass
import json
import os
from pathlib import Path

from . import local


def main(argv=None):
    parser = argparse.ArgumentParser(description="Janus local CLI")
    parser.add_argument("--vault", default="default")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("vaults")
    create = sub.add_parser("create-vault")
    create.add_argument("name")
    opening = sub.add_parser("open")
    opening.add_argument("--port", type=int)
    sub.add_parser("list")
    get = sub.add_parser("get")
    get.add_argument("id", type=int)
    get.add_argument("--show-password", action="store_true", help="Explicitly print secret to stdout")
    add = sub.add_parser("add")
    add.add_argument("name")
    add.add_argument("--login", default="")
    add.add_argument("--url", action="append", default=[])
    export = sub.add_parser("export")
    export.add_argument("file", type=Path)
    restore = sub.add_parser("restore")
    restore.add_argument("file", type=Path)
    importing = sub.add_parser("import")
    importing.add_argument("format", choices=["csv", "bitwarden", "keepass-kdbx", "keepass-xml"])
    importing.add_argument("file", type=Path)
    sub.add_parser("passphrase")
    args = parser.parse_args(argv)
    if args.command == "vaults":
        print("\n".join(local.list_vaults()))
        return
    if args.command == "create-vault":
        print(local.vault_path(args.name, create=True))
        return
    if args.command == "open":
        from .run import main as launch

        launch(["--vault", args.vault] + (["--port", str(args.port)] if args.port else []))
        return
    os.environ["DATABASE"] = str(local.vault_path(args.vault))
    from . import database as db, entries, importers, vault
    from .auth import hash_password, verify_password

    db.configure_database()
    db.init_db()
    if args.command == "passphrase":
        print(entries.passphrase())
        return
    username = input("Local username: ").strip()
    login_password = getpass.getpass("Login password: ")
    from sqlalchemy import select

    with db.engine.begin() as conn:
        user = conn.execute(select(db.users).where(db.users.c.username == username)).mappings().first()
        if user is None and args.command == "restore":
            confirmation = getpass.getpass("Confirm new login password: ")
            if len(login_password) < 6 or login_password != confirmation:
                parser.error("Passwords do not match or are too short")
            user_id = conn.execute(
                db.users.insert().values(
                    username=username, email=username + "@local.invalid", password_hash=hash_password(login_password)
                )
            ).inserted_primary_key[0]
        elif user and verify_password(login_password, user["password_hash"]):
            user_id = user["id"]
        else:
            parser.error("Invalid login")
    password = getpass.getpass("Master password: ")
    if args.command == "restore":
        print(json.dumps(vault.restore_backup(user_id, json.loads(args.file.read_text()), password)))
        return
    token = vault.unlock(user_id, password)
    try:
        if args.command == "export":
            content = json.dumps(vault.export_backup(user_id, token), ensure_ascii=False).encode()
            descriptor = os.open(args.file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                output.write(content)
            return
        with vault.mutex, vault.transaction(user_id) as conn:
            key = vault.key_for(conn, user_id, token)
            if args.command == "list":
                for item in entries.list_credentials(conn, user_id, key):
                    print(f"{item['id']}\t{item['site_name']}\t{item['login']}")
            elif args.command == "get":
                item = entries.reveal(conn, user_id, args.id, key)
                if not args.show_password:
                    item.pop("password", None)
                    item.pop("totp", None)
                    item.pop("custom_fields", None)
                    item.pop("notes", None)
                print(json.dumps(item, ensure_ascii=False, indent=2))
            elif args.command == "add":
                vault.automatic_backup(conn, user_id, key)
                secret = getpass.getpass("Credential password: ")
                print(
                    entries.write(
                        conn,
                        user_id,
                        key,
                        {"site_name": args.name, "login": args.login, "urls": args.url, "password": secret},
                    )
                )
            elif args.command == "import":
                import base64

                source = {
                    "format": args.format,
                    "content": (
                        base64.b64encode(args.file.read_bytes()).decode()
                        if args.format == "keepass-kdbx"
                        else args.file.read_text(encoding="utf-8-sig")
                    ),
                }
                if args.format == "keepass-kdbx":
                    source["password"] = getpass.getpass("KeePass password: ")
                records = importers.parse(source)
                print(json.dumps(importers.preview(records), ensure_ascii=False, indent=2))
                if input("Import these entries? [y/N] ").lower() != "y":
                    return
                vault.automatic_backup(conn, user_id, key)
                print(json.dumps(importers.commit(conn, user_id, key, records)))
    finally:
        vault.lock(token)


if __name__ == "__main__":
    main()
