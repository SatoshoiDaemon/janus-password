"""Local productivity APIs; all secret operations use the same vault transaction."""

from flask import jsonify, request, session
from sqlalchemy import select

from . import database as db, entries, importers, vault


def install(app, login_required, operation):
    def route(path, methods):
        def register(function):
            app.route(path, methods=methods)(login_required(operation(function)))
            return function

        return register

    @route("/api/credentials/<int:item_id>/restore", ["POST"])
    def restore_credential(conn, key, item_id):
        entries.trash(conn, session["user_id"], key, item_id, "restore")
        return jsonify({"message": "Credencial restaurada."})

    @route("/api/credentials/<int:item_id>/purge", ["DELETE"])
    def purge_credential(conn, key, item_id):
        entries.trash(conn, session["user_id"], key, item_id, "purge")
        return jsonify({"message": "Credencial excluída permanentemente."})

    @route("/api/credentials/<int:item_id>/history", ["GET"])
    def list_history(conn, key, item_id):
        entries.owned(conn, session["user_id"], item_id, key, True)
        rows = conn.execute(
            select(db.credential_history.c.id, db.credential_history.c.created_at)
            .where(
                db.credential_history.c.user_id == session["user_id"], db.credential_history.c.credential_id == item_id
            )
            .order_by(db.credential_history.c.id.desc())
        ).mappings()
        return jsonify({"history": [dict(row) for row in rows]})

    def historical(conn, key, item_id, history_id):
        entries.owned(conn, session["user_id"], item_id, key, True)
        row = (
            conn.execute(
                select(db.credential_history).where(
                    db.credential_history.c.user_id == session["user_id"],
                    db.credential_history.c.credential_id == item_id,
                    db.credential_history.c.id == history_id,
                )
            )
            .mappings()
            .first()
        )
        if not row:
            raise vault.VaultError("Versão não encontrada.", 404)
        return entries.decode(row["payload"], key)

    @route("/api/credentials/<int:item_id>/history/<int:history_id>/reveal", ["POST"])
    def reveal_history(conn, key, item_id, history_id):
        return jsonify(historical(conn, key, item_id, history_id))

    @route("/api/credentials/<int:item_id>/history/<int:history_id>/restore", ["POST"])
    def restore_history(conn, key, item_id, history_id):
        data = historical(conn, key, item_id, history_id)
        entries.write(conn, session["user_id"], key, data, item_id)
        return jsonify({"message": "Versão restaurada. A versão anterior permanece no histórico."})

    @route("/api/credentials/<int:item_id>/totp", ["POST"])
    def credential_totp(conn, key, item_id):
        item = entries.owned(conn, session["user_id"], item_id, key)
        if not item["totp"]:
            raise vault.VaultError("Credencial sem TOTP configurado.", 404)
        return jsonify(entries.totp(item["totp"]))

    @route("/api/vault/health", ["GET"])
    def vault_health(conn, key):
        return jsonify({"items": entries.health(conn, session["user_id"], key)})

    @route("/api/vault/import/preview", ["POST"])
    def preview_import(conn, key):
        return jsonify(importers.preview(importers.parse(request.get_json())))

    @route("/api/vault/import", ["POST"])
    def commit_import(conn, key):
        data = request.get_json()
        if data.get("confirmed") is not True:
            raise vault.VaultError("Visualize e confirme a importação antes de gravar.")
        records = importers.parse(data)
        return jsonify(importers.commit(conn, session["user_id"], key, records, data.get("duplicates", "skip")))

    @route("/api/items", ["GET"])
    def list_items(conn, key):
        rows = conn.execute(select(db.vault_items).where(db.vault_items.c.user_id == session["user_id"])).mappings()
        trash = request.args.get("trash") == "1"
        return jsonify(
            {
                "items": [
                    {k: v for k, v in row.items() if k not in {"payload", "user_id"}}
                    for row in rows
                    if bool(row["deleted_at"]) == trash
                ]
            }
        )

    @route("/api/items", ["POST"])
    def create_item(conn, key):
        return jsonify({"id": entries.write_item(conn, session["user_id"], key, request.get_json())}), 201

    def item(conn, item_id):
        row = (
            conn.execute(
                select(db.vault_items).where(
                    db.vault_items.c.user_id == session["user_id"], db.vault_items.c.id == item_id
                )
            )
            .mappings()
            .first()
        )
        if not row:
            raise vault.VaultError("Item não encontrado.", 404)
        return row

    @route("/api/items/<int:item_id>/reveal", ["POST"])
    def reveal_item(conn, key, item_id):
        row = item(conn, item_id)
        if row["deleted_at"]:
            raise vault.VaultError("Item na lixeira.", 404)
        return jsonify(
            {"id": item_id, "kind": row["kind"], "name": row["name"], "fields": entries.decode(row["payload"], key)}
        )

    @route("/api/items/<int:item_id>", ["PUT"])
    def edit_item(conn, key, item_id):
        entries.write_item(conn, session["user_id"], key, request.get_json(), item_id)
        return jsonify({"message": "Item atualizado."})

    @route("/api/items/<int:item_id>", ["DELETE"])
    def trash_item(conn, key, item_id):
        item(conn, item_id)
        conn.execute(
            db.vault_items.update()
            .where(db.vault_items.c.user_id == session["user_id"], db.vault_items.c.id == item_id)
            .values(deleted_at=entries.now())
        )
        return jsonify({"message": "Item movido para a lixeira."})

    @route("/api/items/<int:item_id>/restore", ["POST"])
    def restore_item(conn, key, item_id):
        item(conn, item_id)
        conn.execute(
            db.vault_items.update()
            .where(db.vault_items.c.user_id == session["user_id"], db.vault_items.c.id == item_id)
            .values(deleted_at=None)
        )
        return jsonify({"message": "Item restaurado."})

    @route("/api/items/<int:item_id>/purge", ["DELETE"])
    def purge_item(conn, key, item_id):
        if not item(conn, item_id)["deleted_at"]:
            raise vault.VaultError("Mova o item para a lixeira primeiro.", 409)
        conn.execute(
            db.vault_items.delete().where(
                db.vault_items.c.user_id == session["user_id"], db.vault_items.c.id == item_id
            )
        )
        return jsonify({"message": "Item excluído permanentemente."})

    @route("/api/attachments", ["GET"])
    def list_attachments(conn, key):
        rows = conn.execute(select(db.attachments).where(db.attachments.c.user_id == session["user_id"])).mappings()
        return jsonify(
            {
                "attachments": [
                    {
                        "id": row["id"],
                        "credential_id": row["credential_id"],
                        **{k: v for k, v in entries.decode(row["payload"], key).items() if k != "content"},
                    }
                    for row in rows
                ]
            }
        )

    @route("/api/attachments", ["POST"])
    def store_attachment(conn, key):
        return jsonify({"id": entries.add_attachment(conn, session["user_id"], key, request.get_json())}), 201

    @route("/api/attachments/<int:attachment_id>/reveal", ["POST"])
    def reveal_attachment(conn, key, attachment_id):
        row = (
            conn.execute(
                select(db.attachments).where(
                    db.attachments.c.user_id == session["user_id"], db.attachments.c.id == attachment_id
                )
            )
            .mappings()
            .first()
        )
        if not row:
            raise vault.VaultError("Anexo não encontrado.", 404)
        return jsonify(entries.decode(row["payload"], key))

    @route("/api/attachments/<int:attachment_id>", ["DELETE"])
    def delete_attachment(conn, key, attachment_id):
        result = conn.execute(
            db.attachments.delete().where(
                db.attachments.c.user_id == session["user_id"], db.attachments.c.id == attachment_id
            )
        )
        if not result.rowcount:
            raise vault.VaultError("Anexo não encontrado.", 404)
        return jsonify({"message": "Anexo excluído."})

    @app.post("/api/generate-passphrase")
    @login_required
    def generate_passphrase():
        data = request.get_json(silent=True) or {}
        return jsonify({"password": entries.passphrase(data.get("words", 6), data.get("separator", "-"))})
