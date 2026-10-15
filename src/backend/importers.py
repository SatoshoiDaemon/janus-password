"""Offline importers. Parse and validate every item before any database write."""

import base64
import csv
import io
import json

from defusedxml import ElementTree
from pykeepass import PyKeePass

from . import entries, vault


def _credential(name, username, password, urls=None, **extra):
    item = {
        "site_name": name or urls and urls[0] or "Imported",
        "login": username or "",
        "password": password or "",
        "urls": urls or [],
        **extra,
    }
    if not item["password"]:
        raise vault.VaultError(f"Entrada sem senha: {item['site_name']}. Corrija o arquivo antes de importar.")
    entries.fields(item)
    return {"kind": "credential", "data": item, "attachments": []}


def parse_csv(text):
    try:
        dialect = csv.Sniffer().sniff(text[:8192], delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(io.StringIO(text), dialect=dialect)
    if not reader.fieldnames:
        raise vault.VaultError("CSV vazio ou sem cabeçalho.")
    result = []
    aliases = {
        "title": "name",
        "account": "name",
        "site_name": "name",
        "login": "username",
        "user name": "username",
        "login_username": "username",
        "login_password": "password",
        "login_uri": "url",
        "website": "url",
        "group": "folder",
    }
    for number, original in enumerate(reader, 2):
        if None in original:
            raise vault.VaultError(f"CSV inválido na linha {number}.")
        row = {aliases.get(k.strip().casefold(), k.strip().casefold()): v or "" for k, v in original.items()}
        known = {
            "name",
            "username",
            "password",
            "url",
            "folder",
            "notes",
            "favorite",
            "totp",
            "login_totp",
            "type",
            "fields",
            "reprompt",
        }
        custom = [{"name": k, "value": v} for k, v in row.items() if k not in known]
        if row.get("type") not in {None, "", "login"}:
            raise vault.VaultError(f"Tipo CSV não suportado na linha {number}; use JSON Bitwarden para outros tipos.")
        result.append(
            _credential(
                row.get("name"),
                row.get("username"),
                row.get("password"),
                [row["url"]] if row.get("url") else [],
                folder=row.get("folder", ""),
                notes=row.get("notes", ""),
                favorite=row.get("favorite", "").lower() in {"1", "true", "yes"},
                custom_fields=custom,
                totp=row.get("totp") or row.get("login_totp", ""),
            )
        )
    return result


def parse_bitwarden(text):
    data = json.loads(text)
    if not isinstance(data, dict) or data.get("encrypted") or not isinstance(data.get("items"), list):
        raise vault.VaultError(
            "Use uma exportação JSON Bitwarden não criptografada; o arquivo será processado apenas localmente."
        )
    folders = {folder["id"]: folder["name"] for folder in data.get("folders", [])}
    result = []
    for item in data["items"]:
        name = item.get("name") or "Imported"
        if item.get("attachments"):
            raise vault.VaultError(
                f"{name}: o JSON referencia anexos não incluídos no arquivo. Exporte-os separadamente antes de importar."
            )
        if item.get("type") == 1:
            login = item.get("login") or {}
            if login.get("fido2Credentials"):
                raise vault.VaultError(f"{name}: passkeys não podem ser importadas como senhas.")
            fields = [
                {"name": f.get("name") or "Field", "value": str(f.get("value") or "")} for f in item.get("fields") or []
            ]
            result.append(
                _credential(
                    name,
                    login.get("username"),
                    login.get("password"),
                    [uri["uri"] for uri in login.get("uris") or [] if uri.get("uri")],
                    folder=folders.get(item.get("folderId"), ""),
                    favorite=bool(item.get("favorite")),
                    custom_fields=fields,
                    notes=item.get("notes") or "",
                    totp=login.get("totp") or "",
                )
            )
        elif item.get("type") in {2, 3, 4}:
            kind = {2: "note", 3: "card", 4: "identity"}[item["type"]]
            body = {k: str(v) if v is not None else "" for k, v in (item.get(kind) or {}).items()}
            body["notes"] = item.get("notes") or ""
            for field in item.get("fields") or []:
                body[field.get("name") or "Field"] = str(field.get("value") or "")
            result.append({"kind": kind, "data": {"kind": kind, "name": name, "fields": body}})
        else:
            raise vault.VaultError(f"Tipo Bitwarden desconhecido em {name}; nenhum item será importado.")
    return result


def parse_keepass_xml(text):
    root = ElementTree.fromstring(text)
    if root.tag != "KeePassFile":
        raise vault.VaultError("XML não é uma exportação KeePass.")
    result = []

    def group(node, parent=""):
        folder = "/".join(filter(None, [parent, node.findtext("Name", "")]))
        for element in node.findall("Entry"):
            if element.findall("Binary"):
                raise vault.VaultError("XML com anexos: importe o KDBX original para preservar os arquivos.")
            values = {field.findtext("Key"): field.findtext("Value", "") for field in element.findall("String")}
            if any(
                field.find("Value").get("Protected") == "True"
                for field in element.findall("String")
                if field.find("Value") is not None
            ):
                raise vault.VaultError("Exporte XML com valores descriptografados ou importe o KDBX original.")
            result.append(
                _credential(
                    values.get("Title"),
                    values.get("UserName"),
                    values.get("Password"),
                    [values["URL"]] if values.get("URL") else [],
                    folder=folder,
                    notes=values.get("Notes", ""),
                    custom_fields=[
                        {"name": k, "value": v}
                        for k, v in values.items()
                        if k not in {"Title", "UserName", "Password", "URL", "Notes"}
                    ],
                    tags=[t for t in element.findtext("Tags", "").split(";") if t],
                )
            )
        for child in node.findall("Group"):
            group(child, folder)

    for node in root.findall("Root/Group"):
        group(node)
    return result


def parse_keepass_kdbx(raw, password, keyfile=None):
    try:
        kp = PyKeePass(
            io.BytesIO(raw),
            password=password or None,
            keyfile=io.BytesIO(base64.b64decode(keyfile, validate=True)) if keyfile else None,
        )
        result = []
        for item in kp.entries:
            if kp.recyclebin_group and any(
                ancestor == kp.recyclebin_group._element for ancestor in item._element.iterancestors("Group")
            ):
                continue
            record = _credential(
                item.title,
                item.username,
                item.password,
                [item.url] if item.url else [],
                folder="/".join(item.group.path),
                notes=item.notes or "",
                tags=item.tags or [],
                custom_fields=[{"name": k, "value": v} for k, v in item.custom_properties.items() if k != "otp"],
                totp=item.otp or "",
            )
            record["attachments"] = [
                {"name": attachment.filename, "content": base64.b64encode(attachment.binary).decode()}
                for attachment in item.attachments
            ]
            result.append(record)
        return result
    except vault.VaultError:
        raise
    except Exception as exc:
        raise vault.VaultError("KDBX inválido, senha/keyfile incorretos ou formato não suportado.") from exc


def parse(data):
    try:
        format_name = data["format"]
        content = data["content"]
        if not isinstance(content, str):
            raise ValueError("Expected content")
        if format_name == "csv":
            result = parse_csv(content.lstrip("\ufeff"))
        elif format_name == "bitwarden":
            result = parse_bitwarden(content)
        elif format_name == "keepass-xml":
            result = parse_keepass_xml(content)
        elif format_name == "keepass-kdbx":
            result = parse_keepass_kdbx(
                base64.b64decode(content, validate=True), data.get("password", ""), data.get("keyfile")
            )
        else:
            raise vault.VaultError("Formato de importação não suportado.")
        if not result or len(result) > 10000:
            raise vault.VaultError("Importe entre 1 e 10.000 entradas por arquivo.")
        return result
    except vault.VaultError:
        raise
    except Exception as exc:
        raise vault.VaultError("Arquivo inválido; nenhuma entrada foi importada.") from exc


def preview(records):
    return {
        "count": len(records),
        "items": [
            {
                "kind": r["kind"],
                "name": r["data"].get("site_name") or r["data"].get("name"),
                "attachments": len(r.get("attachments", [])),
            }
            for r in records
        ],
    }


def commit(conn, user_id, key, records, duplicates="skip"):
    if duplicates not in {"skip", "keep"}:
        raise vault.VaultError("Política de duplicatas inválida.")
    existing = {
        (item["site_name"], item["login"], item["password"])
        for item in [
            entries.reveal(conn, user_id, row["id"], key) for row in entries.list_credentials(conn, user_id, key)
        ]
    }
    imported = skipped = 0
    for record in records:
        data = record["data"]
        if record["kind"] == "credential":
            identity = (data["site_name"], data["login"], data["password"])
            if duplicates == "skip" and identity in existing:
                skipped += 1
                continue
            item_id = entries.write(conn, user_id, key, data)
            existing.add(identity)
            for attachment in record.get("attachments", []):
                entries.add_attachment(conn, user_id, key, {**attachment, "credential_id": item_id})
        else:
            entries.write_item(conn, user_id, key, data)
        imported += 1
    return {"imported": imported, "skipped": skipped}
