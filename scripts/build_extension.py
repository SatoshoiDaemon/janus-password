"""Build deterministic Chromium and Firefox extension ZIPs, without npm."""

import json
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def build(output=None):
    output = output or ROOT / "dist"
    output.mkdir(parents=True, exist_ok=True)
    base = {
        "manifest_version": 3,
        "name": "Janus Local Vault",
        "version": "0.3.0",
        "description": "User-triggered access to your paired offline-first Janus vault.",
        "permissions": ["activeTab", "scripting", "storage"],
        "host_permissions": ["http://127.0.0.1/*"],
        "action": {"default_popup": "popup.html"},
    }
    for browser in ("chromium", "firefox"):
        manifest = {
            **base,
            "background": (
                {"service_worker": "background.js"} if browser == "chromium" else {"scripts": ["background.js"]}
            ),
        }
        if browser == "firefox":
            manifest["browser_specific_settings"] = {
                "gecko": {"id": "janus-local@satoshoidaemon", "strict_min_version": "128.0"}
            }
        with zipfile.ZipFile(output / f"janus-{browser}.zip", "w", zipfile.ZIP_STORED) as archive:
            files = {
                path.name: path.read_text(encoding="utf-8").encode("utf-8")
                for path in (ROOT / "extension").iterdir()
                if path.is_file()
            }
            files["LICENSE"] = (ROOT / "LICENSE").read_text(encoding="utf-8").encode("utf-8")
            files["manifest.json"] = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
            for name, content in sorted(files.items()):
                info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.compress_type = zipfile.ZIP_STORED
                info.external_attr = 0o644 << 16
                archive.writestr(info, content)
    return output


if __name__ == "__main__":
    print(build())
