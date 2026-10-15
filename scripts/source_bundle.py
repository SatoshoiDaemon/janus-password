"""Ship the exact GPL importer source beside builds, verified against the lock."""

import hashlib
import json
import subprocess
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = "4.1.1.post1"


def main():
    with urllib.request.urlopen(f"https://pypi.org/pypi/pykeepass/{VERSION}/json", timeout=30) as response:
        metadata = json.load(response)
    source = next(item for item in metadata["urls"] if item["packagetype"] == "sdist")
    if not source["url"].startswith("https://files.pythonhosted.org/"):
        raise RuntimeError("Unexpected source host")
    expected = source["digests"]["sha256"]
    if expected not in (ROOT / "requirements-lock.txt").read_text():
        raise RuntimeError("Source digest absent from the dependency lock")
    with urllib.request.urlopen(source["url"], timeout=30) as response:
        imported_source = response.read()
    if hashlib.sha256(imported_source).hexdigest() != expected:
        raise RuntimeError("Importer source digest mismatch")
    own_source = subprocess.check_output(["git", "archive", "--format=tar", "HEAD"], cwd=ROOT)
    output = ROOT / "dist" / "janus-sources.zip"
    output.parent.mkdir(exist_ok=True)
    files = {
        "janus-source.tar": own_source,
        source["filename"]: imported_source,
        "PyKeePass-GPL-3.0.txt": (ROOT / "packaging/PyKeePass-GPL-3.0.txt").read_bytes(),
        "THIRD_PARTY_NOTICES.md": (ROOT / "THIRD_PARTY_NOTICES.md").read_bytes(),
    }
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, content)
    print(output)


if __name__ == "__main__":
    main()
