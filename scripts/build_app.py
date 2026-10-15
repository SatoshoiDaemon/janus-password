"""Native builds must run on their target OS. Never bundle writable vault data."""

import os
import subprocess
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    os.environ.setdefault("SOURCE_DATE_EPOCH", "1577836800")
    os.environ.setdefault("PYTHONHASHSEED", "0")
    assets = [(ROOT / "src/frontend", "src/frontend"), (ROOT / "src/backend/wordlist.txt", "src/backend")]
    for name, entry, gui in (("Janus", "scripts/janus_desktop.py", True), ("JanusCLI", "scripts/janus_cli.py", False)):
        command = [
            sys.executable,
            "-m",
            "PyInstaller",
            "--noconfirm",
            "--clean",
            "--onedir",
            "--name",
            name,
            "--paths",
            str(ROOT),
            "--collect-all",
            "argon2",
            "--collect-all",
            "pykeepass",
        ]
        if gui and os.name == "nt":
            command.append("--noconsole")
        for source, destination in assets:
            command.extend(["--add-data", str(source) + os.pathsep + destination])
        command.append(entry)
        subprocess.run(command, cwd=ROOT, check=True)
        for notice in ("LICENSE", "THIRD_PARTY_NOTICES.md", "CHANGELOG.md", "packaging/PyKeePass-GPL-3.0.txt"):
            shutil.copyfile(ROOT / notice, ROOT / "dist" / name / Path(notice).name)


if __name__ == "__main__":
    main()
