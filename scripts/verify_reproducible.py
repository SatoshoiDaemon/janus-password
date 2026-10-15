"""Fail CI if a second native/extension build changes bytes on the same runner."""

import hashlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def digests():
    paths = [path for folder in ("Janus", "JanusCLI") for path in (ROOT / "dist" / folder).rglob("*") if path.is_file()]
    paths += list((ROOT / "dist").glob("*.zip"))
    return {str(path.relative_to(ROOT / "dist")): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}


def main():
    first = digests()
    if not first:
        raise SystemExit("Build the app before checking reproducibility")
    subprocess.run([sys.executable, "scripts/build_app.py"], cwd=ROOT, check=True)
    subprocess.run([sys.executable, "scripts/build_extension.py"], cwd=ROOT, check=True)
    second = digests()
    changes = sorted(name for name in first.keys() | second.keys() if first.get(name) != second.get(name))
    if changes:
        raise SystemExit("Non-reproducible build files: " + ", ".join(changes))
    print(f"Reproducible on this OS/runtime: {len(first)} identical files")


if __name__ == "__main__":
    main()
