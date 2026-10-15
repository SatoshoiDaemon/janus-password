import hashlib
import platform
from pathlib import Path

folder = Path("dist")
files = sorted(path for path in folder.iterdir() if path.is_file() and path.suffix in {".gz", ".exe", ".zip"})
(folder / f"Janus-{platform.system()}-SHA256SUMS.txt").write_text(
    "".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in files)
)
