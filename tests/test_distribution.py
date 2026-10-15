import hashlib
import http.cookiejar
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

from scripts.build_extension import build

ROOT = Path(__file__).resolve().parents[1]


def test_extension_zips_are_deterministic(tmp_path):
    first = build(tmp_path / "first")
    second = build(tmp_path / "second")
    for name in ("janus-chromium.zip", "janus-firefox.zip"):
        assert (
            hashlib.sha256((first / name).read_bytes()).digest()
            == hashlib.sha256((second / name).read_bytes()).digest()
        )

    with zipfile.ZipFile(first / "janus-chromium.zip") as archive:
        assert all(info.create_system == 3 and info.compress_type == zipfile.ZIP_STORED for info in archive.infolist())


def test_launcher_single_instance_and_authenticated_shutdown(tmp_path):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    environment = {
        **os.environ,
        "JANUS_HOME": str(tmp_path / "home"),
        "DATABASE": str(tmp_path / "vault.db"),
        "HOST": "127.0.0.1",
    }
    launcher = (
        [os.environ["JANUS_SMOKE_EXECUTABLE"]]
        if os.environ.get("JANUS_SMOKE_EXECUTABLE")
        else [sys.executable, "-m", "src.backend.run"]
    )
    command = [*launcher, "--no-browser", "--vault", "smoke", "--port", str(port)]
    process = subprocess.Popen(
        command, cwd=ROOT, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def request(path, data=None, headers=None):
        body = json.dumps(data).encode() if data is not None else None
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}" + path,
            data=body,
            headers={"Content-Type": "application/json", **(headers or {})},
        )
        with opener.open(req, timeout=5) as response:
            return response.status, json.loads(response.read()) if path.startswith("/api/") else None

    try:
        for _attempt in range(100):
            try:
                request("/login")
                break
            except (OSError, urllib.error.URLError):
                if process.poll() is not None:
                    raise AssertionError(process.communicate()) from None
                time.sleep(0.05)
        else:
            raise AssertionError("Launcher did not start")
        second = subprocess.run(command, cwd=ROOT, env=environment, capture_output=True, text=True, timeout=10)
        assert second.returncode == 2
        if not os.environ.get("JANUS_SMOKE_EXECUTABLE"):
            assert "já está aberto" in second.stderr
        request(
            "/api/register",
            {
                "username": "smoke",
                "email": "smoke@example.test",
                "password": "login-password",
                "password_confirm": "login-password",
            },
        )
        request("/api/login", {"username": "smoke", "password": "login-password"})
        _, csrf = request("/api/csrf-token")
        headers = {"X-CSRF-Token": csrf["csrf_token"]}
        request("/api/vault/unlock", {"master_password": "master-password"}, headers)
        assert request("/api/local/shutdown", {}, headers)[0] == 200
        process.wait(timeout=8)
        assert process.returncode == 0, process.communicate()
        assert (tmp_path / "vault.db").exists()
        assert not (tmp_path / "home/smoke.instance.json").exists()
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
