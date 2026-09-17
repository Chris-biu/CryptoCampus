"""Run a disposable real-engine desktop check; never reuse a deployed database."""

import argparse
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[2]


def wait_for(url, process=None):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            raise RuntimeError("test web server exited during startup")
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError):
            time.sleep(0.2)
    raise RuntimeError("test server did not become ready")


def free_port():
    with socket.socket() as connection:
        connection.bind(("127.0.0.1", 0))
        return connection.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--image", required=True, help="existing server image containing real bridge"
    )
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--discover", action="store_true")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    vite = ROOT / "web/node_modules/vite/bin/vite.js"
    if not vite.is_file():
        parser.error("run npm --prefix web ci first")
    api_port, web_port = free_port(), free_port()
    while web_port == api_port:
        web_port = free_port()
    api = f"http://127.0.0.1:{api_port}"
    base = f"http://127.0.0.1:{web_port}"
    name = "cryptocampus-e2e-" + secrets.token_hex(6)
    environment = dict(
        os.environ,
        CC_REAL_E2E_PASSWORD="Qa9!" + secrets.token_urlsafe(24),
        VITE_API_PROXY_TARGET=api,
    )
    web = None
    started = False
    try:
        subprocess.run(
            [
                "docker",
                "run",
                "--detach",
                "--rm",
                "--pull",
                "never",
                "--name",
                name,
                "-p",
                f"127.0.0.1:{api_port}:8000",
                "--workdir",
                "/src",
                "--mount",
                f"type=bind,source={ROOT},target=/src,readonly",
                "-e",
                "CC_RUN_REAL_E2E=1",
                "-e",
                "CC_REAL_E2E_PASSWORD",
                "-e",
                "PYTHONPATH=/src/server",
                args.image,
                "python",
                "-m",
                "uvicorn",
                "support.real_app:app",
                "--app-dir",
                "/src/tests/e2e",
                "--host",
                "0.0.0.0",
                "--port",
                "8000",
                "--no-access-log",
            ],
            env=environment,
            check=True,
            stdout=subprocess.DEVNULL,
        )
        started = True
        wait_for(api + "/openapi.json")
        with tempfile.TemporaryFile() as log:
            web = subprocess.Popen(
                [
                    "node",
                    str(vite),
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(web_port),
                    "--strictPort",
                ],
                cwd=ROOT / "web",
                env=environment,
                stdout=log,
                stderr=log,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            wait_for(base, web)
            command = [
                sys.executable,
                str(ROOT / "tests/e2e/real_crypto_browser.py"),
                "--base-url",
                base,
                "--output",
                str(args.output.resolve()),
            ]
            if args.discover:
                command.append("--discover")
            subprocess.run(command, env=environment, check=True)
    finally:
        if web is not None:
            web.terminate()
            try:
                web.wait(timeout=10)
            except subprocess.TimeoutExpired:
                web.kill()
                web.wait()
        if started:
            subprocess.run(
                ["docker", "stop", "--time", "5", name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )


if __name__ == "__main__":
    main()
