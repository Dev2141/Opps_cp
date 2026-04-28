#!/usr/bin/env python3
"""
StegOS Secure Suite launcher.

Run:
    python server.py

This script:
  1. Compiles the Java backend if needed.
  2. Starts the SecureShareServer Java API on port 8088.
  3. Serves the frontend on port 8080.
  4. Proxies /share-api/* requests from the frontend to the Java backend.
  5. Optionally opens an ngrok tunnel for the full frontend app.
"""

import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = SCRIPT_DIR
FRONTEND_DIR = SCRIPT_DIR

MAIN_CLASS = "SecureShareServer"
JAVA_SOURCES = [
    "SecureShareServer.java",
    "EncryptionService.java",
    "ImageHandler.java",
    "PayloadEnvelope.java",
    "SteganographyEngine.java",
    "StegoAnalyzer.java",
]

JAVA_PORT = 8088
FRONTEND_PORT = 8080
SHARE_PROXY_PREFIX = "/share-api"

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

java_process = None


def _enable_ansi_windows():
    if sys.platform == "win32":
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            pass


_enable_ansi_windows()


def log(level, msg):
    colours = {"INFO": CYAN, "OK": GREEN, "WARN": YELLOW, "ERR": RED}
    prefix = colours.get(level, RESET) + f"[{level}]" + RESET
    print(f"  {prefix} {msg}")


def find_javac():
    javac = shutil.which("javac")
    if javac:
        return javac

    for base in [
        r"C:\Program Files\Java",
        r"C:\Program Files\Eclipse Adoptium",
        r"C:\Program Files\Microsoft",
    ]:
        base_path = Path(base)
        if not base_path.exists():
            continue
        for jdk in sorted(base_path.iterdir(), reverse=True):
            candidate = jdk / "bin" / "javac.exe"
            if candidate.exists():
                return str(candidate)
    return None


def classes_are_fresh():
    for src in JAVA_SOURCES:
        java_path = BACKEND_DIR / src
        class_path = BACKEND_DIR / src.replace(".java", ".class")
        if not java_path.exists():
            continue
        if not class_path.exists():
            return False
        if java_path.stat().st_mtime > class_path.stat().st_mtime:
            return False
    return True


def compile_java():
    javac = find_javac()
    if not javac:
        log("ERR", "Could not find 'javac'. Make sure Java JDK is installed and on PATH.")
        return False

    sources = [str(BACKEND_DIR / src) for src in JAVA_SOURCES if (BACKEND_DIR / src).exists()]
    if not sources:
        log("ERR", f"No Java source files found in: {BACKEND_DIR}")
        return False

    log("INFO", f"Compiling {len(sources)} Java source(s)...")
    result = subprocess.run(
        [javac, "-d", str(BACKEND_DIR), "-cp", str(BACKEND_DIR)] + sources,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        log("ERR", "Java compilation failed:\n" + result.stderr)
        return False

    log("OK", "Java compilation successful.")
    return True


def start_java_backend():
    java = shutil.which("java")
    if not java:
        log("ERR", "Could not find 'java'. Make sure Java is installed and on PATH.")
        return None

    log("INFO", f"Freeing port {JAVA_PORT} if occupied...")
    free_port(JAVA_PORT)
    log("INFO", f"Starting Java backend on port {JAVA_PORT}...")
    proc = subprocess.Popen(
        [java, "-cp", str(BACKEND_DIR), MAIN_CLASS, str(JAVA_PORT)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        cwd=str(BACKEND_DIR),
    )

    def _stream():
        for line in proc.stdout:
            print(f"  {YELLOW}[Java]{RESET} {line}", end="")

    threading.Thread(target=_stream, daemon=True).start()

    time.sleep(1.5)
    if proc.poll() is not None:
        log(
            "ERR",
            f"Java backend exited immediately (code {proc.returncode}). Check that port {JAVA_PORT} is free.",
        )
        return None

    log("OK", f"Java backend running at http://localhost:{JAVA_PORT}")
    return proc


class QuietHandler(SimpleHTTPRequestHandler):
    """Serve the frontend and proxy /share-api/* to the local Java backend."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(FRONTEND_DIR), **kwargs)

    def log_message(self, format, *args):
        pass

    def handle(self):
        # Browsers and tunnels may close sockets mid-request; treat these as benign.
        try:
            super().handle()
        except (ConnectionResetError, BrokenPipeError):
            pass

    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, ngrok-skip-browser-warning")
        super().end_headers()

    def do_OPTIONS(self):
        if self.path.startswith(SHARE_PROXY_PREFIX):
            self.send_response(204)
            self.end_headers()
            return
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        if self.path.startswith(SHARE_PROXY_PREFIX):
            self._proxy_request("GET")
            return
        super().do_GET()

    def do_POST(self):
        if self.path.startswith(SHARE_PROXY_PREFIX):
            self._proxy_request("POST")
            return
        super().do_POST()

    def _proxy_request(self, method):
        backend_path = self.path[len(SHARE_PROXY_PREFIX) :] or "/"
        target_url = f"http://127.0.0.1:{JAVA_PORT}{backend_path}"

        body = None
        if method in {"POST", "PUT", "PATCH"}:
            content_length = int(self.headers.get("Content-Length", "0") or "0")
            body = self.rfile.read(content_length) if content_length > 0 else b""

        headers = {}
        for name in ("Content-Type", "ngrok-skip-browser-warning"):
            value = self.headers.get(name)
            if value:
                headers[name] = value

        request = urllib.request.Request(target_url, data=body, headers=headers, method=method)

        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                payload = response.read()
                self.send_response(response.status)
                self.send_header("Content-Type", response.headers.get("Content-Type", "application/json; charset=utf-8"))
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
        except urllib.error.HTTPError as exc:
            payload = exc.read()
            self.send_response(exc.code)
            self.send_header("Content-Type", exc.headers.get("Content-Type", "application/json; charset=utf-8"))
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        except Exception:
            payload = (
                b'{"ok":false,"error":"Secure Share backend is offline or unreachable. '
                b'Start server.py again or refresh after the tunnel reconnects."}'
            )
            self.send_response(502)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)


def free_port(port):
    if sys.platform == "win32":
        try:
            out = subprocess.check_output(
                f'netstat -ano | findstr ":{port}"',
                shell=True,
                text=True,
                stderr=subprocess.DEVNULL,
            )
            pids = set()
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 5 and f":{port}" in parts[1]:
                    try:
                        pids.add(int(parts[-1]))
                    except ValueError:
                        pass
            for pid in pids:
                if pid == 0:
                    continue
                subprocess.call(
                    ["taskkill", "/PID", str(pid), "/F"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                log("WARN", f"Killed PID {pid} that was using port {port}.")
            if pids:
                time.sleep(0.6)
        except subprocess.CalledProcessError:
            pass
    else:
        try:
            out = subprocess.check_output(
                ["lsof", "-ti", f":{port}"],
                text=True,
                stderr=subprocess.DEVNULL,
            )
            for pid_str in out.strip().splitlines():
                subprocess.call(["kill", "-9", pid_str], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                log("WARN", f"Killed PID {pid_str} that was using port {port}.")
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass


def start_frontend_server():
    log("INFO", f"Freeing port {FRONTEND_PORT} if occupied...")
    free_port(FRONTEND_PORT)
    server = ThreadingHTTPServer(("0.0.0.0", FRONTEND_PORT), QuietHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    log("OK", f"Frontend served at http://localhost:{FRONTEND_PORT}")
    return server


def ensure_pyngrok():
    try:
        import pyngrok  # noqa: F401
    except ImportError:
        log("INFO", "pyngrok not found. Installing once...")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "pyngrok", "-q"],
            stdout=subprocess.DEVNULL,
        )
        log("OK", "pyngrok installed.")


def start_ngrok_tunnel(auth_token=None):
    ensure_pyngrok()
    try:
        from pyngrok import ngrok

        # Clear stale local ngrok agent sessions to reduce endpoint conflict errors.
        try:
            ngrok.kill()
        except Exception:
            pass

        if auth_token:
            ngrok.set_auth_token(auth_token)

        log("INFO", f"Opening ngrok tunnel -> localhost:{FRONTEND_PORT}...")
        tunnel = ngrok.connect(FRONTEND_PORT, "http")
        public_url = tunnel.public_url
        if public_url.startswith("http://"):
            public_url = "https://" + public_url[len("http://") :]
        log("OK", f"ngrok public URL: {public_url}")
        return public_url
    except Exception as exc:
        msg = str(exc)
        if "auth" in msg.lower() or "token" in msg.lower() or "ERR_NGROK_105" in msg:
            log("WARN", "ngrok requires a free auth token.")
            log("WARN", "  1. Sign up at https://dashboard.ngrok.com/signup")
            log("WARN", "  2. Copy your token from https://dashboard.ngrok.com/get-started/your-authtoken")
            log("WARN", "  3. Re-run server.py and paste it when prompted.")
            token = input("  Paste ngrok auth token (or press Enter to skip): ").strip()
            if token:
                return start_ngrok_tunnel(auth_token=token)
        else:
            log("WARN", f"ngrok tunnel failed: {exc}")
        return None


def write_ngrok_config(url):
    config_path = FRONTEND_DIR / "ngrok_config.js"
    with open(config_path, "w", encoding="utf-8") as handle:
        if url:
            handle.write("// Auto-generated by server.py - do not edit manually\n")
            handle.write(f'window.NGROK_URL = "{url}";\n')
        else:
            handle.write("// ngrok not available - local-only mode\n")
            handle.write("window.NGROK_URL = null;\n")

    if url:
        log("OK", f"ngrok_config.js written -> {url}")
    else:
        log("INFO", "ngrok_config.js written -> null (localhost fallback)")


def main():
    global java_process

    print()
    print(BOLD + CYAN + "  ======================================" + RESET)
    print(BOLD + CYAN + "  StegOS Secure Suite Launcher" + RESET)
    print(BOLD + CYAN + "  ======================================" + RESET)
    print()

    if not BACKEND_DIR.exists():
        log("ERR", f"Backend directory not found: {BACKEND_DIR}")
        sys.exit(1)
    if not FRONTEND_DIR.exists():
        log("ERR", f"Frontend directory not found: {FRONTEND_DIR}")
        sys.exit(1)
    if not (FRONTEND_DIR / "index.html").exists():
        log("ERR", f"index.html not found in: {FRONTEND_DIR}")
        sys.exit(1)

    if classes_are_fresh():
        log("INFO", "Java classes are up to date, skipping compilation.")
    else:
        ok = compile_java()
        if not ok:
            log("WARN", "Will try to start the backend anyway.")

    java_process = start_java_backend()
    if java_process is None:
        log("WARN", "Java backend did not start. Share mode will stay offline.")

    start_frontend_server()
    ngrok_url = start_ngrok_tunnel()
    write_ngrok_config(ngrok_url)

    local_url = f"http://localhost:{FRONTEND_PORT}"
    time.sleep(0.5)
    log("INFO", f"Opening browser at {local_url}...")
    webbrowser.open(local_url)

    print()
    print(BOLD + GREEN + "  StegOS is running." + RESET)
    print(f"     Frontend (local) -> {local_url}")
    print(f"     API      (local) -> http://localhost:{JAVA_PORT}")
    if ngrok_url:
        print(BOLD + GREEN + f"     App      (public) -> {ngrok_url}" + RESET)
        print()
        print(BOLD + YELLOW + "  Share the PUBLIC URL above so others open the full app." + RESET)
    else:
        print()
        print(YELLOW + "  ngrok not active - public sharing is unavailable." + RESET)
    print()
    print("  Press Ctrl+C to stop all servers.\n")

    def _shutdown(signum, frame):
        print()
        log("INFO", "Shutting down...")
        try:
            from pyngrok import ngrok

            ngrok.kill()
        except Exception:
            pass

        if java_process and java_process.poll() is None:
            java_process.terminate()
            try:
                java_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                java_process.kill()

        cfg = FRONTEND_DIR / "ngrok_config.js"
        if cfg.exists():
            cfg.unlink()

        log("OK", "Stopped. Goodbye.")
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    while True:
        time.sleep(1)
        if java_process and java_process.poll() is not None:
            log("WARN", "Java backend crashed. Restarting...")
            java_process = start_java_backend()


if __name__ == "__main__":
    main()
