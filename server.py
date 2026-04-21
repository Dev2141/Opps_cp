#!/usr/bin/env python3
"""
StegOS Secure Suite — Unified Server Launcher
==============================================
Run this ONE file to start the whole project:

    python server.py

What it does:
    1. Compiles the Java backend (*.java in this folder) if not already compiled.
  2. Launches SecureShareServer (Java) on port 8088.
  3. Opens an ngrok tunnel → public HTTPS URL for Secure Share.
  4. Writes the ngrok URL to ngrok_config.js so the frontend loads it.
  5. Serves the frontend on port 8080 and opens your browser.

Requirements:
  - Python 3.7+
  - Java JDK 11+  (javac + java on PATH)
  - pyngrok       (auto-installed if missing)
  - ngrok account free token (prompted once if not set)
"""

import os
import sys
import time
import signal
import shutil
import threading
import subprocess
import webbrowser
from pathlib import Path
from http.server import HTTPServer, SimpleHTTPRequestHandler

# ─── Paths ────────────────────────────────────────────────────────────────────
SCRIPT_DIR   = Path(__file__).resolve().parent          # Opps_cp-main/
BACKEND_DIR  = SCRIPT_DIR                               # Java source directory
FRONTEND_DIR = SCRIPT_DIR                               # Frontend directory (index.html, app.js, styles.css)

# Java main class and source files
MAIN_CLASS   = "SecureShareServer"
JAVA_SOURCES = [
    "SecureShareServer.java",
    "EncryptionService.java",
    "ImageHandler.java",
    "PayloadEnvelope.java",
    "SteganographyEngine.java",
    "StegoAnalyzer.java",
]

# Ports
JAVA_PORT     = 8088
FRONTEND_PORT = 8080

# ─── ANSI Colours (Windows-safe) ──────────────────────────────────────────────
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def _enable_ansi_windows():
    """Enable ANSI escape codes in Windows cmd / PowerShell."""
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
    prefix   = colours.get(level, RESET) + f"[{level}]" + RESET
    print(f"  {prefix} {msg}")

# ─── Java compilation ──────────────────────────────────────────────────────────
def find_javac():
    """Return path to javac or None."""
    javac = shutil.which("javac")
    if javac:
        return javac
    # Common Windows JDK locations
    for base in [r"C:\Program Files\Java", r"C:\Program Files\Eclipse Adoptium",
                 r"C:\Program Files\Microsoft"]:
        base_path = Path(base)
        if base_path.exists():
            for jdk in sorted(base_path.iterdir(), reverse=True):
                candidate = jdk / "bin" / "javac.exe"
                if candidate.exists():
                    return str(candidate)
    return None

def classes_are_fresh():
    """Return True if all .class files exist and are newer than their .java files."""
    for src in JAVA_SOURCES:
        java_path  = BACKEND_DIR / src
        class_path = BACKEND_DIR / src.replace(".java", ".class")
        if not java_path.exists():
            continue   # optional file (e.g. TestExtract)
        if not class_path.exists():
            return False
        if java_path.stat().st_mtime > class_path.stat().st_mtime:
            return False
    return True

def compile_java():
    """Compile Java sources.  Returns True on success."""
    javac = find_javac()
    if not javac:
        log("ERR", "Could not find 'javac'. Make sure Java JDK is installed and on PATH.")
        return False

    sources = [str(BACKEND_DIR / s) for s in JAVA_SOURCES if (BACKEND_DIR / s).exists()]
    if not sources:
        log("ERR", f"No Java source files found in: {BACKEND_DIR}")
        return False

    log("INFO", f"Compiling {len(sources)} Java source(s) …")
    result = subprocess.run(
        [javac, "-d", str(BACKEND_DIR), "-cp", str(BACKEND_DIR)] + sources,
        capture_output=True, text=True
    )
    if result.returncode != 0:
        log("ERR", "Java compilation failed:\n" + result.stderr)
        return False
    log("OK", "Java compilation successful.")
    return True

# ─── Java backend process ──────────────────────────────────────────────────────
java_process = None

def start_java_backend():
    """Start SecureShareServer in a subprocess.  Returns the process object."""
    java = shutil.which("java")
    if not java:
        log("ERR", "Could not find 'java'. Make sure Java JRE/JDK is installed and on PATH.")
        return None

    log("INFO", f"Starting Java backend (SecureShareServer) on port {JAVA_PORT} …")
    proc = subprocess.Popen(
        [java, "-cp", str(BACKEND_DIR), MAIN_CLASS, str(JAVA_PORT)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        cwd=str(BACKEND_DIR),
    )

    # Stream Java output
    def _stream():
        for line in proc.stdout:
            print(f"  {YELLOW}[Java]{RESET} {line}", end="")
    threading.Thread(target=_stream, daemon=True).start()

    # Wait a moment to check it started
    time.sleep(1.5)
    if proc.poll() is not None:
        log("ERR", f"Java backend exited immediately (code {proc.returncode}).  "
            "Check that port {JAVA_PORT} is free and the class compiled successfully.")
        return None

    log("OK", f"Java backend running at http://localhost:{JAVA_PORT}")
    return proc

# ─── Static frontend server ────────────────────────────────────────────────────
class QuietHandler(SimpleHTTPRequestHandler):
    """Serve files from FRONTEND_DIR and suppress access logs."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(FRONTEND_DIR), **kwargs)

    def log_message(self, format, *args):
        pass   # suppress per-request logs; keep terminal clean

    def end_headers(self):
        # Allow CORS so browser can also talk to Java API directly
        self.send_header("Access-Control-Allow-Origin", "*")
        super().end_headers()

def free_port(port):
    """Kill any process currently listening on `port` (Windows + Unix)."""
    if sys.platform == "win32":
        try:
            # Find PID using netstat
            out = subprocess.check_output(
                f'netstat -ano | findstr ":{port}"',
                shell=True, text=True, stderr=subprocess.DEVNULL
            )
            pids = set()
            for line in out.splitlines():
                parts = line.split()
                # netstat columns: Proto  Local  Foreign  State  PID
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
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                log("WARN", f"Killed PID {pid} that was using port {port}.")
            if pids:
                time.sleep(0.6)  # give OS time to release the port
        except subprocess.CalledProcessError:
            pass  # nothing was using that port
    else:
        # Unix: lsof
        try:
            out = subprocess.check_output(
                ["lsof", "-ti", f":{port}"], text=True, stderr=subprocess.DEVNULL
            )
            for pid_str in out.strip().splitlines():
                subprocess.call(["kill", "-9", pid_str],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                log("WARN", f"Killed PID {pid_str} that was using port {port}.")
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass

def start_frontend_server():
    """Kill anything on FRONTEND_PORT, then start our static HTTP server."""
    log("INFO", f"Freeing port {FRONTEND_PORT} if occupied…")
    free_port(FRONTEND_PORT)
    server = HTTPServer(("0.0.0.0", FRONTEND_PORT), QuietHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    log("OK", f"Frontend served at http://localhost:{FRONTEND_PORT}")
    return server

# ─── ngrok tunnel ─────────────────────────────────────────────────────────────
def ensure_pyngrok():
    """Import pyngrok, installing it automatically if not present."""
    try:
        import pyngrok  # noqa: F401
    except ImportError:
        log("INFO", "pyngrok not found — installing (one-time)…")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "pyngrok", "-q"],
            stdout=subprocess.DEVNULL
        )
        log("OK", "pyngrok installed.")

def start_ngrok_tunnel(auth_token=None):
    """
    Open an ngrok HTTP tunnel on JAVA_PORT.
    Returns the public URL string, or None on failure.
    """
    ensure_pyngrok()
    try:
        from pyngrok import ngrok, conf, exception as ngrok_exc

        # Apply auth token if provided (or already saved by pyngrok)
        if auth_token:
            ngrok.set_auth_token(auth_token)

        log("INFO", f"Opening ngrok tunnel → localhost:{JAVA_PORT} …")
        tunnel = ngrok.connect(JAVA_PORT, "http")
        public_url = tunnel.public_url

        # Prefer https if available
        if public_url.startswith("http://"):
            https_url = "https://" + public_url[len("http://"):]
            # Verify https variant works (ngrok always provides both for free tier)
            public_url = https_url

        log("OK",   f"ngrok public URL: {public_url}")
        return public_url

    except Exception as exc:
        msg = str(exc)
        if "auth" in msg.lower() or "token" in msg.lower() or "ERR_NGROK_105" in msg:
            log("WARN", "ngrok requires a free auth token.")
            log("WARN", "  1. Sign up free at https://dashboard.ngrok.com/signup")
            log("WARN", "  2. Copy your token from https://dashboard.ngrok.com/get-started/your-authtoken")
            log("WARN", "  3. Re-run server.py and paste it when prompted.")
            token = input("  Paste ngrok auth token (or press Enter to skip): ").strip()
            if token:
                return start_ngrok_tunnel(auth_token=token)
        else:
            log("WARN", f"ngrok tunnel failed: {exc}")
        return None

def write_ngrok_config(url):
    """
    Write a tiny JS file the frontend loads to know the public API URL.
    If url is None, the file sets NGROK_URL = null (falls back to localhost).
    """
    config_path = FRONTEND_DIR / "ngrok_config.js"
    with open(config_path, "w", encoding="utf-8") as f:
        if url:
            f.write(
                "// Auto-generated by server.py — do not edit manually\n"
                f'window.NGROK_URL = "{url}";\n'
            )
        else:
            f.write(
                "// ngrok not available — using localhost\n"
                "window.NGROK_URL = null;\n"
            )
    if url:
        log("OK", f"ngrok_config.js written → {url}")
    else:
        log("INFO", "ngrok_config.js written → null (localhost fallback)")

# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    global java_process

    print()
    print(BOLD + CYAN + "  ╔══════════════════════════════════════╗" + RESET)
    print(BOLD + CYAN + "  ║     StegOS Secure Suite — Launcher   ║" + RESET)
    print(BOLD + CYAN + "  ╚══════════════════════════════════════╝" + RESET)
    print()

    # ── 1. Validate directories ──
    if not BACKEND_DIR.exists():
        log("ERR", f"Backend directory not found: {BACKEND_DIR}")
        sys.exit(1)
    if not FRONTEND_DIR.exists():
        log("ERR", f"Frontend directory not found: {FRONTEND_DIR}")
        sys.exit(1)
    if not (FRONTEND_DIR / "index.html").exists():
        log("ERR", f"index.html not found in: {FRONTEND_DIR}. Check your project structure.")
        sys.exit(1)

    # ── 2. Compile Java if needed ──
    if classes_are_fresh():
        log("INFO", "Java classes are up-to-date, skipping compilation.")
    else:
        ok = compile_java()
        if not ok:
            log("WARN", "Will try to start backend anyway (may fail).")

    # ── 3. Start Java backend ──
    java_process = start_java_backend()
    if java_process is None:
        log("WARN", "Java backend did not start. Share tab will not work, "
            "but Hide/Extract/Analyze run fully in-browser.")

    # ── 4. Start ngrok tunnel for public Secure Share access ──
    ngrok_url = start_ngrok_tunnel()
    write_ngrok_config(ngrok_url)

    # ── 5. Start frontend static server ──
    start_frontend_server()

    # ── 6. Open browser ──
    local_url = f"http://localhost:{FRONTEND_PORT}"
    time.sleep(0.5)
    log("INFO", f"Opening browser at {local_url} …")
    webbrowser.open(local_url)

    # ── 7. Keep alive ──
    print()
    print(BOLD + GREEN + f"  ✓  StegOS is running!" + RESET)
    print(f"     Frontend (local)  →  http://localhost:{FRONTEND_PORT}")
    print(f"     API    (local)    →  http://localhost:{JAVA_PORT}")
    if ngrok_url:
        print(BOLD + GREEN + f"     API    (public)   →  {ngrok_url}" + RESET)
        print()
        print(BOLD + YELLOW +
              "  ★  Share the PUBLIC URL above so others can reach your Secure Share inbox!" + RESET)
    else:
        print()
        print(YELLOW + "  ⚠  ngrok not active — Secure Share only works on this PC." + RESET)
    print()
    print("  Press  Ctrl+C  to stop all servers.\n")

    def _shutdown(signum, frame):
        print()
        log("INFO", "Shutting down …")
        # Kill ngrok tunnels
        try:
            from pyngrok import ngrok
            ngrok.kill()
        except Exception:
            pass
        # Kill Java backend
        if java_process and java_process.poll() is None:
            java_process.terminate()
            try:
                java_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                java_process.kill()
        # Remove ngrok config file
        cfg = FRONTEND_DIR / "ngrok_config.js"
        if cfg.exists():
            cfg.unlink()
        log("OK", "Stopped. Goodbye!")
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    # Block main thread indefinitely
    while True:
        time.sleep(1)
        # Restart Java backend if it crashed
        if java_process and java_process.poll() is not None:
            log("WARN", "Java backend crashed — restarting …")
            java_process = start_java_backend()

if __name__ == "__main__":
    main()
