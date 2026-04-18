# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Simulated vulnerable TP-Link SOHO router for EmbedXPL-Forge local lab.

Simulates the following vulnerable endpoints:
- CVE-2023-33538: WR940N/WR740N/WR841N SSID command injection
- CVE-2023-1389:  Archer AX21 unauthenticated command injection
- CVE-2022-30075: Archer AX50 backup RCE (stub)

Version: 1.0.0
"""

from __future__ import annotations

import hashlib
import logging
import os

from flask import Flask, jsonify, request

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("lab.router")

app = Flask(__name__)

MODEL = os.getenv("TARGET_MODEL", "WR940N")
SESSION_TOKEN = hashlib.md5(b"admin:admin").hexdigest()[:16]

_WLAN_HTML = """<html><head><title>TP-LINK Wireless Router WR940N</title></head>
<body>
<script>var model="{model}";</script>
<form method="GET" action="/userRpm/WlanNetworkRpm">
  SSID: <input name="ssid1" value="TP-Link_{model}">
  <input type="submit" value="Save">
</form>
<p>TP-LINK Technologies Co., Ltd.</p>
</body></html>"""

_LOGIN_HTML = """<html><head><title>TP-LINK Wireless Router WR940N</title></head>
<body>
<script>var model="{model}"; var sessionToken="{token}";</script>
<form method="POST" action="/userRpm/LoginRpm.htm">
  Username: <input name="username" value="admin">
  Password: <input type="password" name="password">
  <input type="submit" value="Login">
</form>
</body></html>"""


@app.route("/")
def index():
    """Redirect root to login."""
    return _LOGIN_HTML.format(model=MODEL, token=SESSION_TOKEN), 200


@app.route("/userRpm/LoginRpm.htm", methods=["GET", "POST"])
def login():
    """Simulate TP-Link login endpoint -- always accepts admin:admin."""
    user = request.values.get("username", "admin")
    pwd = request.values.get("password", "admin")
    logger.info("Login attempt: %s:%s from %s", user, pwd, request.remote_addr)
    return _LOGIN_HTML.format(model=MODEL, token=SESSION_TOKEN), 200


@app.route("/userRpm/WlanNetworkRpm", methods=["GET", "POST"])
def wlan_network():
    """Simulate CVE-2023-33538: SSID parameter command injection.

    If ssid1 contains shell metacharacters, the response echoes
    a simulated command output (blind injection simulation).
    """
    ssid1 = request.values.get("ssid1", "TP-Link_WR940N")
    logger.info("WlanNetworkRpm ssid1=%r from %s", ssid1, request.remote_addr)

    shell_chars = [";", "$(", "`", "&&", "||", "|", ">", "<"]
    if any(c in ssid1 for c in shell_chars):
        inner = ssid1
        for c in ["$(", ")", ";", "`"]:
            inner = inner.replace(c, "")
        inner = inner.strip()
        # Simulate blind injection -- return benign echo of what cmd would produce
        simulated_output = ""
        if "id" in inner:
            simulated_output = "uid=0(root) gid=0(root) groups=0(root)"
        elif "whoami" in inner:
            simulated_output = "root"
        elif "uname" in inner:
            simulated_output = "Linux WR940N 3.10.14 #1 SMP Fri Nov 2 13:38:02 CST 2018 mips GNU/Linux"
        else:
            simulated_output = "[injection point reached -- blind execution]"

        logger.warning("[CVE-2023-33538] Injection detected in ssid1! cmd=%r", inner)
        return simulated_output, 200

    return _WLAN_HTML.format(model=MODEL), 200


@app.route("/cgi-bin/luci/;stok=/locale", methods=["GET", "POST"])
def ax21_locale():
    """Simulate CVE-2023-1389: Archer AX21 unauthenticated command injection."""
    form_vals = request.form
    country = form_vals.get("country", "")
    logger.info("AX21 locale endpoint hit country=%r from %s", country, request.remote_addr)

    shell_chars = [";", "$(", "`", "&"]
    if any(c in country for c in shell_chars):
        inner = country.replace("$(", "").replace(")", "").replace(";", "").strip()
        logger.warning("[CVE-2023-1389] Injection in country param! cmd=%r", inner)
        output = "uid=0(root) gid=0(root) groups=0(root)" if "id" in inner else "[blind exec]"
        return output, 200

    return jsonify({"country": country, "status": "ok"}), 200


@app.route("/userRpm/StatusRpm.htm")
def status():
    """Return minimal router status page for banner fingerprinting."""
    html = (
        "<html><head><title>TP-LINK Wireless Router WR940N</title></head>"
        "<body><b>Firmware Version: </b>3.16.9 Build 150126 Rel.58038n<br/>"
        "<b>Hardware Version: </b>{model} v4 00000004<br/>"
        "TP-LINK Technologies Co., Ltd.</body></html>"
    ).format(model=MODEL)
    return html, 200


if __name__ == "__main__":
    logger.info("Starting simulated TP-Link %s lab target on 0.0.0.0:80", MODEL)
    app.run(host="0.0.0.0", port=80, debug=False)
