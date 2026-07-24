# ==============================================================================
# npi_app.py — Backend for the NPI Dashboard.
#
# The dashboard was originally a single static HTML file: login was checked in
# JavaScript (with the password in the source) and all data lived in the
# browser's localStorage. That provides NO real security — a static page cannot
# enforce anything. This backend fixes that properly:
#
#   * Serves the dashboard page.
#   * Real server-side login (hashed passwords, session cookie) via security.py.
#   * Dashboard state is stored SERVER-SIDE in npi_state.json.
#       - GET  /api/npi_state  -> read current state (open; it's a team view)
#       - POST /api/npi_state  -> save state (requires a valid session)
#   * The same hardened security layer as the assembly app: secure headers,
#     CSRF (same-origin) checks, brute-force rate limiting, generic errors.
#
# The browser still keeps a localStorage copy as an offline cache, but the
# AUTHORITATIVE, write-protected copy is on the server. A user who fakes the
# client-side "logged in" flag still cannot save: the server returns 401.
# ==============================================================================

import os
import json
import logging
import tempfile

from flask import Flask, request, jsonify, session, send_from_directory

import security

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("npi_app")

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
TEMPLATES  = os.path.join(BASE_DIR, "templates")
STATE_FILE = os.path.join(BASE_DIR, "npi_state.json")

app = Flask(__name__)
security.configure_app(app)   # secret key, hardened cookies, headers, size cap


@app.after_request
def _no_cache(resp):
    # This app has no real-time push — every PC re-fetches on page load/refresh
    # to pick up whatever the server currently has. If any layer in between
    # (browser cache, or a corporate proxy in front of this server) is allowed
    # to cache these responses, one PC's edits can appear to "never show up"
    # on another PC even though the server itself saved them correctly. These
    # headers make every response (page + API) always re-fetched from here.
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    return resp


# ── page ──────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    # Served as a raw file (NOT render_template) so the page's JS template
    # literals and CSS braces are never interpreted as Jinja syntax.
    return send_from_directory(TEMPLATES, "npi-dashboard.html")


# ── auth ──────────────────────────────────────────────────────────────────────
@app.route("/api/login", methods=["POST"])
def login():
    try:
        if not security.same_origin_ok():
            return jsonify({"success": False, "message": "Request blocked (cross-origin)."}), 403
        data = request.get_json(silent=True) or {}
        operator = str(data.get("id", data.get("operator", ""))).strip()
        password = str(data.get("pass", data.get("password", "")))
        if not operator or not password:
            return jsonify({"success": False, "message": "Please enter ID and Password."}), 400
        if not security.rate_limit_check(operator):
            return jsonify({"success": False,
                            "message": "Too many failed attempts. Try again shortly."}), 429
        role = security.authenticate(operator, password)
        if not role:
            security.rate_limit_register_failure(operator)
            return jsonify({"success": False, "message": "Incorrect ID or password."}), 401
        security.rate_limit_clear(operator)
        session.clear()
        session["operator"] = operator
        session["role"]     = role
        return jsonify({"success": True, "operator": operator, "role": role}), 200
    except Exception as e:
        log.exception("login failed: %s", e)
        return jsonify({"success": False, "message": "An internal server error occurred."}), 500


@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"success": True}), 200


@app.route("/api/session", methods=["GET"])
def session_status():
    if session.get("operator"):
        return jsonify({"success": True, "logged_in": True,
                        "operator": session.get("operator"),
                        "role": session.get("role", "operator")}), 200
    return jsonify({"success": True, "logged_in": False}), 200


# ── dashboard state ───────────────────────────────────────────────────────────
@app.route("/api/npi_state", methods=["GET"])
def get_state():
    try:
        if not os.path.isfile(STATE_FILE):
            return jsonify({"success": True, "state": None}), 200
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            state = json.load(f)
        return jsonify({"success": True, "state": state}), 200
    except Exception as e:
        log.exception("get_state failed: %s", e)
        return jsonify({"success": False, "message": "Could not read saved state."}), 500


@app.route("/api/npi_state", methods=["POST"])
@security.login_required
def save_state():
    try:
        data = request.get_json(silent=True) or {}
        state = data.get("state")
        if state is None or not isinstance(state, (dict, list)):
            return jsonify({"success": False, "message": "Invalid state payload."}), 400
        # Atomic write (temp file + replace) so a crash mid-write can't corrupt
        # the saved dashboard data.
        fd, tmp = tempfile.mkstemp(dir=BASE_DIR, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(state, f, ensure_ascii=False)
            os.replace(tmp, STATE_FILE)
        finally:
            if os.path.exists(tmp):
                try: os.remove(tmp)
                except Exception: pass
        return jsonify({"success": True}), 200
    except Exception as e:
        log.exception("save_state failed: %s", e)
        return jsonify({"success": False, "message": "Could not save state."}), 500


if __name__ == "__main__":
    debug_env = os.environ.get("FLASK_DEBUG", "0").lower() in ("1", "true", "yes")
    port      = int(os.environ.get("PORT", "5001"))
    # Default to 0.0.0.0 (all network interfaces), not 127.0.0.1 (loopback
    # only). 127.0.0.1 means ONLY this PC can reach the server — other PCs
    # on the LAN would get "connection refused" even if they typed the
    # right address, which is why edits never showed up on other machines.
    host      = os.environ.get("HOST", "0.0.0.0")
    if debug_env:
        log.warning("Dev server with debug ON — never in production.")
    app.run(host=host, port=port, debug=debug_env)