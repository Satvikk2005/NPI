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
import re
import json
import time
import logging
import tempfile
import uuid

from flask import Flask, request, jsonify, session, send_from_directory
from werkzeug.utils import secure_filename

import security

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("npi_app")

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
TEMPLATES  = os.path.join(BASE_DIR, "templates")
STATE_FILE = os.path.join(BASE_DIR, "npi_state.json")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Attached documents (Manufacturing Readiness) are real files up to this size,
# uploaded as multipart/form-data and stored on disk — NOT base64 embedded in
# npi_state.json / the browser's localStorage. That embedding approach is what
# used to make attachments silently vanish: localStorage is capped around
# 5-10MB TOTAL for the whole app, so anything but a small file blew the
# budget the moment it was saved. A real upload has no such ceiling — the
# only limit is server disk space and the cap below.
MAX_UPLOAD_BYTES = 55 * 1024 * 1024  # 55MB — a little headroom over the
                                      # dashboard's 50MB client-side limit so
                                      # multipart overhead never gets rejected
                                      # right at the boundary.

app = Flask(__name__)
security.configure_app(app)   # secret key, hardened cookies, headers, size cap

# security.configure_app() sets Flask's MAX_CONTENT_LENGTH, which applies to
# EVERY request body app-wide (Flask has no simple per-route override across
# versions). That cap was sized for JSON state payloads, not file uploads, so
# it's raised here to fit MAX_UPLOAD_BYTES plus multipart/form overhead.
# Nothing else about the security layer changes.
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES + (2 * 1024 * 1024)


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


def _safe_path_segment(value, fallback="_"):
    """Collapse a project id / topic key down to a filesystem-safe folder
    name. Used for path SEGMENTS only (never the final filename, which goes
    through secure_filename separately) — this stops someone passing
    "../../etc" as project_id from escaping UPLOAD_DIR."""
    value = str(value or "")
    value = re.sub(r"[^A-Za-z0-9_\-]+", "_", value).strip("._")
    return value or fallback


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


# ── attached files (Manufacturing Readiness) ─────────────────────────────────
# Stored on disk under uploads/<project_id>/<topic_key>/<unique>-<filename>,
# never in npi_state.json — only the small reference below (name/size/url)
# goes there. This is the piece that actually removes the "vanishes on
# refresh" bug and the old ~2MB ceiling: nothing about the file's bytes ever
# touches localStorage or the JSON state file, so there's no small shared
# quota for it to blow through.
@app.route("/api/upload", methods=["POST"])
@security.login_required
def upload_file():
    try:
        f = request.files.get("file")
        if not f or not f.filename:
            return jsonify({"success": False, "message": "No file received."}), 400

        project_id = _safe_path_segment(request.form.get("project_id"), "project")
        topic_key  = _safe_path_segment(request.form.get("topic_key"), "topic")

        original_name = secure_filename(f.filename) or "file"
        # Prefix with a short unique id so re-uploading a same-named file
        # (or two people uploading "report.pdf" to the same section) never
        # silently overwrites another attachment.
        unique = uuid.uuid4().hex[:10]
        stored_name = f"{unique}-{original_name}"

        dest_dir = os.path.join(UPLOAD_DIR, project_id, topic_key)
        os.makedirs(dest_dir, exist_ok=True)
        dest_path = os.path.join(dest_dir, stored_name)

        f.save(dest_path)
        size = os.path.getsize(dest_path)

        if size > MAX_UPLOAD_BYTES:
            os.remove(dest_path)
            return jsonify({"success": False,
                             "message": f"File exceeds the {MAX_UPLOAD_BYTES // (1024*1024)}MB limit."}), 413

        url = f"/uploads/{project_id}/{topic_key}/{stored_name}"
        return jsonify({
            "success": True,
            "file": {
                "name": f.filename,   # original name shown in the UI
                "size": size,
                "url": url,
                "addedAt": time.strftime("%Y-%m-%dT%H:%M:%S"),
            },
        }), 200
    except Exception as e:
        log.exception("upload_file failed: %s", e)
        return jsonify({"success": False, "message": "Could not save the uploaded file."}), 500


@app.route("/api/upload", methods=["DELETE"])
@security.login_required
def delete_file():
    try:
        data = request.get_json(silent=True) or {}
        url = str(data.get("url", ""))
        # Only ever delete a path that resolves to inside UPLOAD_DIR — the
        # url the browser sends back is one we generated ourselves, but this
        # guards against a tampered/replayed request trying to delete
        # anything else on disk.
        rel = url[len("/uploads/"):] if url.startswith("/uploads/") else ""
        if not rel:
            return jsonify({"success": False, "message": "Invalid file reference."}), 400
        target = os.path.abspath(os.path.join(UPLOAD_DIR, rel))
        if not target.startswith(os.path.abspath(UPLOAD_DIR) + os.sep):
            return jsonify({"success": False, "message": "Invalid file reference."}), 400
        if os.path.isfile(target):
            os.remove(target)
        return jsonify({"success": True}), 200
    except Exception as e:
        log.exception("delete_file failed: %s", e)
        return jsonify({"success": False, "message": "Could not remove the file."}), 500


@app.route("/uploads/<path:filepath>", methods=["GET"])
def serve_upload(filepath):
    # Open like GET /api/npi_state (a team view, no login needed to VIEW) —
    # send_from_directory itself rejects any path that tries to escape
    # UPLOAD_DIR (returns 404), so this is safe against path traversal.
    directory, filename = os.path.split(filepath)
    return send_from_directory(os.path.join(UPLOAD_DIR, directory), filename)


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