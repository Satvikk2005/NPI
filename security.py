# ==============================================================================
# security.py  —  Hardening layer for the Eicher / VECV Assembly Line Guidance
# System.  This module is ADDITIVE.  It does not change any existing route's
# request/response contract; it only adds:
#
#   * Server-side session authentication (replaces client-side credential check)
#   * Password verification against hashed credentials (no plaintext anywhere)
#   * A @login_required decorator for state-changing (write) endpoints
#   * Same-origin (CSRF) enforcement for write endpoints
#   * A small in-memory login rate limiter (brute-force protection)
#   * Secure HTTP response headers (CSP, X-Frame-Options, etc.)
#   * Secret-key management (env -> file -> generated)
#
# All primitives use only the Python standard library so no new pip package is
# strictly required for auth to work.
# ==============================================================================

import os
import json
import hmac
import time
import hashlib
import binascii
import secrets
import logging
from functools import wraps

from flask import request, jsonify, session

log = logging.getLogger("security")

# ------------------------------------------------------------------------------
# Paths
# ------------------------------------------------------------------------------
_BASE_DIR       = os.path.dirname(os.path.abspath(__file__))
USERS_FILE      = os.path.join(_BASE_DIR, "auth_users.json")
SECRET_KEY_FILE = os.path.join(_BASE_DIR, ".secret_key")

# ------------------------------------------------------------------------------
# Secret key: environment first, then a persisted local file, then generate one.
# Persisting means sessions survive a server restart (operators stay logged in).
# ------------------------------------------------------------------------------
def get_secret_key():
    env = os.environ.get("SECRET_KEY")
    if env:
        return env
    if os.path.isfile(SECRET_KEY_FILE):
        try:
            with open(SECRET_KEY_FILE, "r", encoding="utf-8") as f:
                val = f.read().strip()
                if val:
                    return val
        except Exception:
            pass
    val = secrets.token_hex(32)
    try:
        with open(SECRET_KEY_FILE, "w", encoding="utf-8") as f:
            f.write(val)
        try:
            os.chmod(SECRET_KEY_FILE, 0o600)  # best-effort on POSIX; no-op semantics on Windows
        except Exception:
            pass
    except Exception:
        log.warning("Could not persist secret key; sessions will reset on restart.")
    return val


# ------------------------------------------------------------------------------
# Password hashing / verification  (PBKDF2-HMAC-SHA256, stdlib only)
# Stored format:  pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>
# ------------------------------------------------------------------------------
_PBKDF2_ITER = 240000

def hash_password(password):
    salt = os.urandom(16)
    dk   = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PBKDF2_ITER)
    return "pbkdf2_sha256${}${}${}".format(
        _PBKDF2_ITER, binascii.hexlify(salt).decode(), binascii.hexlify(dk).decode()
    )

def verify_password(password, stored):
    try:
        algo, iters, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"),
            binascii.unhexlify(salt_hex), int(iters)
        )
        return hmac.compare_digest(binascii.hexlify(dk).decode(), hash_hex)
    except Exception:
        return False


# ------------------------------------------------------------------------------
# User store
# ------------------------------------------------------------------------------
def load_users():
    if not os.path.isfile(USERS_FILE):
        log.error("auth_users.json not found at %s — no one will be able to log in.", USERS_FILE)
        return {}
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        log.error("Failed to read auth_users.json: %s", e)
        return {}


def authenticate(operator_id, password):
    """Return the user's role string on success, or None on failure."""
    users = load_users()
    rec   = users.get(operator_id)
    if not rec:
        # Perform a dummy hash to keep timing roughly constant (avoid user enumeration)
        verify_password(password, "pbkdf2_sha256$1$00$00")
        return None
    if verify_password(password, rec.get("hash", "")):
        return rec.get("role", "operator")
    return None


# ------------------------------------------------------------------------------
# In-memory login rate limiter (per operator-id + client ip).
# Blocks after MAX_ATTEMPTS failures within WINDOW seconds.
# In-memory is sufficient for a single-process plant server; note it resets on
# restart and is per-worker if you run multiple workers.
# ------------------------------------------------------------------------------
_MAX_ATTEMPTS = 8
_WINDOW       = 300      # 5 minutes
_attempts     = {}       # key -> [timestamps]

def _rl_key(operator_id):
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "?").split(",")[0].strip()
    return "{}|{}".format(ip, (operator_id or "").lower())

def rate_limit_check(operator_id):
    key = _rl_key(operator_id)
    now = time.time()
    hits = [t for t in _attempts.get(key, []) if now - t < _WINDOW]
    _attempts[key] = hits
    return len(hits) < _MAX_ATTEMPTS

def rate_limit_register_failure(operator_id):
    key = _rl_key(operator_id)
    _attempts.setdefault(key, []).append(time.time())
    # Opportunistic cleanup so the dict cannot grow without bound: drop any keys
    # whose most recent failure is older than the window.
    if len(_attempts) > 5000:
        now = time.time()
        for k in list(_attempts.keys()):
            if not _attempts[k] or now - _attempts[k][-1] > _WINDOW:
                _attempts.pop(k, None)

def rate_limit_clear(operator_id):
    _attempts.pop(_rl_key(operator_id), None)


# ------------------------------------------------------------------------------
# Same-origin (CSRF) check for state-changing requests.
# We do NOT need a token because:
#   * session cookie is SameSite=Lax + HttpOnly
#   * write endpoints require JSON content-type (a cross-site HTML form cannot
#     forge that without a CORS preflight, which we never allow)
#   * additionally we verify the Origin/Referer header matches our own host.
# The check only REJECTS when an Origin/Referer is present and mismatched, so it
# never breaks the legitimate same-origin front-end.
# ------------------------------------------------------------------------------
def _host_matches(url_value):
    if not url_value:
        return None  # unknown
    try:
        # crude host extraction: scheme://host[:port]/...
        after = url_value.split("://", 1)[-1]
        host  = after.split("/", 1)[0]
        return host == request.host
    except Exception:
        return False

def same_origin_ok():
    origin  = request.headers.get("Origin")
    referer = request.headers.get("Referer")
    for candidate in (origin, referer):
        res = _host_matches(candidate)
        if res is True:
            return True
        if res is False:
            return False
    # Neither header present (e.g. server-to-server tooling). Browsers always
    # send Origin on cross-site POST, so absence is not a browser CSRF vector.
    return True


# ------------------------------------------------------------------------------
# Decorators
# ------------------------------------------------------------------------------
def login_required(view):
    """Require an authenticated session for write/mutating endpoints."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("operator"):
            return jsonify({"success": False,
                            "message": "Authentication required. Please log in."}), 401
        if not same_origin_ok():
            return jsonify({"success": False,
                            "message": "Request blocked (cross-origin)."}), 403
        return view(*args, **kwargs)
    return wrapper


def admin_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("operator"):
            return jsonify({"success": False,
                            "message": "Authentication required. Please log in."}), 401
        if session.get("role") != "admin":
            return jsonify({"success": False,
                            "message": "Administrator privilege required."}), 403
        if not same_origin_ok():
            return jsonify({"success": False,
                            "message": "Request blocked (cross-origin)."}), 403
        return view(*args, **kwargs)
    return wrapper


# ------------------------------------------------------------------------------
# App configuration + security headers
# ------------------------------------------------------------------------------
def configure_app(app):
    app.secret_key = get_secret_key()

    secure_cookie = os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true"
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=secure_cookie,     # set env SESSION_COOKIE_SECURE=true behind HTTPS
        MAX_CONTENT_LENGTH=64 * 1024 * 1024,     # 64 MB cap on request bodies (DoS guard).
                                                  # Raised from 16 MB: every save re-sends the
                                                  # FULL dashboard state (not a diff), and an
                                                  # attached file is stored as base64 inline in
                                                  # that state (~1.33x its real size). With the
                                                  # 8 MB per-file client-side limit plus other
                                                  # projects/attachments already saved, a single
                                                  # save could exceed 16 MB and get rejected —
                                                  # which looked like the upload "disappearing".
        JSON_SORT_KEYS=False,
    )

    @app.after_request
    def _apply_security_headers(resp):
        # Content-Security-Policy: the front-end uses inline styles/handlers and
        # Google Fonts, so we allow 'unsafe-inline' for style but keep script
        # locked to self + inline (the app ships its own inline bootstrap).
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com data:; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Permissions-Policy",
                                "geolocation=(), microphone=(), camera=()")
        resp.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        resp.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        # HSTS only meaningful over HTTPS; harmless header when served on HTTP but
        # we only emit it when the connection is secure.
        if request.is_secure:
            resp.headers.setdefault("Strict-Transport-Security",
                                    "max-age=31536000; includeSubDomains")
        # Remove the framework banner if present (info disclosure).
        resp.headers.pop("Server", None)
        return resp

    # Consistent JSON errors (no default framework pages / stack traces leak).
    from flask import jsonify as _jsonify

    def _json_error(message, code):
        return _jsonify({"success": False, "message": message}), code

    @app.errorhandler(400)
    def _e400(e):  return _json_error("Bad request.", 400)

    @app.errorhandler(401)
    def _e401(e):  return _json_error("Authentication required.", 401)

    @app.errorhandler(403)
    def _e403(e):  return _json_error("Forbidden.", 403)

    @app.errorhandler(404)
    def _e404(e):  return _json_error("Not found.", 404)

    @app.errorhandler(405)
    def _e405(e):  return _json_error("Method not allowed.", 405)

    @app.errorhandler(413)
    def _e413(e):  return _json_error("Request payload too large.", 413)

    @app.errorhandler(415)
    def _e415(e):  return _json_error("Unsupported media type — send JSON.", 415)

    @app.errorhandler(429)
    def _e429(e):  return _json_error("Too many requests. Please slow down.", 429)

    @app.errorhandler(500)
    def _e500(e):
        log.exception("Unhandled 500 error")
        return _json_error("An internal server error occurred.", 500)

    return app