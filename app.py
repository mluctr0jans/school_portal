"""School portal application."""

import base64
import binascii
import hashlib
import hmac
import json
import os
import sqlite3
import time
from pathlib import Path

from flask import Flask, jsonify, make_response, render_template, request
from werkzeug.security import check_password_hash, generate_password_hash


JWT_SECRET = os.environ.get("JWT_SECRET", "")
FLAG = os.environ.get("FLAG", "")
if not JWT_SECRET or not FLAG:
    raise RuntimeError("Set JWT_SECRET and FLAG in the environment before starting the portal.")

DATABASE_PATH = os.environ.get("DATABASE_PATH", "/data/portal.sqlite3")
STUDENT_USERNAME = os.environ.get("STUDENT_USERNAME", "student")
STUDENT_PASSWORD = os.environ.get("STUDENT_PASSWORD", "student123")
TOKEN_TTL_SECONDS = 60 * 60

app = Flask(__name__)


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    return base64.b64decode(padded, altchars=b"-_", validate=True)


def _encode_jwt(claims: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    header_part = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    claims_part = _b64url_encode(json.dumps(claims, separators=(",", ":")).encode())
    signed_part = f"{header_part}.{claims_part}"
    signature = hmac.new(JWT_SECRET.encode(), signed_part.encode(), hashlib.sha256).digest()
    return f"{signed_part}.{_b64url_encode(signature)}"


def _decode_jwt(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Malformed token")

    header = json.loads(_b64url_decode(parts[0]))
    claims = json.loads(_b64url_decode(parts[1]))
    if not isinstance(header, dict) or header.get("alg") != "HS256":
        raise ValueError("Unsupported token algorithm")
    if not isinstance(claims, dict):
        raise ValueError("Malformed token claims")

    signed_part = f"{parts[0]}.{parts[1]}"
    expected = hmac.new(JWT_SECRET.encode(), signed_part.encode(), hashlib.sha256).digest()
    supplied = _b64url_decode(parts[2])
    if not hmac.compare_digest(expected, supplied):
        raise ValueError("Invalid token signature")

    expiry = claims.get("exp")
    if not isinstance(expiry, (int, float)) or expiry <= time.time():
        raise ValueError("Token has expired")
    if not all(isinstance(claims.get(key), str) for key in ("sub", "username", "role")):
        raise ValueError("Required token claims are missing")
    return claims


def _connect_db() -> sqlite3.Connection:
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def _initialize_database() -> None:
    Path(DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)
    with _connect_db() as connection:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL
            )"""
        )
        connection.execute(
            "INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (STUDENT_USERNAME, generate_password_hash(STUDENT_PASSWORD), "student"),
        )


def _request_identity():
    token = request.cookies.get("access_token")
    if not token:
        return None, "Sign in with the student account first."
    try:
        return _decode_jwt(token), None
    except (ValueError, TypeError, binascii.Error, json.JSONDecodeError, UnicodeError):
        return None, "The access token is invalid or expired."


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/healthz")
def healthz():
    return jsonify(status="ok")


@app.post("/api/login")
def login():
    body = request.get_json(silent=True) or {}
    username = body.get("username", "")
    password = body.get("password", "")
    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify(error="Invalid username or password."), 401
    with _connect_db() as connection:
        user = connection.execute(
            "SELECT id, username, password_hash, role FROM users WHERE username = ?",
            (username,),
        ).fetchone()

    if user is None or not check_password_hash(user["password_hash"], password):
        return jsonify(error="Invalid username or password."), 401

    now = int(time.time())
    token = _encode_jwt(
        {
            "sub": str(user["id"]),
            "username": user["username"],
            "role": user["role"],
            "iat": now,
            "exp": now + TOKEN_TTL_SECONDS,
        }
    )
    response = make_response(
        jsonify(
            access_token=token,
            user={"username": user["username"], "role": user["role"]},
        )
    )
    response.set_cookie(
        "access_token",
        token,
        max_age=TOKEN_TTL_SECONDS,
        httponly=False,
        secure=False,
        samesite="Lax",
    )
    return response


@app.get("/api/me")
def me():
    identity, error = _request_identity()
    if identity is None:
        return jsonify(error=error), 401
    return jsonify(user={key: identity[key] for key in ("username", "role")})


@app.post("/api/logout")
def logout():
    response = make_response(jsonify(status="signed out"))
    response.delete_cookie("access_token", samesite="Lax")
    return response


@app.get("/admin/dashboard")
def admin_dashboard():
    identity, error = _request_identity()
    if identity is None:
        response = make_response(render_template("access_denied.html", message=error), 401)
        return response
    if identity["role"] != "admin":
        response = make_response(
            render_template(
                "access_denied.html",
                message="Your account does not have administrator privileges.",
            ),
            403,
        )
        return response
    return render_template("dashboard.html", username=identity["username"], flag=FLAG)


def initialize() -> None:
    _initialize_database()


initialize()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
