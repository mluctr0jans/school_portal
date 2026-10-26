import base64
import hashlib
import hmac
import json
import os
import sqlite3
import time

from flask import Flask, jsonify, make_response, render_template, request
from config import JWT_SECRET
from werkzeug.security import check_password_hash, generate_password_hash

DATABASE_PATH = os.environ.get("DATABASE_PATH", "portal.sqlite3")
STUDENT_USERNAME = os.environ.get("STUDENT_USERNAME", "student")
STUDENT_PASSWORD = os.environ.get("STUDENT_PASSWORD", "student123")
app = Flask(__name__)


def connect_db():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    with connect_db() as connection:
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


def b64url_encode(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64url_decode(value):
    padded = value + "=" * (-len(value) % 4)
    return base64.b64decode(padded, altchars=b"-_", validate=True)


def encode_jwt(claims):
    header = {"alg": "HS256", "typ": "JWT"}
    header_part = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    claims_part = b64url_encode(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{header_part}.{claims_part}"
    signature = hmac.new(JWT_SECRET.encode(), signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{b64url_encode(signature)}"


def decode_jwt(token):
    header_part, claims_part, signature_part = token.split(".")
    header = json.loads(b64url_decode(header_part))
    claims = json.loads(b64url_decode(claims_part))
    if header.get("alg") != "HS256":
        raise ValueError("Unsupported token algorithm")
    signing_input = f"{header_part}.{claims_part}"
    expected = hmac.new(JWT_SECRET.encode(), signing_input.encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(expected, b64url_decode(signature_part)):
        raise ValueError("Invalid token signature")
    if claims.get("exp", 0) <= time.time():
        raise ValueError("Token has expired")
    return claims


def request_identity():
    token = request.cookies.get("access_token")
    if not token:
        return None
    try:
        return decode_jwt(token)
    except (ValueError, TypeError, json.JSONDecodeError):
        return None


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/login")
def login():
    body = request.get_json(silent=True) or {}
    username = body.get("username", "")
    password = body.get("password", "")
    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify(error="Invalid username or password."), 401
    with connect_db() as connection:
        user = connection.execute(
            "SELECT id, username, password_hash, role FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    if user is None or not check_password_hash(user["password_hash"], password):
        return jsonify(error="Invalid username or password."), 401

    now = int(time.time())
    token = encode_jwt({
        "sub": str(user["id"]),
        "username": user["username"],
        "role": user["role"],
        "iat": now,
        "exp": now + 3600,
    })
    response = make_response(jsonify(
        access_token=token,
        user={"username": user["username"], "role": user["role"]},
    ))
    response.set_cookie("access_token", token, max_age=3600, httponly=False, secure=False, samesite="Lax")
    return response


@app.get("/api/me")
def me():
    identity = request_identity()
    if identity is None:
        return jsonify(error="Sign in first."), 401
    return jsonify(user={"username": identity["username"], "role": identity["role"]})


@app.post("/api/logout")
def logout():
    response = make_response(jsonify(status="signed out"))
    response.delete_cookie("access_token", samesite="Lax")
    return response


initialize_database()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
