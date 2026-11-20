"""Aula Segura / TaskSecure - prototipo académico de autenticación segura."""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import smtplib
import sqlite3
import time
from email.message import EmailMessage
from pathlib import Path
from typing import Callable

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from flask import Flask, abort, g, redirect, render_template, request, session
from werkzeug.middleware.proxy_fix import ProxyFix

PASSWORD_HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
DUMMY_HASH = PASSWORD_HASHER.hash(secrets.token_urlsafe(32))
SESSION_TTL = 30 * 60
RESET_TTL = 15 * 60


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def create_app(config: dict | None = None) -> Flask:
    app = Flask(__name__)
    configured_secret = os.getenv("SECRET_KEY") or (config or {}).get("SECRET_KEY")
    if os.getenv("PRODUCTION") == "1" and not configured_secret:
        raise RuntimeError("SECRET_KEY es obligatoria en producción")
    app.config.update(
        SECRET_KEY=configured_secret or secrets.token_hex(32),
        DATABASE=os.getenv("DATABASE", "tasksecure.db"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.getenv("PRODUCTION") == "1",
        PERMANENT_SESSION_LIFETIME=SESSION_TTL,
        MAX_CONTENT_LENGTH=16 * 1024,
        RESET_SENDER=None,
        ALLOWED_EMAIL_DOMAINS=("edu.pe",),
        TRUST_PROXY=os.getenv("TRUST_PROXY") == "1",
    )
    if config:
        app.config.update(config)
    # Activar solo cuando el servicio está detrás de un proxy conocido y configurado.
    if app.config.get("TRUST_PROXY"):
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

    def db() -> sqlite3.Connection:
        if "db" not in g:
            database = app.config["DATABASE"]
            if database != ":memory:":
                Path(database).parent.mkdir(parents=True, exist_ok=True)
            g.db = sqlite3.connect(database, timeout=15)
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys=ON")
        return g.db

    @app.teardown_appcontext
    def close_db(_error):
        connection = g.pop("db", None)
        if connection is not None:
            connection.close()

    with app.app_context():
        db().executescript(
            """
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'student'
            );
            CREATE TABLE IF NOT EXISTS sessions(
                token TEXT PRIMARY KEY, uid INTEGER NOT NULL,
                expires INTEGER NOT NULL,
                FOREIGN KEY(uid) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS resets(
                token TEXT PRIMARY KEY, uid INTEGER NOT NULL,
                expires INTEGER NOT NULL,
                FOREIGN KEY(uid) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS limits(
                k TEXT PRIMARY KEY, n INTEGER NOT NULL, level INTEGER NOT NULL,
                until INTEGER NOT NULL, last INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS tasks(
                id INTEGER PRIMARY KEY, uid INTEGER NOT NULL, title TEXT NOT NULL,
                FOREIGN KEY(uid) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        db().commit()

    def audit(event: str, uid: int | None = None) -> None:
        # Nunca registrar contraseñas, tokens, cookies ni direcciones de recuperación.
        app.logger.warning("security_event=%s uid=%s", event, uid if uid is not None else "anonymous")

    def verify_password(encoded: str, candidate: str) -> bool:
        try:
            return PASSWORD_HASHER.verify(encoded, candidate)
        except (VerificationError, InvalidHashError):
            return False

    def email_input() -> str:
        return request.form.get("email", "").strip().lower()[:254]

    def institutional_email(email: str) -> bool:
        local, separator, domain = email.rpartition("@")
        allowed = tuple(d.lower().lstrip(".") for d in app.config["ALLOWED_EMAIL_DOMAINS"])
        domain = domain.lower()
        return bool(local and separator and any(domain == d or domain.endswith("." + d) for d in allowed))

    def rate_keys(email: str, kind: str = "login") -> list[tuple[str, int]]:
        # Cuenta + IP. request.remote_addr solo representa la IP real si el proxy
        # de despliegue está configurado como confiable.
        account_key = f"{kind}:account:{digest(email)}"
        ip_key = f"{kind}:ip:{digest(request.remote_addr or 'unknown')}"
        return [(account_key, 5), (ip_key, 20)]

    def blocked_seconds(keys: list[tuple[str, int]]) -> int:
        now = int(time.time())
        values = []
        for key, _threshold in keys:
            row = db().execute("SELECT until FROM limits WHERE k=?", (key,)).fetchone()
            if row:
                values.append(max(0, int(row["until"]) - now))
        return max(values, default=0)

    def record_attempt(keys: list[tuple[str, int]]) -> None:
        """Cuenta intentos y aplica espera progresiva (60 s hasta 900 s)."""
        now = int(time.time())
        connection = db()
        for key, threshold in keys:
            row = connection.execute("SELECT * FROM limits WHERE k=?", (key,)).fetchone()
            count, level = (row["n"], row["level"]) if row and now - row["last"] < 3600 else (0, 0)
            count += 1
            until = 0
            if count >= threshold:
                level += 1
                count = 0
                until = now + min(900, 60 * (2 ** min(level - 1, 4)))
            connection.execute(
                "INSERT OR REPLACE INTO limits(k,n,level,until,last) VALUES(?,?,?,?,?)",
                (key, count, level, until, now),
            )
        connection.commit()

    def clear_account_limit(email: str, kind: str = "login") -> None:
        db().execute("DELETE FROM limits WHERE k=?", (f"{kind}:account:{digest(email)}",))
        db().commit()

    def current_user():
        sid = session.get("sid", "")
        if not sid:
            return None
        return db().execute(
            "SELECT users.* FROM users JOIN sessions ON users.id=sessions.uid "
            "WHERE sessions.token=? AND sessions.expires>?",
            (digest(sid), int(time.time())),
        ).fetchone()

    @app.before_request
    def csrf_protection():
        if request.method == "POST":
            supplied = request.form.get("csrf", "")
            expected = session.get("csrf", "")
            if not expected or not hmac.compare_digest(expected, supplied):
                abort(400)
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)

    @app.after_request
    def security_headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'"
        )
        if request.is_secure or app.config.get("SESSION_COOKIE_SECURE"):
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    def page(title: str, msg: str = "", status: int = 200, **context):
        return render_template("index.html", title=title, msg=msg, **context), status

    def valid_password(password: str) -> bool:
        return 12 <= len(password) <= 128

    def send_reset_email(email: str, token: str) -> None:
        sender: Callable | None = app.config.get("RESET_SENDER")
        if sender:
            sender(email, token)
            return
        required = ("SMTP_USER", "SMTP_PASSWORD", "SMTP_HOST", "BASE_URL")
        if not all(os.getenv(name) for name in required):
            raise RuntimeError("Configuración SMTP incompleta")
        message = EmailMessage()
        message["Subject"] = "Recuperación de contraseña - Aula Segura"
        message["From"] = os.environ["SMTP_USER"]
        message["To"] = email
        # El fragmento no se envía al servidor ni aparece en los logs HTTP.
        message.set_content(os.environ["BASE_URL"].rstrip("/") + "/reset#token=" + token)
        with smtplib.SMTP_SSL(
            os.environ["SMTP_HOST"], int(os.getenv("SMTP_PORT", "465")), timeout=10
        ) as smtp:
            smtp.login(os.environ["SMTP_USER"], os.environ["SMTP_PASSWORD"])
            smtp.send_message(message)

    @app.route("/", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return page("Iniciar sesión")
        email = email_input()
        password = request.form.get("password", "")
        if not institutional_email(email):
            return page("Iniciar sesión", "Solo se permiten correos institucionales terminados en .edu.pe.", 400)
        keys = rate_keys(email)
        wait = blocked_seconds(keys)
        if wait:
            return page("Iniciar sesión", f"Acceso temporalmente bloqueado. Reintente en {wait} segundos.", 429)
        user_row = db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        candidate = password[:128]
        encoded = user_row["password"] if user_row else DUMMY_HASH
        valid = verify_password(encoded, candidate) and len(password) <= 128
        if not user_row or not valid:
            record_attempt(keys)
            audit("login_failed")
            wait = blocked_seconds(keys)
            message = f"Acceso temporalmente bloqueado. Reintente en {wait} segundos." if wait else "Correo o contraseña incorrectos."
            return page("Iniciar sesión", message, 429 if wait else 401)

        connection = db()
        old_sid = session.get("sid", "")
        if old_sid:
            connection.execute("DELETE FROM sessions WHERE token=?", (digest(old_sid),))
        sid = secrets.token_urlsafe(32)
        connection.execute(
            "INSERT INTO sessions(token,uid,expires) VALUES(?,?,?)",
            (digest(sid), user_row["id"], int(time.time()) + SESSION_TTL),
        )
        connection.commit()
        clear_account_limit(email)
        session.clear()
        session.permanent = True
        session.update(sid=sid, csrf=secrets.token_urlsafe(32))
        audit("login_success", user_row["id"])
        return redirect("/dashboard")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "GET":
            return page("Registro")
        email = email_input()
        password = request.form.get("password", "")
        if not institutional_email(email):
            return page("Registro", "Solo se permiten correos institucionales terminados en .edu.pe.", 400)
        if not valid_password(password):
            return page("Registro", "La contraseña debe tener entre 12 y 128 caracteres.", 400)
        # Control de abuso del endpoint: se limita por IP, sin contar el registro
        # exitoso como un fallo de autenticación de la cuenta.
        keys = rate_keys(email, "register")
        wait = blocked_seconds(keys)
        if wait:
            return page("Registro", f"Demasiadas solicitudes. Reintente en {wait} segundos.", 429)
        connection = db()
        connection.execute("BEGIN IMMEDIATE")
        # Limitar solicitudes de alta por cuenta/IP (incluye altas exitosas para
        # evitar automatización masiva, sin mezclarlo con fallos de login).
        record_attempt(keys)
        try:
            connection.execute(
                "INSERT INTO users(email,password) VALUES(?,?)",
                (email, PASSWORD_HASHER.hash(password)),
            )
            connection.commit()
            audit("registration_success")
            return page("Registro", "Cuenta creada correctamente. Ya puede iniciar sesión.")
        except sqlite3.IntegrityError:
            connection.rollback()
            audit("registration_duplicate")
            return page("Registro", "No fue posible completar el registro con esos datos.", 400)

    @app.route("/dashboard", methods=["GET", "POST"])
    def dashboard():
        user_row = current_user()
        if not user_row:
            return redirect("/")
        if request.method == "POST":
            title = request.form.get("task", "").strip()
            if not 3 <= len(title) <= 120:
                abort(400)
            db().execute("INSERT INTO tasks(uid,title) VALUES(?,?)", (user_row["id"], title))
            db().commit()
        tasks = db().execute("SELECT * FROM tasks WHERE uid=? ORDER BY id DESC", (user_row["id"],)).fetchall()
        return page("Panel de tareas", user=user_row, tasks=tasks)

    @app.post("/logout")
    def logout():
        sid = session.get("sid", "")
        if sid:
            db().execute("DELETE FROM sessions WHERE token=?", (digest(sid),))
            db().commit()
        session.clear()
        return redirect("/")

    def replace_password(uid: int, password: str) -> None:
        connection = db()
        connection.execute("UPDATE users SET password=? WHERE id=?", (PASSWORD_HASHER.hash(password), uid))
        connection.execute("DELETE FROM sessions WHERE uid=?", (uid,))
        connection.execute("DELETE FROM resets WHERE uid=?", (uid,))
        connection.commit()
        audit("password_updated", uid)

    @app.route("/change", methods=["GET", "POST"])
    def change_password():
        user_row = current_user()
        if not user_row:
            return redirect("/")
        if request.method == "GET":
            return page("Cambiar contraseña")
        current = request.form.get("current", "")[:128]
        new_password = request.form.get("password", "")
        if not verify_password(user_row["password"], current):
            audit("password_change_failed", user_row["id"])
            return page("Cambiar contraseña", "La contraseña actual es incorrecta.", 401)
        if not valid_password(new_password):
            return page("Cambiar contraseña", "La nueva contraseña debe tener entre 12 y 128 caracteres.", 400)
        replace_password(user_row["id"], new_password)
        session.clear()
        return redirect("/")

    @app.route("/forgot", methods=["GET", "POST"])
    def forgot_password():
        if request.method == "GET":
            return page("Recuperar contraseña")
        email = email_input()
        if not institutional_email(email):
            return page("Recuperar contraseña", "Si existe una cuenta elegible, recibirá instrucciones por correo.", 400)
        keys = rate_keys(email, "forgot")
        wait = blocked_seconds(keys)
        if wait:
            return page("Recuperar contraseña", "Si existe una cuenta elegible, recibirá instrucciones por correo.")
        record_attempt(keys)
        user_row = db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if user_row:
            token = secrets.token_urlsafe(32)
            connection = db()
            connection.execute("DELETE FROM resets WHERE uid=?", (user_row["id"],))
            connection.execute(
                "INSERT INTO resets(token,uid,expires) VALUES(?,?,?)",
                (digest(token), user_row["id"], int(time.time()) + RESET_TTL),
            )
            connection.commit()
            audit("reset_requested", user_row["id"])
            try:
                send_reset_email(email, token)
            except Exception:
                audit("mail_delivery_failed", user_row["id"])
        return page("Recuperar contraseña", "Si existe una cuenta elegible, recibirá instrucciones por correo.")

    @app.route("/reset", methods=["GET", "POST"])
    def reset_password():
        if request.method == "GET":
            return page("Restablecer contraseña")
        token = request.form.get("token", "")
        password = request.form.get("password", "")
        if not valid_password(password):
            return page("Restablecer contraseña", "La contraseña debe tener entre 12 y 128 caracteres.", 400)
        connection = db()
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT uid FROM resets WHERE token=? AND expires>?",
            (digest(token), int(time.time())),
        ).fetchone()
        if not row:
            connection.rollback()
            audit("reset_invalid_or_expired")
            return page("Restablecer contraseña", "Enlace inválido o expirado.", 400)
        uid = row["uid"]
        # Consumir token y cambiar contraseña en una transacción para impedir reutilización concurrente.
        connection.execute("DELETE FROM resets WHERE token=?", (digest(token),))
        connection.execute("UPDATE users SET password=? WHERE id=?", (PASSWORD_HASHER.hash(password), uid))
        connection.execute("DELETE FROM sessions WHERE uid=?", (uid,))
        connection.execute("DELETE FROM resets WHERE uid=?", (uid,))
        connection.commit()
        audit("password_reset_completed", uid)
        session.clear()
        return redirect("/")

    return app


if __name__ == "__main__":
    create_app().run()
