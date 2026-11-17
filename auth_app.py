"""App web de login resistente a ataques comunes (Ejercicio 1.2): API JSON + prototipo web.

Flask + SQLite. Contraseñas con scrypt (hash lento con sal), límite de intentos
por cuenta y por IP, bloqueo progresivo, mensajes genéricos, sesiones con
expiración, revocación al cambiar contraseña y regeneración de sesión al iniciar.
"""
import hashlib
import logging
import os
import re
import secrets
import sqlite3
import time
from contextlib import closing
from functools import wraps

from flask import Flask, g, jsonify, make_response, redirect, render_template_string, request
from markupsafe import Markup
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024          # límite de tamaño de solicitud

DB_PATH = os.environ.get("AUTH_DB", "auth.db")
SESSION_TTL = 15 * 60        # 15 min
RESET_TTL = 10 * 60          # 10 min
WINDOW = 15 * 60             # ventana para contar intentos fallidos
MAX_FAILS_ACCOUNT = 5
MAX_FAILS_IP = 20
BASE_LOCK = 30               # segundos; se duplica con cada intento extra
MAX_LOCK = 15 * 60
HASH_METHOD = "scrypt"
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "0") == "1"   # poner 1 con HTTPS
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$")

log = logging.getLogger("auth")
DUMMY_HASH = generate_password_hash("dummy-password", method=HASH_METHOD)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    pw_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_h TEXT NOT NULL,
    ip TEXT NOT NULL,
    ts REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS reset_tokens (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at REAL NOT NULL
);
"""


def now():
    return time.time()


def sha(texto):
    return hashlib.sha256(texto.encode()).hexdigest()


def init_db():
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.executescript(SCHEMA)
        conn.commit()


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def cerrar_db(_exc):
    conexion = g.pop("db", None)
    if conexion is not None:
        conexion.close()


def enviar_correo(email, token):
    """Simula el envío del enlace de restablecimiento (en producción: SMTP)."""


def error(mensaje, codigo):
    return jsonify({"error": mensaje}), codigo


def datos_json():
    datos = request.get_json(silent=True)
    return datos if isinstance(datos, dict) else {}


def password_valida(pw):
    return isinstance(pw, str) and 10 <= len(pw) <= 128


def crear_sesion(user_id):
    token = secrets.token_urlsafe(32)
    db().execute(
        "INSERT INTO sessions VALUES (?,?,?)", (sha(token), user_id, now() + SESSION_TTL)
    )
    return token


def revocar_sesiones(user_id):
    db().execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))


def token_bearer():
    cabecera = request.headers.get("Authorization", "")
    if cabecera.startswith("Bearer "):
        return cabecera[7:]
    return request.cookies.get("sid")              # cookie HttpOnly del prototipo web


def requiere_sesion(f):
    @wraps(f)
    def envoltura(*args, **kwargs):
        token = token_bearer()
        if not token:
            return error("No autenticado", 401)
        fila = db().execute(
            "SELECT user_id, expires_at FROM sessions WHERE token_hash = ?", (sha(token),)
        ).fetchone()
        if fila is None:
            return error("No autenticado", 401)
        if fila["expires_at"] <= now():
            db().execute("DELETE FROM sessions WHERE token_hash = ?", (sha(token),))
            db().commit()
            return error("Sesión expirada", 401)
        g.user_id = fila["user_id"]
        return f(*args, **kwargs)
    return envoltura


def bloqueado(email_h, ip):
    t = now()
    desde = t - WINDOW
    fallos_ip = db().execute(
        "SELECT COUNT(*) FROM login_attempts WHERE ip = ? AND ts > ?", (ip, desde)
    ).fetchone()[0]
    if fallos_ip >= MAX_FAILS_IP:
        return True
    filas = db().execute(
        "SELECT ts FROM login_attempts WHERE email_h = ? AND ts > ? ORDER BY ts DESC",
        (email_h, desde),
    ).fetchall()
    if len(filas) >= MAX_FAILS_ACCOUNT:
        espera = min(BASE_LOCK * 2 ** (len(filas) - MAX_FAILS_ACCOUNT), MAX_LOCK)
        return filas[0]["ts"] + espera > t
    return False


def crear_usuario(email, pw):
    """Devuelve False si los datos no son válidos. No revela si el correo ya existía."""
    if not EMAIL_RE.match(email) or not password_valida(pw):
        return False
    try:
        db().execute(
            "INSERT INTO users (email, pw_hash) VALUES (?,?)",
            (email, generate_password_hash(pw, method=HASH_METHOD)),
        )
        db().commit()
    except sqlite3.IntegrityError:
        pass  # no revelar si el correo ya existe
    return True


def autenticar(email, pw):
    """Valida credenciales. Devuelve ('ok', token) | ('invalido', None) | ('bloqueado', None)."""
    email_h = sha(email)
    ip = request.remote_addr or "desconocida"

    if bloqueado(email_h, ip):
        log.warning("login_bloqueado regla=limite_intentos cuenta=%s ip=%s", email_h[:8], ip)
        return "bloqueado", None

    usuario = db().execute(
        "SELECT id, pw_hash FROM users WHERE email = ?", (email,)
    ).fetchone()
    # Se verifica siempre un hash (real o ficticio) para igualar tiempos de respuesta
    valido = check_password_hash(usuario["pw_hash"] if usuario else DUMMY_HASH, pw)
    if usuario is None or not valido:
        db().execute(
            "INSERT INTO login_attempts (email_h, ip, ts) VALUES (?,?,?)", (email_h, ip, now())
        )
        db().commit()
        log.warning("login_fallido regla=credenciales cuenta=%s ip=%s", email_h[:8], ip)
        return "invalido", None

    db().execute("DELETE FROM login_attempts WHERE email_h = ?", (email_h,))
    anterior = token_bearer()                      # regeneración del identificador de sesión
    if anterior:
        db().execute("DELETE FROM sessions WHERE token_hash = ?", (sha(anterior),))
    token = crear_sesion(usuario["id"])
    db().commit()
    log.info("login_exitoso usuario=%s", usuario["id"])
    return "ok", token


@app.post("/register")
def register():
    datos = datos_json()
    email = str(datos.get("email", "")).strip().lower()
    if not crear_usuario(email, datos.get("password")):
        return error("Datos inválidos (contraseña de 10 a 128 caracteres)", 400)
    return jsonify({"mensaje": "Solicitud recibida"}), 202


@app.post("/login")
def login():
    datos = datos_json()
    email, pw = datos.get("email"), datos.get("password")
    if not isinstance(email, str) or not isinstance(pw, str):
        return error("Credenciales inválidas", 401)
    estado, token = autenticar(email.strip().lower(), pw)
    if estado == "bloqueado":
        return error("Demasiados intentos. Inténtalo más tarde", 429)
    if estado == "invalido":
        return error("Credenciales inválidas", 401)
    return jsonify({"token": token, "expira_en": SESSION_TTL})


@app.post("/logout")
@requiere_sesion
def logout():
    db().execute("DELETE FROM sessions WHERE token_hash = ?", (sha(token_bearer()),))
    db().commit()
    return jsonify({"mensaje": "Sesión cerrada"})


@app.get("/me")
@requiere_sesion
def me():
    fila = db().execute("SELECT id, email FROM users WHERE id = ?", (g.user_id,)).fetchone()
    return jsonify({"id": fila["id"], "email": fila["email"]})


@app.post("/password/change")
@requiere_sesion
def cambiar_password():
    datos = datos_json()
    actual, nueva = datos.get("actual"), datos.get("nueva")
    if not password_valida(nueva) or not isinstance(actual, str):
        return error("Datos inválidos", 400)
    usuario = db().execute("SELECT pw_hash FROM users WHERE id = ?", (g.user_id,)).fetchone()
    if not check_password_hash(usuario["pw_hash"], actual):
        return error("Credenciales inválidas", 401)
    db().execute(
        "UPDATE users SET pw_hash = ? WHERE id = ?",
        (generate_password_hash(nueva, method=HASH_METHOD), g.user_id),
    )
    revocar_sesiones(g.user_id)                    # revocación de todas las sesiones
    db().commit()
    log.info("password_cambiada usuario=%s sesiones_revocadas=si", g.user_id)
    return jsonify({"mensaje": "Contraseña actualizada; inicia sesión de nuevo"})


@app.post("/password/forgot")
def olvide_password():
    email = str(datos_json().get("email", "")).strip().lower()
    usuario = db().execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    if usuario:
        db().execute("DELETE FROM reset_tokens WHERE user_id = ?", (usuario["id"],))  # invalida anteriores
        token = secrets.token_urlsafe(32)          # aleatorio, un solo uso
        db().execute(
            "INSERT INTO reset_tokens VALUES (?,?,?)", (sha(token), usuario["id"], now() + RESET_TTL)
        )
        db().commit()
        enviar_correo(email, token)
        log.info("reset_solicitado usuario=%s", usuario["id"])   # sin exponer el token
    return jsonify({"mensaje": "Si el correo existe, recibirás instrucciones"}), 202


@app.post("/password/reset")
def restablecer_password():
    datos = datos_json()
    token, nueva = datos.get("token"), datos.get("nueva")
    if not isinstance(token, str) or not password_valida(nueva):
        return error("Solicitud inválida", 400)
    fila = db().execute(
        "SELECT user_id, expires_at FROM reset_tokens WHERE token_hash = ?", (sha(token),)
    ).fetchone()
    if fila is None or fila["expires_at"] <= now():
        log.warning("reset_rechazado regla=token_invalido_o_expirado")
        return error("Solicitud inválida", 400)
    db().execute(
        "UPDATE users SET pw_hash = ? WHERE id = ?",
        (generate_password_hash(nueva, method=HASH_METHOD), fila["user_id"]),
    )
    db().execute("DELETE FROM reset_tokens WHERE user_id = ?", (fila["user_id"],))  # un solo uso
    revocar_sesiones(fila["user_id"])
    db().commit()
    log.info("password_restablecida usuario=%s", fila["user_id"])
    return jsonify({"mensaje": "Contraseña restablecida"})


# ----------------------------------------------------------------------------
# Prototipo web (HTML renderizado en el servidor, sin JavaScript)
# ----------------------------------------------------------------------------
BASE = """<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ titulo }}</title>
<style>
body{font-family:Arial,Helvetica,sans-serif;background:#f1f3f6;margin:0;padding:40px 12px;color:#1f2937}
.tarjeta{max-width:380px;margin:0 auto;background:#fff;padding:28px 30px;border-radius:8px;border:1px solid #d9dee5}
h1{font-size:22px;margin:0 0 6px 0;color:#8c1515}
.sub{color:#6b7280;font-size:13px;margin:0 0 18px 0}
label{display:block;font-size:13px;font-weight:bold;margin:14px 0 4px 0}
input{width:100%;box-sizing:border-box;padding:9px;border:1px solid #9ca3af;border-radius:4px;font-size:14px}
button{margin-top:20px;width:100%;padding:10px;background:#8c1515;color:#fff;border:0;border-radius:4px;font-size:15px;cursor:pointer}
.alerta{padding:9px 11px;border-radius:4px;font-size:13px;margin:0 0 6px 0}
.error{background:#fde8e8;color:#9b1c1c;border:1px solid #f5b5b5}
.ok{background:#e3f6e8;color:#166534;border:1px solid #a7e0b5}
.aviso{background:#fff4d6;color:#8a5a00;border:1px solid #f1d58a}
.pie{font-size:13px;margin-top:16px;color:#4b5563}
a{color:#8c1515}
</style></head><body><div class="tarjeta">{{ contenido }}</div></body></html>"""

LOGIN = """<h1>Iniciar sesión</h1><p class="sub">Portal académico seguro · UNSAAC</p>
{% if mensaje %}<p class="alerta {{ tipo }}" role="alert">{{ mensaje }}</p>{% endif %}
<form method="post" action="/web/login">
<input type="hidden" name="csrf" value="{{ csrf }}">
<label for="email">Correo institucional</label>
<input id="email" name="email" type="email" required maxlength="254" value="{{ email }}">
<label for="password">Contraseña</label>
<input id="password" name="password" type="password" required maxlength="128">
<button type="submit">Ingresar</button></form>
<p class="pie">¿No tienes cuenta? <a href="/registro">Regístrate</a></p>"""

REGISTRO = """<h1>Crear cuenta</h1><p class="sub">La contraseña debe tener de 10 a 128 caracteres</p>
{% if mensaje %}<p class="alerta {{ tipo }}" role="alert">{{ mensaje }}</p>{% endif %}
<form method="post" action="/web/registro">
<input type="hidden" name="csrf" value="{{ csrf }}">
<label for="email">Correo institucional</label>
<input id="email" name="email" type="email" required maxlength="254" value="{{ email }}">
<label for="password">Contraseña</label>
<input id="password" name="password" type="password" required minlength="10" maxlength="128">
<button type="submit">Registrarme</button></form>
<p class="pie">¿Ya tienes cuenta? <a href="/">Inicia sesión</a></p>"""

PANEL = """<h1>Panel del usuario</h1><p class="sub">Sesión autenticada</p>
<p class="alerta ok">Sesión iniciada como <b>{{ email }}</b>.</p>
<p class="pie">La sesión expira en {{ minutos }} min.</p>
{% if mensaje %}<p class="alerta {{ tipo }}" role="alert">{{ mensaje }}</p>{% endif %}
<form method="post" action="/web/password">
<input type="hidden" name="csrf" value="{{ csrf }}">
<label for="actual">Contraseña actual</label>
<input id="actual" name="actual" type="password" required maxlength="128">
<label for="nueva">Nueva contraseña</label>
<input id="nueva" name="nueva" type="password" required minlength="10" maxlength="128">
<button type="submit">Cambiar contraseña</button></form>
<form method="post" action="/web/logout">
<input type="hidden" name="csrf" value="{{ csrf }}">
<button type="submit">Cerrar sesión</button></form>"""


def pagina(plantilla, estado=200, titulo="Portal seguro", **ctx):
    """Renderiza con autoescape de Jinja2 y entrega un token CSRF (doble envío)."""
    csrf = secrets.token_urlsafe(16)
    ctx.setdefault("mensaje", None)
    ctx.setdefault("tipo", "error")
    ctx.setdefault("email", "")
    contenido = Markup(render_template_string(plantilla, csrf=csrf, **ctx))
    resp = make_response(render_template_string(BASE, titulo=titulo, contenido=contenido), estado)
    resp.set_cookie("csrf", csrf, httponly=True, samesite="Strict", secure=COOKIE_SECURE)
    return resp


def csrf_valido():
    enviado, cookie = request.form.get("csrf", ""), request.cookies.get("csrf", "")
    return bool(cookie) and secrets.compare_digest(enviado, cookie)


def sesion_activa():
    token = token_bearer()
    if not token:
        return None
    fila = db().execute(
        "SELECT user_id, expires_at FROM sessions WHERE token_hash = ?", (sha(token),)
    ).fetchone()
    return fila if fila and fila["expires_at"] > now() else None


def poner_sesion(resp, token):
    resp.set_cookie("sid", token, max_age=SESSION_TTL, httponly=True,
                    samesite="Strict", secure=COOKIE_SECURE)
    return resp


@app.get("/")
def inicio():
    if sesion_activa():
        return redirect("/panel")
    return pagina(LOGIN, titulo="Iniciar sesión")


@app.get("/registro")
def registro():
    return pagina(REGISTRO, titulo="Crear cuenta")


@app.post("/web/registro")
def web_registro():
    email = request.form.get("email", "").strip().lower()
    if not csrf_valido():
        return pagina(REGISTRO, 400, mensaje="Solicitud inválida. Recarga la página.")
    if not crear_usuario(email, request.form.get("password", "")):
        return pagina(REGISTRO, 400, mensaje="Datos inválidos. Revisa el correo y la contraseña.", email=email)
    return pagina(LOGIN, 202, mensaje="Solicitud recibida. Ya puedes iniciar sesión.", tipo="ok")


@app.post("/web/login")
def web_login():
    email = request.form.get("email", "").strip().lower()
    if not csrf_valido():
        return pagina(LOGIN, 400, mensaje="Solicitud inválida. Recarga la página.")
    estado, token = autenticar(email, request.form.get("password", ""))
    if estado == "ok":
        return poner_sesion(redirect("/panel"), token)
    if estado == "bloqueado":
        return pagina(LOGIN, 429, mensaje="Demasiados intentos. Inténtalo más tarde.", tipo="aviso", email=email)
    return pagina(LOGIN, 401, mensaje="Credenciales inválidas.", email=email)


@app.get("/panel")
def panel():
    sesion = sesion_activa()
    if not sesion:
        return redirect("/")
    usuario = db().execute("SELECT email FROM users WHERE id = ?", (sesion["user_id"],)).fetchone()
    minutos = max(0, int((sesion["expires_at"] - now()) // 60))
    return pagina(PANEL, titulo="Panel", email=usuario["email"], minutos=minutos)


@app.post("/web/password")
def web_password():
    sesion = sesion_activa()
    if not sesion:
        return redirect("/")
    usuario = db().execute("SELECT email, pw_hash FROM users WHERE id = ?", (sesion["user_id"],)).fetchone()
    if not csrf_valido():
        return pagina(PANEL, 400, email=usuario["email"], minutos=0, mensaje="Solicitud inválida.")
    actual, nueva = request.form.get("actual", ""), request.form.get("nueva", "")
    if not password_valida(nueva) or not check_password_hash(usuario["pw_hash"], actual):
        return pagina(PANEL, 400, email=usuario["email"],
                      minutos=max(0, int((sesion["expires_at"] - now()) // 60)),
                      mensaje="No se pudo cambiar la contraseña. Revisa los datos.")
    db().execute("UPDATE users SET pw_hash = ? WHERE id = ?",
                 (generate_password_hash(nueva, method=HASH_METHOD), sesion["user_id"]))
    revocar_sesiones(sesion["user_id"])
    db().commit()
    log.info("password_cambiada usuario=%s sesiones_revocadas=si", sesion["user_id"])
    resp = pagina(LOGIN, mensaje="Contraseña actualizada. Inicia sesión de nuevo.", tipo="ok")
    resp.delete_cookie("sid")
    return resp


@app.post("/web/logout")
def web_logout():
    if csrf_valido() and token_bearer():
        db().execute("DELETE FROM sessions WHERE token_hash = ?", (sha(token_bearer()),))
        db().commit()
    resp = redirect("/")
    resp.delete_cookie("sid")
    return resp


@app.after_request
def cabeceras_seguridad(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Cache-Control"] = "no-store"
    return resp



if __name__ == "__main__":
    init_db()
    app.run(debug=False)
