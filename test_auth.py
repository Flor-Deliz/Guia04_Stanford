import logging
import sqlite3

import pytest

import auth_app

EMAIL, PW = "flor@unsaac.edu.pe", "ClaveSegura#2026"


@pytest.fixture
def ctx(tmp_path, monkeypatch):
    monkeypatch.setattr(auth_app, "DB_PATH", str(tmp_path / "auth.db"))
    auth_app.init_db()
    reloj = {"t": 1_000_000.0}
    monkeypatch.setattr(auth_app, "now", lambda: reloj["t"])
    correos = []
    monkeypatch.setattr(auth_app, "enviar_correo", lambda e, t: correos.append(t))
    auth_app.app.config["TESTING"] = True
    cliente = auth_app.app.test_client()
    cliente.post("/register", json={"email": EMAIL, "password": PW})
    return cliente, reloj, correos, tmp_path / "auth.db"


def login(c, email=EMAIL, pw=PW, token=None):
    cab = {"Authorization": f"Bearer {token}"} if token else {}
    return c.post("/login", json={"email": email, "password": pw}, headers=cab)


def me(c, token):
    return c.get("/me", headers={"Authorization": f"Bearer {token}"})


def test_password_guardada_con_hash_lento(ctx):
    _, _, _, db = ctx
    h = sqlite3.connect(db).execute("SELECT pw_hash FROM users").fetchone()[0]
    assert h.startswith("scrypt:") and PW not in h


def test_login_valido_devuelve_token(ctx):
    c, *_ = ctx
    r = login(c)
    assert r.status_code == 200 and me(c, r.get_json()["token"]).status_code == 200


def test_credenciales_invalidas_mensaje_generico(ctx):
    c, *_ = ctx
    r1 = login(c, pw="incorrecta12345")
    r2 = login(c, email="noexiste@correo.com")
    assert r1.status_code == r2.status_code == 401
    assert r1.get_json() == r2.get_json()          # no revela si el correo existe


def test_fuerza_bruta_bloquea_por_cuenta_y_se_libera(ctx):
    c, reloj, *_ = ctx
    for _ in range(5):
        assert login(c, pw="mala-contraseña").status_code == 401
    assert login(c).status_code == 429             # ni la clave correcta pasa
    reloj["t"] += 31                               # primer bloqueo: 30 s
    assert login(c).status_code == 200


def test_bloqueo_progresivo(ctx):
    c, reloj, *_ = ctx
    for _ in range(5):
        login(c, pw="mala-contraseña")
    reloj["t"] += 31
    assert login(c, pw="mala-contraseña").status_code == 401   # 6.º fallo
    reloj["t"] += 31
    assert login(c).status_code == 429             # ahora el bloqueo dura 60 s
    reloj["t"] += 40
    assert login(c).status_code == 200


def test_limite_por_ip(ctx):
    c, *_ = ctx
    for i in range(20):
        login(c, email=f"usuario{i}@correo.com", pw="x" * 12)
    assert login(c).status_code == 429             # misma IP bloqueada


def test_sesion_expirada(ctx):
    c, reloj, *_ = ctx
    token = login(c).get_json()["token"]
    reloj["t"] += auth_app.SESSION_TTL + 1
    assert me(c, token).status_code == 401


def test_regeneracion_de_sesion(ctx):
    c, *_ = ctx
    viejo = login(c).get_json()["token"]
    nuevo = login(c, token=viejo).get_json()["token"]
    assert nuevo != viejo
    assert me(c, viejo).status_code == 401 and me(c, nuevo).status_code == 200


def test_logout_invalida_token(ctx):
    c, *_ = ctx
    t = login(c).get_json()["token"]
    c.post("/logout", headers={"Authorization": f"Bearer {t}"})
    assert me(c, t).status_code == 401


def test_cambio_de_password_revoca_sesiones(ctx):
    c, *_ = ctx
    t = login(c).get_json()["token"]
    r = c.post("/password/change", json={"actual": PW, "nueva": "OtraClave#2027x"},
               headers={"Authorization": f"Bearer {t}"})
    assert r.status_code == 200
    assert me(c, t).status_code == 401
    assert login(c).status_code == 401
    assert login(c, pw="OtraClave#2027x").status_code == 200


def test_reset_token_un_solo_uso(ctx):
    c, _, correos, _ = ctx
    c.post("/password/forgot", json={"email": EMAIL})
    token = correos[-1]
    assert c.post("/password/reset", json={"token": token, "nueva": "NuevaClave#2028x"}).status_code == 200
    assert c.post("/password/reset", json={"token": token, "nueva": "OtraMas#2029xx"}).status_code == 400
    assert login(c, pw="NuevaClave#2028x").status_code == 200


def test_reset_invalida_tokens_anteriores_y_sesiones(ctx):
    c, _, correos, _ = ctx
    sesion = login(c).get_json()["token"]
    c.post("/password/forgot", json={"email": EMAIL})
    c.post("/password/forgot", json={"email": EMAIL})
    viejo, nuevo = correos
    assert c.post("/password/reset", json={"token": viejo, "nueva": "NuevaClave#2028x"}).status_code == 400
    assert c.post("/password/reset", json={"token": nuevo, "nueva": "NuevaClave#2028x"}).status_code == 200
    assert me(c, sesion).status_code == 401


def test_reset_token_expirado(ctx):
    c, reloj, correos, _ = ctx
    c.post("/password/forgot", json={"email": EMAIL})
    reloj["t"] += auth_app.RESET_TTL + 1
    assert c.post("/password/reset", json={"token": correos[-1], "nueva": "NuevaClave#2028x"}).status_code == 400


def test_forgot_no_revela_si_el_correo_existe(ctx):
    c, *_ = ctx
    a = c.post("/password/forgot", json={"email": EMAIL})
    b = c.post("/password/forgot", json={"email": "noexiste@correo.com"})
    assert a.status_code == b.status_code == 202 and a.get_json() == b.get_json()


def test_logs_no_exponen_token_ni_password(ctx, caplog):
    c, _, correos, _ = ctx
    caplog.set_level(logging.INFO, logger="auth")
    c.post("/password/forgot", json={"email": EMAIL})
    c.post("/password/reset", json={"token": correos[-1], "nueva": "NuevaClave#2028x"})
    login(c, pw="mala-contraseña")
    assert correos[-1] not in caplog.text and "NuevaClave" not in caplog.text
    assert "mala-contraseña" not in caplog.text


# ---------------------------- prototipo web ----------------------------
def csrf_de(c):
    return c.get_cookie("csrf").value


def test_web_login_correcto_y_panel(ctx):
    c, *_ = ctx
    r = c.get("/")
    assert r.status_code == 200 and b"Iniciar sesi" in r.data
    r = c.post("/web/login", data={"csrf": csrf_de(c), "email": EMAIL, "password": PW})
    assert r.status_code == 302 and r.headers["Location"] == "/panel"
    cookie = r.headers.get("Set-Cookie", "")
    assert "sid=" in cookie and "HttpOnly" in cookie and "SameSite=Strict" in cookie
    panel = c.get("/panel")
    assert panel.status_code == 200 and EMAIL.encode() in panel.data


def test_web_login_invalido_mensaje_generico(ctx):
    c, *_ = ctx
    c.get("/")
    r1 = c.post("/web/login", data={"csrf": csrf_de(c), "email": EMAIL, "password": "incorrecta12345"})
    c.get("/")
    r2 = c.post("/web/login", data={"csrf": csrf_de(c), "email": "no@existe.com", "password": "incorrecta12345"})
    assert r1.status_code == r2.status_code == 401
    assert b"Credenciales inv" in r1.data and b"Credenciales inv" in r2.data
    assert "sid=" not in r1.headers.get("Set-Cookie", "")


def test_web_sin_csrf_rechazado(ctx):
    c, *_ = ctx
    r = c.post("/web/login", data={"email": EMAIL, "password": PW})
    assert r.status_code == 400


def test_web_bloqueo_por_fuerza_bruta(ctx):
    c, *_ = ctx
    for _ in range(5):
        c.get("/")
        c.post("/web/login", data={"csrf": csrf_de(c), "email": EMAIL, "password": "mala-contraseña"})
    c.get("/")
    r = c.post("/web/login", data={"csrf": csrf_de(c), "email": EMAIL, "password": PW})
    assert r.status_code == 429


def test_web_panel_requiere_sesion(ctx):
    c, *_ = ctx
    r = c.get("/panel")
    assert r.status_code == 302 and r.headers["Location"] == "/"


def test_web_xss_en_campo_email_se_escapa(ctx):
    c, *_ = ctx
    c.get("/")
    r = c.post("/web/login", data={"csrf": csrf_de(c), "email": '"><script>alert(1)</script>', "password": "x" * 12})
    assert b"<script>alert(1)</script>" not in r.data and b"&lt;script&gt;" in r.data


def test_web_logout_y_cambio_de_password(ctx):
    c, *_ = ctx
    c.get("/")
    c.post("/web/login", data={"csrf": csrf_de(c), "email": EMAIL, "password": PW})
    c.get("/panel")
    r = c.post("/web/password", data={"csrf": csrf_de(c), "actual": PW, "nueva": "OtraClave#2027x"})
    assert r.status_code == 200 and c.get("/panel").status_code == 302   # sesión revocada
    c.get("/")
    c.post("/web/login", data={"csrf": csrf_de(c), "email": EMAIL, "password": "OtraClave#2027x"})
    c.get("/panel")
    c.post("/web/logout", data={"csrf": csrf_de(c)})
    assert c.get("/panel").status_code == 302
