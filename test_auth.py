import sqlite3
import time

import pytest
from app import create_app, digest


@pytest.fixture
def setup(tmp_path):
    sent_tokens = []
    app = create_app({
        "TESTING": True,
        "DATABASE": str(tmp_path / "test.db"),
        "SECRET_KEY": "test-secret-key-not-for-production",
        "RESET_SENDER": lambda email, token: sent_tokens.append((email, token)),
    })
    client = app.test_client()

    def post(path, **fields):
        client.get(path)
        with client.session_transaction() as flask_session:
            fields["csrf"] = flask_session["csrf"]
        return client.post(path, data=fields, follow_redirects=False)

    post("/register", email="student@unsaac.edu.pe", password="Password12345!")
    return app, client, post, sent_tokens


def test_invalid_credentials_are_generic(setup):
    _app, _client, post, _tokens = setup
    response = post("/", email="student@unsaac.edu.pe", password="incorrecta")
    assert response.status_code == 401
    assert b"Correo o contrase" in response.data
    assert b"no existe" not in response.data.lower()


def test_brute_force_account_lockout(setup):
    _app, _client, post, _tokens = setup
    for _ in range(4):
        assert post("/", email="student@unsaac.edu.pe", password="incorrecta").status_code == 401
    response = post("/", email="student@unsaac.edu.pe", password="incorrecta")
    assert response.status_code == 429
    assert b"segundos" in response.data


def test_reset_token_is_single_use(setup):
    _app, _client, post, tokens = setup
    post("/forgot", email="student@unsaac.edu.pe")
    token = tokens[0][1]
    assert post("/reset", token=token, password="NewPassword123!").status_code == 302
    assert post("/reset", token=token, password="NewPassword123!").status_code == 400


def test_expired_session_is_rejected(setup):
    app, client, post, _tokens = setup
    assert post("/", email="student@unsaac.edu.pe", password="Password12345!").status_code == 302
    with sqlite3.connect(app.config["DATABASE"]) as connection:
        connection.execute("UPDATE sessions SET expires=0")
    assert client.get("/dashboard").status_code == 302


def test_institutional_email_policy(setup):
    _app, _client, post, _tokens = setup
    assert post("/register", email="student@gmail.com", password="Password12345!").status_code == 400
    assert post("/register", email="another@estudiantes.unsaac.edu.pe", password="Password12345!").status_code == 200


def test_csrf_is_required(setup):
    _app, client, _post, _tokens = setup
    response = client.post("/", data={"email": "student@unsaac.edu.pe", "password": "Password12345!"})
    assert response.status_code == 400


def test_login_rotates_session_identifier(setup):
    _app, client, post, _tokens = setup
    client.get("/")
    with client.session_transaction() as flask_session:
        old_sid = flask_session.get("sid")
    assert post("/", email="student@unsaac.edu.pe", password="Password12345!").status_code == 302
    with client.session_transaction() as flask_session:
        new_sid = flask_session.get("sid")
    assert new_sid and new_sid != old_sid


def test_password_change_revokes_all_sessions(setup):
    app, client, post, _tokens = setup
    assert post("/", email="student@unsaac.edu.pe", password="Password12345!").status_code == 302
    client.get("/change")
    with client.session_transaction() as flask_session:
        csrf = flask_session["csrf"]
    response = client.post("/change", data={
        "csrf": csrf,
        "current": "Password12345!",
        "password": "ChangedPassword123!",
    })
    assert response.status_code == 302
    with sqlite3.connect(app.config["DATABASE"]) as connection:
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
    assert client.get("/dashboard").status_code == 302


def test_reset_token_expires(setup):
    app, _client, post, tokens = setup
    post("/forgot", email="student@unsaac.edu.pe")
    token = tokens[0][1]
    with sqlite3.connect(app.config["DATABASE"]) as connection:
        connection.execute("UPDATE resets SET expires=0 WHERE token=?", (digest(token),))
    assert post("/reset", token=token, password="NewPassword123!").status_code == 400


def test_reset_invalidates_existing_sessions(setup):
    app, client, post, tokens = setup
    post("/", email="student@unsaac.edu.pe", password="Password12345!")
    post("/forgot", email="student@unsaac.edu.pe")
    token = tokens[0][1]
    assert post("/reset", token=token, password="NewPassword123!").status_code == 302
    with sqlite3.connect(app.config["DATABASE"]) as connection:
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0


def test_registration_duplicate_does_not_create_second_account(setup):
    app, _client, post, _tokens = setup
    response = post("/register", email="student@unsaac.edu.pe", password="Password12345!")
    assert response.status_code == 400
    with sqlite3.connect(app.config["DATABASE"]) as connection:
        assert connection.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1


def test_task_dashboard_requires_authentication(setup):
    _app, client, _post, _tokens = setup
    assert client.get("/dashboard").status_code == 302


def test_ip_rate_limit_across_different_accounts(setup):
    _app, _client, post, _tokens = setup
    # El límite por cuenta no se alcanza porque cada correo es distinto;
    # el límite compartido por IP debe activarse en el intento 20.
    for index in range(19):
        response = post("/", email=f"unknown{index}@campus.edu.pe", password="incorrecta")
        assert response.status_code == 401
    response = post("/", email="unknown19@campus.edu.pe", password="incorrecta")
    assert response.status_code == 429


def test_login_rejects_non_institutional_domain(setup):
    _app, _client, post, _tokens = setup
    assert post("/", email="user@gmail.com", password="Password12345!").status_code == 400


def test_security_headers_are_present(setup):
    _app, client, _post, _tokens = setup
    response = client.get("/")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Cache-Control"] == "no-store"
