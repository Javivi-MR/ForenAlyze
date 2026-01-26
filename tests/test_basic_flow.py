from werkzeug.security import generate_password_hash

from app.extensions import db
from app.models import User


def test_home_page_accessible(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"ForenAlyze" in resp.data


def test_about_page_accessible(client):
    resp = client.get("/about")
    assert resp.status_code == 200
    assert b"About" in resp.data or b"ForenAlyze" in resp.data


def test_login_page_loads(client):
    resp = client.get("/auth/login")
    assert resp.status_code == 200
    assert b"Sign in" in resp.data


def _create_test_user():
    """Crea un usuario de pruebas en la base de datos actual."""

    user = User(
        username="testuser",
        password=generate_password_hash("secret123"),
        is_admin=False,
    )
    db.session.add(user)
    db.session.commit()
    return user


def test_successful_login_redirects_to_dashboard(app, client):
    with app.app_context():
        _create_test_user()

    resp = client.post(
        "/auth/login",
        data={"username": "testuser", "password": "secret123"},
        follow_redirects=False,
    )

    # Debe redirigir al dashboard
    assert resp.status_code in (301, 302)
    location = resp.headers.get("Location", "")
    assert "/dashboard" in location


def test_logout_requires_login_and_redirects_to_login(app, client):
    # Primero creamos usuario y hacemos login
    with app.app_context():
        _create_test_user()

    client.post(
        "/auth/login",
        data={"username": "testuser", "password": "secret123"},
        follow_redirects=True,
    )

    # Ahora llamamos a logout y comprobamos que redirige al login
    resp = client.get("/auth/logout", follow_redirects=False)
    assert resp.status_code in (301, 302)
    location = resp.headers.get("Location", "")
    assert "/auth/login" in location
