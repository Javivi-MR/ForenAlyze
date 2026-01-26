import os

from werkzeug.security import generate_password_hash

from app.analysis import dashboard as dashboard_mod
from app.extensions import db
from app.models import Alert, Analysis, File, User


def _create_admin_user():
    admin = User(
        username="admin",
        password=generate_password_hash("admin1234"),
        is_admin=True,
    )
    db.session.add(admin)
    db.session.commit()
    return admin


def _login(client, username: str, password: str):
    return client.post(
        "/auth/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )


def test_admin_can_create_user_via_dashboard(app, client):
    # Preparamos un admin y lo autenticamos
    with app.app_context():
        _create_admin_user()

    resp = _login(client, "admin", "admin1234")
    assert resp.status_code == 200

    # Enviamos el formulario de creación de usuario
    resp = client.post(
        "/admin/users",
        data={
            "action": "create",
            "username": "newuser",
            "password": "password123",
            "confirm_password": "password123",
            "is_admin": "on",
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200

    # Verificamos que el usuario se ha creado en la base de datos
    with app.app_context():
        created = User.query.filter_by(username="newuser").first()
        assert created is not None
        assert created.is_admin is True


def test_non_admin_cannot_access_admin_users(app, client):
    # Usuario normal
    with app.app_context():
        user = User(
            username="normal",
            password=generate_password_hash("password123"),
            is_admin=False,
        )
        db.session.add(user)
        db.session.commit()

    resp = _login(client, "normal", "password123")
    assert resp.status_code == 200

    resp = client.get("/admin/users", follow_redirects=True)
    # Debe redirigir al dashboard; comprobamos que ha llegado al Dashboard
    assert resp.status_code == 200
    assert b"Dashboard" in resp.data


def test_upload_creates_file_analysis_and_alert(app, client, monkeypatch):
    # Preparamos usuario y login
    with app.app_context():
        user = User(
            username="uploader",
            password=generate_password_hash("password123"),
            is_admin=False,
        )
        db.session.add(user)
        db.session.commit()

    resp = _login(client, "uploader", "password123")
    assert resp.status_code == 200

    # Stub del análisis para no depender de herramientas externas
    def fake_analyze(path, mime_hint=None):  # pragma: no cover - lógica trivial
        return {
            "md5": "dummy-md5",
            "sha1": "dummy-sha1",
            "sha256": "dummy-sha256",
            "mime_type": mime_hint or "image/png",
            "yara_result": None,
            "antivirus_result": None,
            "virustotal_result": None,
            "macro_detected": "no",
            "stego_detected": "no",
            "audio_analysis": None,
            "sandbox_score": None,
            "final_verdict": "clean",
            "summary": "Test analysis summary",
            "engine_version": "test-engine",
            "ruleset_version": "test-rules",
            "additional_results": "{}",
        }

    class DummyThread:
        """Reemplazo de threading.Thread que ejecuta el target de forma síncrona."""

        def __init__(self, target, args=(), daemon=None):  # pragma: no cover
            self._target = target
            self._args = args

        def start(self):  # pragma: no cover
            self._target(*self._args)

    # Aplicamos los parches sobre el módulo del dashboard de análisis
    monkeypatch.setattr(dashboard_mod, "analyze_file", fake_analyze, raising=False)
    monkeypatch.setattr(dashboard_mod, "Thread", DummyThread)

    # Ruta a un fichero de ejemplo existente en los estáticos
    static_dir = os.path.join(app.root_path, "static")
    sample_path = os.path.join(static_dir, "tool.png")
    assert os.path.exists(sample_path)

    with open(sample_path, "rb") as f:
        resp = client.post(
            "/upload",
            data={"file": (f, "sample.png")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )

    # Debe volver al dashboard (200) tras el upload
    assert resp.status_code == 200
    assert b"Dashboard" in resp.data

    # Comprobamos que se ha creado File, Analysis y al menos una alerta de "Report ready"
    with app.app_context():
        uploaded_file = File.query.filter_by(filename_original="sample.png").first()
        assert uploaded_file is not None

        analysis = Analysis.query.filter_by(file_id=uploaded_file.id).first()
        assert analysis is not None

        alerts = Alert.query.filter_by(file_id=uploaded_file.id, analysis_id=analysis.id).all()
        assert alerts, "No alerts generated for uploaded file"
        titles = {a.title for a in alerts}
        assert "Report ready" in titles
