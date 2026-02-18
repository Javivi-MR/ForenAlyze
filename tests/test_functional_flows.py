import os

from werkzeug.security import generate_password_hash

from app.analysis import dashboard as dashboard_mod
from app.extensions import db
from app.models import Alert, Analysis, File, Log, User


def _create_admin_user():
    admin = User(
        username="admin",
        password=generate_password_hash("admin1234"),
        is_admin=True,
    )
    db.session.add(admin)
    db.session.commit()
    return admin


def _create_user(username: str, password: str = "password123", is_admin: bool = False) -> User:
    user = User(
        username=username,
        password=generate_password_hash(password),
        is_admin=is_admin,
    )
    db.session.add(user)
    db.session.commit()
    return user


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
        _create_user("normal")

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


def test_logs_view_admin_sees_all_entries(app, client):
    with app.app_context():
        admin = _create_admin_user()
        normal = _create_user("normal")

        admin_log = Log(
            user_id=admin.id,
            username=admin.username,
            action="login",
            resource="auth.login",
            status="success",
            message="Admin log entry",
        )
        user_log = Log(
            user_id=normal.id,
            username=normal.username,
            action="upload",
            resource="dashboard.upload",
            status="success",
            message="User log entry",
        )
        system_log = Log(
            user_id=None,
            username="system",
            action="system_maintenance",
            resource="system",
            status="info",
            message="System log entry",
        )
        db.session.add_all([admin_log, user_log, system_log])
        db.session.commit()

    resp = _login(client, "admin", "admin1234")
    assert resp.status_code == 200

    resp = client.get("/logs")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert "Admin log entry" in html
    assert "User log entry" in html
    assert "System log entry" in html


def test_logs_view_user_sees_only_own_entries(app, client):
    with app.app_context():
        user = _create_user("normal")
        other = _create_user("other")

        own_log = Log(
            user_id=user.id,
            username=user.username,
            action="upload",
            resource="dashboard.upload",
            status="success",
            message="Own log entry",
        )
        other_log = Log(
            user_id=other.id,
            username=other.username,
            action="upload",
            resource="dashboard.upload",
            status="success",
            message="Other log entry",
        )
        db.session.add_all([own_log, other_log])
        db.session.commit()

    resp = _login(client, "normal", "password123")
    assert resp.status_code == 200

    resp = client.get("/logs")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert "Own log entry" in html
    assert "Other log entry" not in html


def test_storage_view_shows_only_user_files(app, client):
    with app.app_context():
        user = _create_user("owner")
        other = _create_user("other")

        file_owner = File(
            user_id=user.id,
            filename_original="owner_file.docx",
            filename_stored="owner_file_1.docx",
            storage_path="/nonexistent/owner_file_1.docx",
            size=1234,
            file_type="DOCX",
            mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
        file_other = File(
            user_id=other.id,
            filename_original="other_file.docx",
            filename_stored="other_file_1.docx",
            storage_path="/nonexistent/other_file_1.docx",
            size=4321,
            file_type="DOCX",
            mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
        db.session.add_all([file_owner, file_other])
        db.session.commit()

    resp = _login(client, "owner", "password123")
    assert resp.status_code == 200

    resp = client.get("/storage")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert "owner_file.docx" in html
    assert "other_file.docx" not in html


def test_admin_can_delete_user_and_related_data(app, client, tmp_path):
    with app.app_context():
        admin = _create_admin_user()
        user = _create_user("to_delete")

        # Create a real file on disk to verify physical deletion
        upload_dir = tmp_path / "uploads"
        upload_dir.mkdir()
        file_path = upload_dir / "sample.bin"
        file_path.write_bytes(b"0123456789")
        size_bytes = file_path.stat().st_size

        file_obj = File(
            user_id=user.id,
            filename_original="sample.bin",
            filename_stored="sample_1.bin",
            storage_path=str(file_path),
            size=size_bytes,
            file_type="BIN",
            mime_type="application/octet-stream",
        )
        db.session.add(file_obj)
        db.session.flush()

        analysis = Analysis(
            file_id=file_obj.id,
            user_id=user.id,
            sha256="deadbeef",
            final_verdict="clean",
        )
        db.session.add(analysis)
        db.session.flush()

        alert = Alert(
            user_id=user.id,
            file_id=file_obj.id,
            analysis_id=analysis.id,
            title="Report ready",
            severity="info",
            description="Test alert",
            is_read=False,
        )
        log = Log(
            user_id=user.id,
            username=user.username,
            action="upload",
            resource="dashboard.upload",
            status="success",
            message="User upload log",
        )
        db.session.add_all([alert, log])
        db.session.commit()

        user_id = user.id
        file_id = file_obj.id
        analysis_id = analysis.id

    assert file_path.exists()

    # Login as admin and trigger deletion
    resp = _login(client, "admin", "admin1234")
    assert resp.status_code == 200

    resp = client.post(f"/admin/users/{user_id}/delete", follow_redirects=True)
    assert resp.status_code == 200

    with app.app_context():
        assert User.query.get(user_id) is None
        assert File.query.filter_by(user_id=user_id).count() == 0
        assert Analysis.query.filter_by(user_id=user_id).count() == 0
        assert (
            Alert.query.filter(
                (Alert.user_id == user_id)
                | (Alert.file_id == file_id)
                | (Alert.analysis_id == analysis_id)
            ).count()
            == 0
        )
        assert Log.query.filter_by(user_id=user_id).count() == 0

    # Physical file should be gone
    assert not file_path.exists()


def test_admin_cannot_delete_self_or_other_admin(app, client):
    with app.app_context():
        admin = _create_admin_user()
        other_admin = _create_user("other_admin", is_admin=True)
        admin_id = admin.id
        other_admin_id = other_admin.id

    resp = _login(client, "admin", "admin1234")
    assert resp.status_code == 200

    # Attempt to delete self
    resp = client.post(f"/admin/users/{admin_id}/delete", follow_redirects=True)
    assert resp.status_code == 200

    # Attempt to delete another admin
    resp = client.post(f"/admin/users/{other_admin_id}/delete", follow_redirects=True)
    assert resp.status_code == 200

    with app.app_context():
        assert User.query.get(admin_id) is not None
        assert User.query.get(other_admin_id) is not None


def test_analysis_report_owner_marks_alerts_as_read(app, client):
    with app.app_context():
        owner = _create_user("alice")
        file_obj = File(
            user_id=owner.id,
            filename_original="secret.docm",
            filename_stored="secret_1.docm",
            storage_path="/nonexistent/secret_1.docm",
            size=1024,
            file_type="DOCM",
            mime_type="application/vnd.ms-word.document.macroEnabled.12",
        )
        db.session.add(file_obj)
        db.session.flush()

        analysis = Analysis(
            file_id=file_obj.id,
            user_id=owner.id,
            sha256="abc123",
            final_verdict="clean",
        )
        db.session.add(analysis)
        db.session.flush()

        alert = Alert(
            user_id=owner.id,
            file_id=file_obj.id,
            analysis_id=analysis.id,
            title="Report ready",
            severity="info",
            description="Test alert",
            is_read=False,
        )
        owner.notifications = 2
        db.session.add(alert)
        db.session.commit()

        analysis_id = analysis.id
        alert_id = alert.id
        owner_id = owner.id

    resp = _login(client, "alice", "password123")
    assert resp.status_code == 200

    resp = client.get(f"/analysis/{analysis_id}/report")
    assert resp.status_code == 200
    assert b"secret.docm" in resp.data

    with app.app_context():
        updated_alert = Alert.query.get(alert_id)
        updated_owner = User.query.get(owner_id)
        assert updated_alert is not None and updated_alert.is_read is True
        assert updated_owner is not None and updated_owner.notifications == 1


def test_analysis_report_forbidden_for_other_user(app, client):
    with app.app_context():
        owner = _create_user("alice")
        other = _create_user("bob")

        file_obj = File(
            user_id=owner.id,
            filename_original="owner_only.docm",
            filename_stored="owner_only_1.docm",
            storage_path="/nonexistent/owner_only_1.docm",
            size=2048,
            file_type="DOCM",
            mime_type="application/vnd.ms-word.document.macroEnabled.12",
        )
        db.session.add(file_obj)
        db.session.flush()

        analysis = Analysis(
            file_id=file_obj.id,
            user_id=owner.id,
            sha256="def456",
            final_verdict="clean",
        )
        db.session.add(analysis)
        db.session.commit()

        analysis_id = analysis.id

    resp = _login(client, "bob", "password123")
    assert resp.status_code == 200

    resp = client.get(f"/analysis/{analysis_id}/report", follow_redirects=False)
    assert resp.status_code in (302, 303)
    location = resp.headers.get("Location", "")
    assert "/files" in location

