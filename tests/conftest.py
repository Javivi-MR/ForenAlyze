import pytest

from app.extensions import db


@pytest.fixture()
def app():
    """Crea una instancia de la app para tests.

    Usa una base de datos SQLite en memoria y desactiva CSRF para poder
    enviar formularios fácilmente desde los tests.
    """

    from app import create_app
    from app.config import Config as BaseConfig

    class TestConfig(BaseConfig):
        TESTING = True
        SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
        WTF_CSRF_ENABLED = False

        # Desactivar integraciones externas en entorno de test
        YARA_ENABLED = False
        SANDBOX_ENABLED = False
        TIKA_ENABLED = False

    app = create_app(TestConfig)

    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    """Cliente de pruebas de Flask."""

    return app.test_client()
