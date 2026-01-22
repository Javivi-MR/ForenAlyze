from flask import Flask, render_template
from sqlalchemy import text

from .config import Config
from .extensions import db, login_manager


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    login_manager.init_app(app)

    # Para SQLite, activamos WAL y ampliamos el timeout de bloqueo para
    # reducir errores "database is locked" cuando hay hilos en paralelo.
    with app.app_context():
        uri = app.config.get("SQLALCHEMY_DATABASE_URI", "")
        if uri.startswith("sqlite:///"):
            try:
                with db.engine.connect() as conn:  # type: ignore[attr-defined]
                    conn.execute(text("PRAGMA journal_mode=WAL;"))
                    conn.execute(text("PRAGMA busy_timeout=30000;"))
            except Exception:
                # No rompemos la app.
                pass

    from .auth import auth_bp
    # Blueprint principal de dashboard, subida y listado de ficheros
    from .analysis.dashboard import dashboard_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)

    @app.route("/")
    def index():
        return render_template("home.html")

    @app.route("/about")
    def about():
        return render_template("about.html")

    return app
