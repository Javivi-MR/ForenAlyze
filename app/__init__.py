from flask import Flask, render_template
from sqlalchemy import text

from .config import Config
from .extensions import db, login_manager, migrate

try:  # Carga opcional de variables desde .env si python-dotenv está instalado
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    load_dotenv = None  # type: ignore[assignment]


def create_app():
    if load_dotenv is not None:
        # Cargamos variables de entorno desde un fichero .env en entorno de
        # desarrollo. Las variables ya definidas en el entorno del sistema
        # tienen prioridad.
        load_dotenv(override=False)

    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app, db)

    # Ya no usamos SQLite como backend principal, por lo que no aplicamos
    # PRAGMAs específicos de SQLite aquí.

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
