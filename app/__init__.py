from flask import Flask, render_template

from .config import Config
from .extensions import db, login_manager


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    login_manager.init_app(app)

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
