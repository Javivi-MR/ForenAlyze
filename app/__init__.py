from flask import Flask, render_template, request
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

    @app.after_request
    def apply_security_headers(response):
        """Añade cabeceras de seguridad HTTP por defecto.

        Muchas de estas defensas también se pueden configurar en el
        reverse proxy (Nginx, etc.), pero las fijamos aquí para que la
        aplicación sea razonablemente segura por sí misma.
        """

        # Evita que la app se embeba en iframes (clickjacking)
        response.headers.setdefault("X-Frame-Options", "DENY")

        # Evita que el navegador intente adivinar tipos de contenido
        response.headers.setdefault("X-Content-Type-Options", "nosniff")

        # Política de referer restrictiva
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")

        # Protección XSS heredada (algunos navegadores antiguos)
        response.headers.setdefault("X-XSS-Protection", "1; mode=block")

        # Política de permisos de navegador (APIs potentes)
        response.headers.setdefault(
            "Permissions-Policy",
            "geolocation=(), microphone=(), camera=(), payment=(), usb=()",
        )

        # Content Security Policy básica. Permitimos 'unsafe-inline' porque
        # la app usa algunos scripts/estilos embebidos; si se refactoriza a
        # ficheros estáticos se puede endurecer eliminando esa directiva.
        #
        # También autorizamos el CDN jsDelivr, usado para Bootstrap, AOS,
        # Chart.js, SweetAlert2 y algunos iconos en la página About.
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data: https://cdn.jsdelivr.net; "
            "font-src 'self' data: https://cdn.jsdelivr.net; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        response.headers.setdefault("Content-Security-Policy", csp)

        # HSTS sólo tiene sentido sobre HTTPS; comprobamos si la petición
        # ha llegado por un canal seguro.
        if request.is_secure:
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains; preload",
            )

        return response

    @app.route("/")
    def index():
        return render_template("home.html")

    @app.route("/about")
    def about():
        return render_template("about.html")

    return app
