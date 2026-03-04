import os

from app import create_app

app = create_app()

if __name__ == "__main__":
    # Número de workers para el servidor de desarrollo integrado de Flask.
    # En producción se recomienda usar gunicorn (ver Dockerfile), pero
    # este parámetro permite simular varios procesos también en local.
    workers = int(os.environ.get("FLASK_WORKERS", "1"))

    if workers > 1:
        # Cuando se usan múltiples workers, se desactiva el modo threaded
        # y se delega en varios procesos del servidor de desarrollo.
        app.run(processes=workers, threaded=False)
    else:
        # Un único worker (por defecto), usando el servidor threaded.
        app.run(threaded=True)
