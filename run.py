import os

from app import create_app

app = create_app()

if __name__ == "__main__":
    # Número de workers para el servidor de desarrollo integrado de Flask.
    # En producción se recomienda usar gunicorn (ver Dockerfile). En Windows
    # no está soportado el modo multiproceso basado en fork, por lo que se
    # fuerza siempre el modo threaded independientemente de FLASK_WORKERS.
    workers = int(os.environ.get("FLASK_WORKERS", "1"))

    if os.name == "nt":
        # Plataforma Windows: evitamos procesos múltiples para no provocar
        # ValueError("Your platform does not support forking.").
        app.run(threaded=True)
    elif workers > 1:
        # En plataformas tipo Unix se puede simular varios procesos del
        # servidor de desarrollo utilizando el parámetro "processes".
        app.run(processes=workers, threaded=False)
    else:
        # Un único worker (por defecto), usando el servidor threaded.
        app.run(threaded=True)
