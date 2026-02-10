from app import create_app

app = create_app()

if __name__ == "__main__":
    # En producción, el modo debug de Flask debe estar desactivado
    # para evitar el debugger interactivo y posibles fugas de información.
    # El valor de DEBUG puede controlarse vía configuración/variables de entorno.
    app.run()
