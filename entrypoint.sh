#!/bin/sh
set -e

# Aplicar migraciones de base de datos si están definidas
if command -v flask >/dev/null 2>&1; then
  echo "Ejecutando flask db upgrade (si hay migraciones)..."
  flask db upgrade || echo "Aviso: flask db upgrade ha fallado, continuando de todas formas"
fi

# Crear tablas y usuario admin por si no existen aún
if [ -f "create_admin.py" ]; then
  echo "Ejecutando create_admin.py para inicializar BD y usuario admin (idempotente)..."
  python create_admin.py || echo "Aviso: create_admin.py ha fallado, continuando de todas formas"
fi

# Arrancar la aplicación con gunicorn
exec gunicorn --bind 0.0.0.0:8000 run:app
