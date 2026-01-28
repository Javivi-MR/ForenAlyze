# Base image for Forenalyze application with ClamAV available
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install system dependencies, including ClamAV
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential \
       libpq-dev \
       clamav \
       clamav-freshclam \
    && rm -rf /var/lib/apt/lists/*

# Update ClamAV signatures at build time (optional but good for demo)
RUN freshclam || true

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Default CLAMAV_PATH relies on `clamscan` being in PATH
ENV CLAMAV_PATH=clamscan \
    FLASK_APP=run.py

# Al iniciar el contenedor:
#   1) ejecuta create_admin.py (crea tablas y usuario admin si faltan)
#   2) arranca la app con gunicorn
CMD ["sh", "-c", "python create_admin.py && gunicorn --bind 0.0.0.0:8000 run:app"]
