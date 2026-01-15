from datetime import datetime

from flask_login import UserMixin
from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from .extensions import db


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    image_url = db.Column(db.String(256), nullable=True)
    notifications = db.Column(db.Integer, default=0)

    def __repr__(self) -> str:  # pragma: no cover - representación sencilla
        return f"<User {self.username}>"


class File(db.Model):
    """Fichero subido por un usuario.

    Se usa en dashboard, listado de ficheros y alertas.
    """

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("user.id"), nullable=False)

    # Nombre original y almacenado
    filename_original = Column(String(256), nullable=False)
    filename_stored = Column(String(256), nullable=False)

    # Información de almacenamiento
    storage_path = Column(String(512), nullable=False)
    upload_date = Column(DateTime, default=datetime.utcnow)

    # Metadatos básicos
    size = Column(Integer)
    file_type = Column(String(64))  # EXE, PDF, JPG, WAV, etc.
    mime_type = Column(String(128))

    # Hashes principales
    md5 = Column(String(32))
    sha1 = Column(String(40))
    sha256 = Column(String(64))

    analyses = relationship("Analysis", backref="file", lazy=True)


class Analysis(db.Model):
    """Resultado de análisis de un fichero concreto."""

    id = Column(Integer, primary_key=True)
    file_id = Column(Integer, ForeignKey("file.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("user.id"), nullable=False)

    analyzed_at = Column(DateTime, default=datetime.utcnow)

    # Hashes (repetidos para consulta rápida)
    md5 = Column(String(32))
    sha1 = Column(String(40))
    sha256 = Column(String(64))

    mime_type = Column(String(128))

    # Resultados motores / reglas
    yara_result = Column(Text)  # JSON/texto con coincidencias YARA
    antivirus_result = Column(Text)  # Resultado ClamAV u otros AV locales
    virustotal_result = Column(Text)  # Opcional, si se integra VT

    # Detecciones específicas
    macro_detected = Column(String(16))  # yes/no/unknown
    stego_detected = Column(String(16))  # yes/no/unknown
    audio_analysis = Column(Text)  # Información básica de audio

    sandbox_score = Column(Float)  # reservado para sandbox futuro

    # Veredicto global
    final_verdict = Column(String(16))  # clean/suspicious/malicious/critical
    summary = Column(Text)

    # Información adicional / versiones
    engine_version = Column(String(64))
    ruleset_version = Column(String(64))
    additional_results = Column(Text)

    user = relationship("User", backref="analyses")


class Alert(db.Model):
    """Alerta generada a partir de un análisis.

    Se muestra en el panel de "Alertas recientes".
    """

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    file_id = db.Column(db.Integer, db.ForeignKey("file.id"), nullable=False)
    analysis_id = db.Column(db.Integer, db.ForeignKey("analysis.id"), nullable=True)

    title = db.Column(db.String(128), nullable=False)
    severity = db.Column(db.String(16), nullable=False)  # info/warning/danger/critical
    description = db.Column(db.Text, nullable=True)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, nullable=False, server_default=db.func.now())

    user = db.relationship("User", backref="alerts")
    file = db.relationship("File", backref="alerts")

    def __repr__(self) -> str:  # pragma: no cover - representación sencilla
        return f"<Alert {self.severity} {self.title}>"

