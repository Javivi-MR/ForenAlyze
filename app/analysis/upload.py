import os
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from flask import Blueprint, current_app, redirect, request, url_for, flash
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename

from app.extensions import db
from app.models import File  # ajusta al nombre real del modelo

upload_bp = Blueprint("upload", __name__)

MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB
ALLOWED_EXTENSIONS = {
    "exe",
    "pdf",
    "doc",
    "docx",
    "xls",
    "xlsx",
    "png",
    "jpg",
    "jpeg",
    "gif",
    "bmp",
    "wav",
    "mp3",
}


def allowed_file(filename: str) -> bool:
  ext = (filename.rsplit(".", 1)[-1] or "").lower()
  return ext in ALLOWED_EXTENSIONS


@upload_bp.route("/upload", methods=["POST"])
@login_required
def upload_file():
  file = request.files.get("file")

  if not file or file.filename == "":
    flash("No se ha seleccionado ningún fichero.", "error")
    return redirect(url_for("dashboard"))

  if not allowed_file(file.filename):
    flash("Tipo de fichero no permitido.", "error")
    return redirect(url_for("dashboard"))

  # Validación adicional de tamaño en servidor
  if request.content_length and request.content_length > MAX_FILE_SIZE:
    flash("El fichero supera el tamaño máximo permitido de 100 MB.", "error")
    return redirect(url_for("dashboard"))

  upload_folder = current_app.config.get(
      "UPLOAD_FOLDER",
      os.path.join(current_app.instance_path, "uploads")
  )
  os.makedirs(upload_folder, exist_ok=True)

  original_name = secure_filename(file.filename)
  ext = Path(original_name).suffix.lower()
  stored_name = f"{uuid4().hex}{ext}"
  full_path = os.path.join(upload_folder, stored_name)

  file.save(full_path)
  size_bytes = os.path.getsize(full_path)

  new_file = File(
      user_id=current_user.id,
      filename_original=original_name,
      filename_stored=stored_name,
      file_type=ext.replace(".", "").upper(),
      mime_type=file.mimetype,
      size=size_bytes,
      upload_date=datetime.utcnow(),
      storage_path=full_path,
  )
  db.session.add(new_file)
  db.session.commit()

  flash("Fichero subido correctamente. El análisis se ejecutará en breve.", "success")
  return redirect(url_for("dashboard"))
