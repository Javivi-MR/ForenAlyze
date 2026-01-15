from flask import Blueprint, render_template
from flask_login import login_required

from app.extensions import db
from app.models import File, Analysis, User  # ajusta a tus modelos reales

files_bp = Blueprint("files", __name__, url_prefix="/files")


@files_bp.route("/", methods=["GET"])
@login_required
def list_files():
    # Join File + Analysis (puede haber 0..1 análisis)
    q = (
        db.session.query(File, Analysis, User)
        .outerjoin(Analysis, Analysis.file_id == File.id)
        .outerjoin(User, User.id == File.user_id)
        .order_by(File.upload_date.desc())
    )

    def human_size(num_bytes):
        if not num_bytes:
            return "0 B"
        suffixes = ["B", "KB", "MB", "GB"]
        i = 0
        v = float(num_bytes)
        while v >= 1024 and i < len(suffixes) - 1:
            v /= 1024
            i += 1
        return f"{v:.1f} {suffixes[i]}"

    files = []
    for f, a, u in q.all():
        files.append(
            {
                "id": f.id,
                "filename_original": f.filename_original,
                "filename_stored": f.filename_stored,
                "file_type": f.file_type,
                "mime_type": f.mime_type,
                "size": f.size,
                "size_human": human_size(f.size),
                "upload_date": f.upload_date.isoformat() if f.upload_date else "",
                "storage_path": f.storage_path,
                "sha256": getattr(a, "sha256", None),
                "md5": getattr(a, "md5", None),
                "sha1": getattr(a, "sha1", None),
                "final_verdict": getattr(a, "final_verdict", None),
                "user_username": getattr(u, "username", None),
            }
        )

    return render_template("files.html", files=files)
