from datetime import date, datetime, timedelta
import os
from pathlib import Path
from uuid import uuid4

from flask import (
    Blueprint,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required
from werkzeug.utils import secure_filename

from app.extensions import db
from app.models import Alert, Analysis, File, User
from app.services.alerts import create_alerts_for_analysis
from app.analysis.pipeline import analyze_file


dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/dashboard", methods=["GET"])
@login_required
def dashboard_index():
    data = build_dashboard_data(current_user)

    return render_template(
        "dashboard.html",
        summary=data["summary"],
        alerts=data["recent_alerts"],
        recent_files=data["recent_files"],
        dashboard_data=data,
    )


@dashboard_bp.route("/dashboard/api/overview", methods=["GET"])
@login_required
def dashboard_overview():
    data = build_dashboard_data(current_user)
    return jsonify(data)


def build_dashboard_data(user: User | None):
    """Calcula KPIs y datasets del dashboard para el usuario (o global)."""
    now = datetime.utcnow()
    today = date.today()
    start_24h = now - timedelta(hours=24)
    start_7d = now - timedelta(days=6)

    # Ficheros (puedes filtrar por user_id si lo deseas)
    files_q = File.query
    analyses_q = Analysis.query

    total_uploads = files_q.count()
    uploads_today = files_q.filter(File.upload_date >= today).count()

    analyzed_total = analyses_q.count()
    pending_analysis = max(total_uploads - analyzed_total, 0)

    malicious_24h = (
        analyses_q.filter(
            Analysis.analyzed_at >= start_24h,
            Analysis.final_verdict.in_(["malicious", "critical"]),
        ).count()
    )
    critical_count = analyses_q.filter(
        Analysis.final_verdict == "critical"
    ).count()

    # Almacenamiento (adapta a tu lógica real de cuota)
    used_bytes = db.session.query(db.func.coalesce(db.func.sum(File.size), 0)).scalar()
    storage_quota_mb = 2048  # 2 GB por defecto
    storage_used_mb = round(used_bytes / (1024 * 1024), 1)
    storage_used_pct = (
        min(100, round((storage_used_mb / storage_quota_mb) * 100, 1))
        if storage_quota_mb
        else 0
    )

    summary = {
        "total_uploads": total_uploads,
        "uploads_today": uploads_today,
        "analyzed_total": analyzed_total,
        "pending_analysis": pending_analysis,
        "malicious_24h": malicious_24h,
        "critical_count": critical_count,
        "storage_used_mb": storage_used_mb,
        "storage_quota_mb": storage_quota_mb,
        "storage_used_pct": storage_used_pct,
    }

    # Serie últimos 7 días
    days = [
        (today - timedelta(days=i)) for i in range(6, -1, -1)
    ]  # hace 6 días ... hoy
    ts_clean = {d: 0 for d in days}
    ts_suspicious = {d: 0 for d in days}
    ts_malicious = {d: 0 for d in days}

    recent_analyses = analyses_q.filter(Analysis.analyzed_at >= start_7d).all()
    for a in recent_analyses:
        if not a.analyzed_at:
            continue
        d = a.analyzed_at.date()
        if d not in ts_clean:
            continue
        if a.final_verdict == "clean":
            ts_clean[d] += 1
        elif a.final_verdict == "suspicious":
            ts_suspicious[d] += 1
        elif a.final_verdict in ("malicious", "critical"):
            ts_malicious[d] += 1

    timeseries_7d = {
        "labels": [d.strftime("%d %b") for d in days],
        "clean": [ts_clean[d] for d in days],
        "suspicious": [ts_suspicious[d] for d in days],
        "malicious": [ts_malicious[d] for d in days],
    }

    # Tipos de archivo analizados
    # Preferimos usar file_type; si no, mime_type.
    ft_rows = (
        db.session.query(File.file_type, db.func.count(File.id))
        .group_by(File.file_type)
        .all()
    )
    labels, counts = [], []
    other_count = 0
    main_types = {"EXE", "PDF", "DOC", "JPG", "WAV"}
    for ft, c in ft_rows:
        ft_norm = (ft or "Otros").upper()
        if ft_norm in main_types:
            labels.append(ft_norm)
            counts.append(c)
        else:
            other_count += c
    if other_count:
        labels.append("Otros")
        counts.append(other_count)

    file_types = {"labels": labels, "counts": counts}

    # Detecciones por fuente (simple: se basa en final_verdict)
    src_labels = ["ClamAV", "YARA", "Sandbox", "Estego", "Macros"]
    src_clean = [0, 0, 0, 0, 0]
    src_suspicious = [0, 0, 0, 0, 0]
    src_malicious = [0, 0, 0, 0, 0]

    all_analyses = analyses_q.all()
    for a in all_analyses:
        if a.final_verdict == "clean":
            bucket = src_clean
        elif a.final_verdict == "suspicious":
            bucket = src_suspicious
        elif a.final_verdict in ("malicious", "critical"):
            bucket = src_malicious
        else:
            continue

        # ClamAV
        if a.antivirus_result:
            bucket[0] += 1
        # YARA
        if a.yara_result:
            bucket[1] += 1
        # Sandbox
        if a.sandbox_score is not None:
            bucket[2] += 1
        # Estego
        if a.stego_detected:
            bucket[3] += 1
        # Macros
        if a.macro_detected:
            bucket[4] += 1

    detections_source = {
        "labels": src_labels,
        "clean": src_clean,
        "suspicious": src_suspicious,
        "malicious": src_malicious,
    }

    # Alertas recientes (no leídas primero)
    recent_alerts = (
        Alert.query.order_by(Alert.is_read.asc(), Alert.created_at.desc())
        .limit(10)
        .all()
    )

    # Últimos archivos analizados (join File + Analysis)
    recent_files = (
        db.session.query(File, Analysis)
        .join(Analysis, Analysis.file_id == File.id)
        .order_by(Analysis.analyzed_at.desc())
        .limit(10)
        .all()
    )

    # Normalizamos a objetos "ligeros" para la plantilla / API
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

    recent_files_payload = []
    for f, a in recent_files:
        recent_files_payload.append(
            {
                "id": f.id,
                "analysis_id": a.id,
                "filename_original": f.filename_original,
                "file_type": f.file_type,
                "mime_type": f.mime_type,
                "size": f.size,
                "size_human": human_size(f.size),
                "upload_date": f.upload_date.isoformat() if f.upload_date else None,
                "analyzed_at": a.analyzed_at.isoformat() if a.analyzed_at else None,
                "sha256": a.sha256,
                "final_verdict": a.final_verdict,
            }
        )

    data = {
        "summary": summary,
        "timeseries_7d": timeseries_7d,
        "file_types": file_types,
        "detections_source": detections_source,
        "recent_alerts": recent_alerts,
        "recent_files": recent_files_payload,
    }
    return data


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


def _allowed_file(filename: str) -> bool:
    ext = (filename.rsplit(".", 1)[-1] or "").lower()
    return ext in ALLOWED_EXTENSIONS


def _human_size(num_bytes: int | None) -> str:
    if not num_bytes:
        return "0 B"
    suffixes = ["B", "KB", "MB", "GB"]
    i = 0
    v = float(num_bytes)
    while v >= 1024 and i < len(suffixes) - 1:
        v /= 1024
        i += 1
    return f"{v:.1f} {suffixes[i]}"


@dashboard_bp.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    """Subida de ficheros y disparo del análisis completo."""

    if request.method == "GET":
        return render_template("upload.html")

    file = request.files.get("file")
    if not file or file.filename == "":
        flash("No se ha seleccionado ningún fichero.", "error")
        return redirect(url_for("dashboard.upload"))

    if not _allowed_file(file.filename):
        flash("Tipo de fichero no permitido.", "error")
        return redirect(url_for("dashboard.upload"))

    # Validación de tamaño (además de MAX_CONTENT_LENGTH en config)
    content_length = request.content_length or 0
    if content_length > MAX_FILE_SIZE:
        flash("El fichero supera el tamaño máximo permitido de 100 MB.", "error")
        return redirect(url_for("dashboard.upload"))

    upload_folder = current_app.config.get(
        "UPLOAD_FOLDER",
        os.path.join(current_app.instance_path, "uploads"),
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
    db.session.flush()  # asegura new_file.id antes del análisis

    # Ejecutar análisis sincrónico básico
    analysis_data = analyze_file(full_path, mime_hint=file.mimetype)

    analysis = Analysis(
        file_id=new_file.id,
        user_id=current_user.id,
        md5=analysis_data.get("md5"),
        sha1=analysis_data.get("sha1"),
        sha256=analysis_data.get("sha256"),
        mime_type=analysis_data.get("mime_type"),
        yara_result=analysis_data.get("yara_result"),
        antivirus_result=analysis_data.get("antivirus_result"),
        virustotal_result=analysis_data.get("virustotal_result"),
        macro_detected=analysis_data.get("macro_detected"),
        stego_detected=analysis_data.get("stego_detected"),
        audio_analysis=analysis_data.get("audio_analysis"),
        sandbox_score=analysis_data.get("sandbox_score"),
        final_verdict=analysis_data.get("final_verdict"),
        summary=analysis_data.get("summary"),
        engine_version=analysis_data.get("engine_version"),
        ruleset_version=analysis_data.get("ruleset_version"),
        additional_results=analysis_data.get("additional_results"),
    )
    db.session.add(analysis)
    db.session.flush()

    # Crear alertas asociadas al análisis
    create_alerts_for_analysis(analysis)

    # Actualizar contadores de notificaciones del usuario
    current_user.notifications = (current_user.notifications or 0) + 1

    db.session.commit()

    flash("Fichero subido y analizado correctamente.", "success")
    return redirect(url_for("dashboard.dashboard_index"))


@dashboard_bp.route("/files", methods=["GET"])
@login_required
def list_files():
    """Listado de ficheros con estado de análisis."""

    q = (
        db.session.query(File, Analysis, User)
        .outerjoin(Analysis, Analysis.file_id == File.id)
        .outerjoin(User, User.id == File.user_id)
        .order_by(File.upload_date.desc())
    )

    files_payload: list[dict] = []
    for f, a, u in q.all():
        files_payload.append(
            {
                "id": f.id,
                "filename_original": f.filename_original,
                "filename_stored": f.filename_stored,
                "file_type": f.file_type,
                "mime_type": f.mime_type,
                "size": f.size,
                "size_human": _human_size(f.size),
                "upload_date": f.upload_date.isoformat() if f.upload_date else "",
                "storage_path": f.storage_path,
                "sha256": getattr(a, "sha256", None),
                "md5": getattr(a, "md5", None),
                "sha1": getattr(a, "sha1", None),
                "final_verdict": getattr(a, "final_verdict", None),
                "user_username": getattr(u, "username", None),
            }
        )

    return render_template("files.html", files=files_payload)
