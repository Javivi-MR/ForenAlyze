from datetime import date, datetime, timedelta
import json
import os
from pathlib import Path
from threading import Thread
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
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from app.extensions import db
from app.models import Alert, Analysis, File, Log, User
from app.services.alerts import create_alerts_for_analysis
from app.analysis.pipeline import analyze_file
from app.services.logs import log_event


dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/dashboard", methods=["GET"])
@login_required
def dashboard_index():
	data = build_dashboard_data(current_user)

	# JSON-safe payload for frontend charts (no ORM objects)
	dashboard_data_js = {
		"summary": data["summary"],
		"timeseries_7d": data["timeseries_7d"],
		"file_types": data["file_types"],
		"detections_source": data["detections_source"],
		"recent_files": data["recent_files"],
		"recent_alerts": data["recent_alerts_api"],
	}

	return render_template(
		"dashboard.html",
		summary=data["summary"],
		alerts=data["recent_alerts"],
		recent_files=data["recent_files"],
		dashboard_data=dashboard_data_js,
	)


@dashboard_bp.route("/dashboard/api/overview", methods=["GET"])
@login_required
def dashboard_overview():
	data = build_dashboard_data(current_user)
	dashboard_data_js = {
		"summary": data["summary"],
		"timeseries_7d": data["timeseries_7d"],
		"file_types": data["file_types"],
		"detections_source": data["detections_source"],
		"recent_files": data["recent_files"],
		"recent_alerts": data["recent_alerts_api"],
	}
	return jsonify(dashboard_data_js)


@dashboard_bp.route("/profile", methods=["GET", "POST"])
@login_required
def edit_profile():
	"""Profile page for the current user.

	Allows updating basic info (username), profile picture and password
	via separate forms/modals.
	"""

	if request.method == "POST":
		form_type = request.form.get("form_type", "basic").strip().lower()

		if form_type == "basic":
			new_username = (request.form.get("username") or "").strip()
			if not new_username:
				flash("Username cannot be empty.", "error")
				return redirect(url_for("dashboard.edit_profile"))

			# Check that the username is not already taken by someone else
			existing = (
				User.query.filter(User.username == new_username, User.id != current_user.id)
				.first()
			)
			if existing:
				flash("This username is already in use.", "error")
				return redirect(url_for("dashboard.edit_profile"))

			old_username = current_user.username
			current_user.username = new_username
			try:
				db.session.commit()
			except Exception:
				db.session.rollback()
				flash("An error occurred while updating your profile.", "error")
				return redirect(url_for("dashboard.edit_profile"))

			flash("Profile information updated.", "success")
			log_event(
				action="profile_update",
				message="User updated basic profile information.",
				status="success",
				resource="dashboard.edit_profile",
				extra={
					"old_username": old_username,
					"new_username": new_username,
				},
			)
			return redirect(url_for("dashboard.edit_profile"))

		elif form_type == "avatar":
			file = request.files.get("avatar_file")
			if not file or file.filename == "":
				flash("Please select an image file.", "error")
				return redirect(url_for("dashboard.edit_profile"))

			ext = os.path.splitext(file.filename)[1].lower()
			allowed_ext = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"}
			if ext not in allowed_ext:
				flash("Unsupported image format. Use PNG, JPG, GIF or WEBP.", "error")
				return redirect(url_for("dashboard.edit_profile"))

			avatar_folder = os.path.join(current_app.root_path, "static", "avatars")
			os.makedirs(avatar_folder, exist_ok=True)

			filename = secure_filename(f"user_{current_user.id}_{uuid4().hex}{ext}")
			full_path = os.path.join(avatar_folder, filename)
			try:
				file.save(full_path)
			except Exception:
				flash("An error occurred while saving the image.", "error")
				return redirect(url_for("dashboard.edit_profile"))

			image_url = url_for("static", filename=f"avatars/{filename}")
			current_user.image_url = image_url
			try:
				db.session.commit()
			except Exception:
				db.session.rollback()
				flash("An error occurred while updating your profile photo.", "error")
				return redirect(url_for("dashboard.edit_profile"))

			flash("Profile photo updated.", "success")
			log_event(
				action="profile_avatar_update",
				message="User updated profile photo.",
				status="success",
				resource="dashboard.edit_profile",
			)
			return redirect(url_for("dashboard.edit_profile"))

		elif form_type == "password":
			current_password = request.form.get("current_password") or ""
			new_password = request.form.get("new_password") or ""
			confirm_password = request.form.get("confirm_password") or ""

			if not current_password or not new_password or not confirm_password:
				flash("Please complete all password fields.", "error")
				return redirect(url_for("dashboard.edit_profile"))

			if new_password != confirm_password:
				flash("New password and confirmation do not match.", "error")
				return redirect(url_for("dashboard.edit_profile"))

			if len(new_password) < 8:
				flash("The new password must be at least 8 characters long.", "error")
				return redirect(url_for("dashboard.edit_profile"))

			if not check_password_hash(current_user.password, current_password):
				flash("Current password is incorrect.", "error")
				return redirect(url_for("dashboard.edit_profile"))

			current_user.password = generate_password_hash(new_password)
			try:
				db.session.commit()
			except Exception:
				db.session.rollback()
				flash("An error occurred while updating your password.", "error")
				return redirect(url_for("dashboard.edit_profile"))

			flash("Password updated successfully.", "success")
			log_event(
				action="password_change",
				message="User changed account password.",
				status="success",
				resource="dashboard.edit_profile",
			)
			return redirect(url_for("dashboard.edit_profile"))

		else:
			flash("Invalid action.", "error")
			return redirect(url_for("dashboard.edit_profile"))

	return render_template("edit_user.html", user=current_user)


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

	# Almacenamiento global (todas las cuentas). La cuota se toma de la config.
	used_bytes = db.session.query(db.func.coalesce(db.func.sum(File.size), 0)).scalar()
	storage_quota_mb = current_app.config.get("STORAGE_QUOTA_MB", 2048)
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

	# Recent alerts (unread first)
	recent_alerts = (
		Alert.query.order_by(Alert.is_read.asc(), Alert.created_at.desc())
		.limit(10)
		.all()
	)
	recent_alerts_payload: list[dict] = []
	for a in recent_alerts:
		recent_alerts_payload.append(
			{
				"id": a.id,
				"title": a.title,
				"severity": a.severity,
				"description": a.description,
				"file_id": a.file_id,
				"analysis_id": a.analysis_id,
				"is_read": a.is_read,
				"created_at": a.created_at.isoformat() if a.created_at else None,
			}
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
		"recent_alerts_api": recent_alerts_payload,
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


def _compute_user_storage(user: User) -> dict:
	"""Calcula estadísticas de almacenamiento para un usuario concreto.

	Devuelve bytes usados, MB usados, MB de cuota, porcentaje y estado
	para poder mostrar avisos claros en la página de Storage.
	"""

	quota_mb = current_app.config.get("STORAGE_QUOTA_MB", 2048)
	used_bytes = (
		db.session.query(db.func.coalesce(db.func.sum(File.size), 0))
		.filter(File.user_id == user.id)
		.scalar()
	)
	used_mb = round((used_bytes or 0) / (1024 * 1024), 2)
	quota_mb_val = float(quota_mb) if quota_mb else 0.0
	if quota_mb_val > 0:
		pct = round(min(100.0, (used_mb / quota_mb_val) * 100.0), 1)
		remaining_mb = max(quota_mb_val - used_mb, 0.0)
	else:
		pct = 0.0
		remaining_mb = 0.0

	# Estado para avisos visuales
	if quota_mb_val == 0:
		status = "unknown"
	elif pct >= 100.0:
		status = "full"
	elif pct >= 85.0:
		status = "warning"
	else:
		status = "ok"

	return {
		"used_bytes": int(used_bytes or 0),
		"used_mb": used_mb,
		"quota_mb": quota_mb_val,
		"used_pct": pct,
		"remaining_mb": remaining_mb,
		"status": status,
	}


@dashboard_bp.route("/logs", methods=["GET"])
@login_required
def logs_view():
	"""Simple audit log view ordered by most recent first.

	Shows high-level activity events such as logins, uploads and
	completed analyses. Designed to be minimal and read-only.
	"""

	page = request.args.get("page", 1, type=int)
	per_page = 50

	query = Log.query.order_by(Log.created_at.desc())
	pagination = query.paginate(page=page, per_page=per_page, error_out=False)
	items = pagination.items

	logs_payload: list[dict] = []
	for entry in items:
		# Intentamos parsear detalles si son JSON válido, pero mantenemos el
		# texto original para el modal detallado en la plantilla.
		details_obj = None
		if entry.details:
			try:
				details_obj = json.loads(entry.details)
			except Exception:
				details_obj = None

		logs_payload.append(
			{
				"id": entry.id,
				"created_at": entry.created_at,
				"username": entry.username,
				"action": entry.action,
				"resource": entry.resource,
				"status": entry.status,
				"ip_address": entry.ip_address,
				"message": entry.message,
				"details_raw": entry.details,
				"details": details_obj,
			},
		)

	return render_template(
		"logs.html",
		logs=logs_payload,
		pagination=pagination,
	)


@dashboard_bp.route("/storage", methods=["GET"])
@login_required
def storage_view():
	"""Vista de almacenamiento para el usuario actual.

	Muestra cuánto espacio está usando, la cuota disponible y permite
	gestionar el espacio eliminando ficheros (y sus informes asociados).
	"""

	stats = _compute_user_storage(current_user)

	# Listado de ficheros del usuario ordenados por tamaño descendente
	q = (
		db.session.query(File, Analysis)
		.outerjoin(Analysis, Analysis.file_id == File.id)
		.filter(File.user_id == current_user.id)
		.order_by(File.size.desc().nullslast())
	)

	files_payload: list[dict] = []
	for f, a in q.all():
		files_payload.append(
			{
				"id": f.id,
				"filename_original": f.filename_original,
				"file_type": f.file_type,
				"mime_type": f.mime_type,
				"size": f.size,
				"size_human": _human_size(f.size),
				"upload_date": f.upload_date,
				"final_verdict": getattr(a, "final_verdict", None),
			}
		)

	return render_template(
		"storage.html",
		stats=stats,
		files=files_payload,
	)


@dashboard_bp.route("/storage/delete/<int:file_id>", methods=["POST"])
@login_required
def storage_delete_file(file_id: int):
	"""Elimina un fichero del usuario y sus análisis/alertas asociados.

	También borra el fichero físico del disco para liberar espacio.
	"""

	file_obj = File.query.get_or_404(file_id)
	if file_obj.user_id != current_user.id:
		flash("You cannot delete this file.", "error")
		return redirect(url_for("dashboard.storage_view"))

	size_bytes = file_obj.size or 0
	filename = file_obj.filename_original or "(unnamed)"
	path = file_obj.storage_path

	# Eliminar análisis relacionados
	analyses = Analysis.query.filter_by(file_id=file_obj.id).all()
	for analysis in analyses:
		# Eliminar alertas vinculadas a este análisis
		Alert.query.filter_by(analysis_id=analysis.id).delete(synchronize_session=False)
		
		# Log opcional por cada análisis eliminado
		log_event(
			action="analysis_deleted",
			resource="storage.delete",
			status="success",
			message=f"Analysis {analysis.id} deleted as part of file cleanup.",
			extra={"file_id": file_obj.id, "analysis_id": analysis.id},
		)

		db.session.delete(analysis)

	# Alertas asociadas directamente al fichero (sin analysis_id)
	Alert.query.filter_by(file_id=file_obj.id).delete(synchronize_session=False)

	# Borrar fichero físico si existe
	try:
		if path and os.path.exists(path):
			os.remove(path)
	except OSError:
		# No bloqueamos el flujo por un fallo de E/S; el registro
		# de base de datos seguirá limpiándose.
		pass

	# Eliminar registro principal del fichero
	db.session.delete(file_obj)

	# Registrar el evento de limpieza de almacenamiento
	log_event(
		action="storage_cleanup",
		resource="storage.delete",
		status="success",
		message=f"File '{filename}' deleted by user to free storage.",
		extra={
			"file_id": file_id,
			"size_bytes": int(size_bytes),
		},
	)

	try:
		db.session.commit()
	except Exception:
		db.session.rollback()
		flash("An error occurred while deleting the file.", "error")
		return redirect(url_for("dashboard.storage_view"))

	freed_human = _human_size(size_bytes)
	flash(f"File '{filename}' deleted. Freed {freed_human} of storage.", "success")
	return redirect(url_for("dashboard.storage_view"))


def _run_analysis_background(app, file_id: int, full_path: str, mime_type: str, user_id: int) -> None:
	"""Run the full analysis in a background thread.

	Creates the Analysis, generates alerts and updates the user's
	notification counter without blocking the HTTP upload request.
	"""

	from app.analysis.pipeline import analyze_file as _analyze_file

	with app.app_context():
		try:
			file_obj = File.query.get(file_id)
			user = User.query.get(user_id)
			if not file_obj or not user:
				return

			analysis_data = _analyze_file(full_path, mime_hint=mime_type)

			analysis = Analysis(
				file_id=file_obj.id,
				user_id=user.id,
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

			create_alerts_for_analysis(analysis)
			user.notifications = (user.notifications or 0) + 1

			# Información de almacenamiento en el momento de finalizar el análisis
			used_bytes = db.session.query(db.func.coalesce(db.func.sum(File.size), 0)).scalar()
			storage_quota_mb = 2048  # Mantener alineado con el dashboard
			storage_used_mb = round((used_bytes or 0) / (1024 * 1024), 1)
			storage_remaining_mb = max(storage_quota_mb - storage_used_mb, 0)

			# Log de actividad: análisis completado
			log_event(
				action="analysis_completed",
				message=f"Analysis completed for file '{file_obj.filename_original}'.",
				status=analysis.final_verdict or "info",
				resource="dashboard.analysis_background",
				user=user,
				extra={
					"file_id": file_obj.id,
					"analysis_id": analysis.id,
					"filename": file_obj.filename_original,
					"final_verdict": analysis.final_verdict,
					"sha256": analysis.sha256,
					"storage_used_mb": storage_used_mb,
					"storage_quota_mb": storage_quota_mb,
					"storage_remaining_mb": storage_remaining_mb,
				},
			)

			db.session.commit()
		except Exception as exc:  # pragma: no cover - environment/thread errors
			current_app.logger.exception("Error in background analysis: %s", exc)
			try:
				db.session.rollback()
			except Exception:
				pass
		finally:
			try:
				db.session.remove()
			except Exception:
				pass


@dashboard_bp.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
	"""Handle file upload and launch the full analysis."""

	if request.method == "GET":
		return render_template("upload.html")

	file = request.files.get("file")
	if not file or file.filename == "":
		flash("No file has been selected.", "error")
		return redirect(url_for("dashboard.upload"))

	if not _allowed_file(file.filename):
		flash("File type not allowed.", "error")
		return redirect(url_for("dashboard.upload"))

	# Size validation (in addition to MAX_CONTENT_LENGTH in config)
	content_length = request.content_length or 0
	if content_length > MAX_FILE_SIZE:
		flash("The file exceeds the maximum allowed size of 100 MB.", "error")
		return redirect(url_for("dashboard.upload"))

	# Per-user storage quota check
	user_stats = _compute_user_storage(current_user)
	if user_stats.get("status") == "full":
		flash(
			"Your personal storage is already full. Please delete some files in the Storage section before uploading new ones.",
			"error",
		)
		return redirect(url_for("dashboard.storage_view"))

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
	db.session.commit()  # persist file before launching analysis

	# Información de almacenamiento tras la subida
	used_bytes = db.session.query(db.func.coalesce(db.func.sum(File.size), 0)).scalar()
	storage_quota_mb = 2048
	storage_used_mb = round((used_bytes or 0) / (1024 * 1024), 1)
	storage_remaining_mb = max(storage_quota_mb - storage_used_mb, 0)

	# Log de actividad: subida de fichero
	log_event(
		action="upload",
		message=f"File '{original_name}' uploaded and queued for analysis.",
		status="success",
		resource="dashboard.upload",
		extra={
			"file_id": new_file.id,
			"filename": original_name,
			"size_bytes": size_bytes,
			"size_human": _human_size(size_bytes),
			"storage_used_mb": storage_used_mb,
			"storage_quota_mb": storage_quota_mb,
			"storage_remaining_mb": storage_remaining_mb,
		},
	)

	# Launch analysis in a background thread so the UI is not blocked
	app = current_app._get_current_object()
	thread = Thread(
		target=_run_analysis_background,
		args=(app, new_file.id, full_path, file.mimetype, current_user.id),
		daemon=True,
	)
	thread.start()

	flash(
		"File uploaded successfully. The analysis is running in the background; "
		"you will receive a notification when it is ready.",
		"success",
	)
	return redirect(url_for("dashboard.dashboard_index"))


@dashboard_bp.route("/files", methods=["GET"])
@login_required
def files():
	"""List of files with their analysis status."""

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


@dashboard_bp.route("/analysis", methods=["GET"])
@login_required
def analysis_list():
	"""Overview of all completed analyses.

	Shows a table with analyzed files, hashes, verdict and
	detection sources (ClamAV, YARA, macros, stego, audio).
	"""

	q = (
		db.session.query(Analysis, File, User)
		.join(File, Analysis.file_id == File.id)
		.join(User, Analysis.user_id == User.id)
		.order_by(Analysis.analyzed_at.desc())
	)

	def human_size(num_bytes: int | None) -> str:
		if not num_bytes:
			return "0 B"
		suffixes = ["B", "KB", "MB", "GB"]
		i = 0
		v = float(num_bytes)
		while v >= 1024 and i < len(suffixes) - 1:
			v /= 1024
			i += 1
		return f"{v:.1f} {suffixes[i]}"

	rows: list[dict] = []
	for a, f, u in q.all():
		rows.append(
			{
				"id": a.id,
				"analyzed_at": a.analyzed_at,
				"filename_original": f.filename_original,
				"file_type": f.file_type,
				"mime_type": f.mime_type,
				"size_human": human_size(f.size),
				"sha256": a.sha256,
				"final_verdict": a.final_verdict,
				"user_username": u.username,
				"has_clamav": bool(a.antivirus_result),
				"has_yara": bool(a.yara_result),
				"macro_detected": a.macro_detected,
				"stego_detected": a.stego_detected,
				"has_audio": bool(a.audio_analysis),
			}
		)

	return render_template("analysis.html", analyses=rows)


@dashboard_bp.route("/analysis/<int:analysis_id>/report", methods=["GET"])
@login_required
def analysis_report(analysis_id: int):
	"""Detailed report for a specific analysis.

	Displays all available data: hashes, metadata, engines results,
	YARA rules, macros, stego, audio, etc.
	"""

	analysis = Analysis.query.get_or_404(analysis_id)
	file_obj = analysis.file
	user = analysis.user

	# If the authenticated user owns this analysis, mark the related
	# alerts as read and update their notification counter.
	if current_user.is_authenticated and analysis.user_id == current_user.id:
		unread_alerts = (
			Alert.query.filter_by(
				user_id=current_user.id,
				analysis_id=analysis.id,
				is_read=False,
			)
			.all()
		)
		if unread_alerts:
			for a in unread_alerts:
				a.is_read = True
			# Ajustamos el contador entero de notificaciones sin dejarlo en negativo
			decrement = len(unread_alerts)
			current_user.notifications = max(
				0, (current_user.notifications or 0) - decrement
			)
			try:
				db.session.commit()
			except Exception:
				# On error, roll back so the session is not left inconsistent
				db.session.rollback()

	alerts = (
		Alert.query.filter_by(analysis_id=analysis.id)
		.order_by(Alert.created_at.desc())
		.all()
	)

	# Parseo seguro de campos JSON/texto
	def _parse_json(value):
		if not value:
			return None
		try:
			return json.loads(value)
		except Exception:
			return None

	antivirus_data = _parse_json(analysis.antivirus_result) or analysis.antivirus_result
	yara_matches = _parse_json(analysis.yara_result) or []
	additional_meta = _parse_json(analysis.additional_results) or {}
	audio_info = _parse_json(analysis.audio_analysis) or analysis.audio_analysis
	audio_spectrogram = None
	if isinstance(additional_meta, dict):
		audio_spectrogram = additional_meta.get("audio_spectrogram")
	clam_status = None
	clam_detail = None
	clam_detection = None
	clam_message = None
	vt_data = _parse_json(analysis.virustotal_result)
	vt_stats = None
	vt_total = None
	vt_positives = None
	vt_summary = None

	if isinstance(vt_data, dict):
		stats = vt_data.get("stats") or vt_data.get("last_analysis_stats")
		if isinstance(stats, dict):
			vt_stats = stats
			try:
				vt_total = sum(int(v or 0) for v in stats.values())
			except Exception:
				vt_total = None
			try:
				vt_positives = int(stats.get("malicious", 0) or 0) + int(
					stats.get("suspicious", 0) or 0
				)
			except Exception:
				vt_positives = None

			if vt_total:
				if not vt_positives:
					vt_summary = f"Sin detecciones: 0 de {vt_total} motores han marcado el archivo."
				elif vt_positives <= 3:
					vt_summary = (
						f"Bajas detecciones: {vt_positives} de {vt_total} motores lo "
						"marcan como sospechoso/malicioso."
					)
				else:
					vt_summary = (
						f"Múltiples detecciones: {vt_positives} de {vt_total} motores lo "
						"marcan como sospechoso/malicioso."
					)

	# Preparamos estructura para la plantilla
	file_info = {
		"filename_original": getattr(file_obj, "filename_original", None),
		"filename_stored": getattr(file_obj, "filename_stored", None),
		"file_type": getattr(file_obj, "file_type", None),
		"mime_type": getattr(file_obj, "mime_type", None),
		"size": getattr(file_obj, "size", None),
		"upload_date": getattr(file_obj, "upload_date", None),
		"storage_path": getattr(file_obj, "storage_path", None),
		"md5": analysis.md5,
		"sha1": analysis.sha1,
		"sha256": analysis.sha256,
	}

	# Human-friendly interpretation of ClamAV result
	if isinstance(antivirus_data, dict):
		clam_status = antivirus_data.get("status")
		clam_detail = antivirus_data.get("detail") or ""
	elif isinstance(antivirus_data, str):
		clam_detail = antivirus_data

	if clam_detail and ":" in clam_detail:
		try:
			_, rest = clam_detail.split(":", 1)
			rest = rest.strip()
			if rest.upper().endswith("FOUND"):
				name = rest[: -len("FOUND")].strip()
				clam_detection = name or None
		except Exception:
			pass

	if clam_status == "clean":
		clam_message = "ClamAV did not detect any threats in this file."
	elif clam_status == "infected":
		clam_message = "ClamAV detected this file as malicious."
	elif clam_status == "not_available":
		clam_message = "ClamAV is not available on this system (not installed or not accessible)."
	elif clam_status == "error":
		clam_message = "An error occurred while running ClamAV. Please review the engine configuration."
	elif clam_status == "unknown":
		clam_message = "The ClamAV result is unknown. Review the technical details if needed."

	context = {
		"analysis": analysis,
		"file": file_obj,
		"file_info": file_info,
		"user": user,
		"alerts": alerts,
		"antivirus_data": antivirus_data,
		"clam_status": clam_status,
		"clam_detail": clam_detail,
		"clam_detection": clam_detection,
		"clam_message": clam_message,
		"yara_matches": yara_matches,
		"additional_meta": additional_meta,
		"audio_info": audio_info,
		"audio_spectrogram": audio_spectrogram,
		"vt_data": vt_data,
		"vt_stats": vt_stats,
		"vt_total": vt_total,
		"vt_positives": vt_positives,
		"vt_summary": vt_summary,
	}

	return render_template("analysis_report.html", **context)


@dashboard_bp.route("/analysis/<int:analysis_id>/stego_payload", methods=["GET"])
@login_required
def stego_payload(analysis_id: int):
	"""Return full steganography payload (original or decoded) as JSON.

	This is used by the analysis report view to populate an on-page
	modal with the complete payload when the user requests it.
	"""

	mode = request.args.get("mode", "decoded")  # "decoded" or "original"
	index = request.args.get("index", "0")
	try:
		idx = int(index)
	except ValueError:
		idx = 0

	analysis = Analysis.query.get_or_404(analysis_id)

	# Reparse additional_results in the same way as the report view.
	try:
		additional_meta = json.loads(analysis.additional_results) if analysis.additional_results else {}
	except Exception:
		additional_meta = {}

	stego = additional_meta.get("steganography") or {}
	base64_list = stego.get("base64") or []
	if not isinstance(base64_list, list) or not base64_list:
		return jsonify({"error": "No steganography payload is available for this analysis."}), 404

	if idx < 0 or idx >= len(base64_list):
		return jsonify({"error": "Requested payload index is out of range."}), 404

	entry = base64_list[idx] or {}
	if mode == "original":
		content = entry.get("original_full") or entry.get("original_preview") or ""
		label = "Original base64 payload"
	else:
		content = entry.get("decoded_full") or entry.get("decoded_preview") or ""
		label = "Decoded steganography payload"

	return jsonify(
		{
			"mode": mode,
			"index": idx,
			"label": label,
			"content": str(content),
			"source": entry.get("source"),
			"decoded_type": entry.get("decoded_type"),
			"decoded_length": entry.get("decoded_length"),
		}
	)


@dashboard_bp.route("/notifications/mark_all_read", methods=["POST"])
@login_required
def notifications_mark_all_read():
	"""Mark all notifications for the current user as read.

	Used from the bell dropdown in the navbar.
	"""

	unread = Alert.query.filter_by(user_id=current_user.id, is_read=False).all()
	count = len(unread)
	if count:
		for a in unread:
			a.is_read = True
		current_user.notifications = max(
			0, (current_user.notifications or 0) - count
		)
		try:
			db.session.commit()
		except Exception:
			db.session.rollback()

	# Redirect back to the previous page if possible, or to the dashboard.
	return redirect(request.referrer or url_for("dashboard.dashboard_index"))



