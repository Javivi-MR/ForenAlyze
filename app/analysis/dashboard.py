from datetime import date, datetime, timedelta
from io import BytesIO
import json
import os
from pathlib import Path
from threading import Thread
from uuid import uuid4
import textwrap
from functools import wraps

from flask import (
	Blueprint,
	current_app,
	flash,
	jsonify,
	redirect,
	render_template,
	request,
	url_for,
	send_file,
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


def admin_required(view_func):
	"""Decorator to restrict access to admin users only."""

	@wraps(view_func)
	def wrapped_view(*args, **kwargs):
		if not current_user.is_authenticated:
			return redirect(url_for("auth.login"))

		if not getattr(current_user, "is_admin", False):
			flash("You do not have permission to access this section.", "error")
			return redirect(url_for("dashboard.dashboard_index"))

		return view_func(*args, **kwargs)

	return wrapped_view


def _get_yara_rules_root() -> Path | None:
	"""Devuelve la ruta base de reglas YARA como Path si es válida.

	Se basa en la configuración YARA_RULES_PATH y sólo devuelve un Path
	cuando YARA_ENABLED es true y la ruta existe.
	"""

	cfg = current_app.config if current_app else {}
	if not cfg.get("YARA_ENABLED", False):
		return None
	root_cfg = cfg.get("YARA_RULES_PATH")
	if not root_cfg:
		return None
	root_path = Path(root_cfg)
	if not root_path.exists():
		return None
	return root_path


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


@dashboard_bp.route("/admin/users", methods=["GET", "POST"])
@login_required
@admin_required
def manage_users():
	"""Simple user management view for admins.

	- GET: list all users.
	- POST: create a new user (admin or normal).
	"""

	if request.method == "POST":
		action = (request.form.get("action") or "create").strip().lower()
		if action != "create":
			flash("Invalid action.", "error")
			return redirect(url_for("dashboard.manage_users"))

		new_username = (request.form.get("username") or "").strip()
		password = request.form.get("password") or ""
		confirm = request.form.get("confirm_password") or ""
		is_admin_flag = bool(request.form.get("is_admin"))

		if not new_username or not password or not confirm:
			flash("Please complete all required fields.", "error")
			return redirect(url_for("dashboard.manage_users"))

		if password != confirm:
			flash("Password and confirmation do not match.", "error")
			return redirect(url_for("dashboard.manage_users"))

		if len(password) < 8:
			flash("The password must be at least 8 characters long.", "error")
			return redirect(url_for("dashboard.manage_users"))

		# Ensure username uniqueness
		existing = User.query.filter_by(username=new_username).first()
		if existing:
			flash("This username is already in use.", "error")
			return redirect(url_for("dashboard.manage_users"))

		user = User(
			username=new_username,
			password=generate_password_hash(password),
			is_admin=is_admin_flag,
		)
		try:
			db.session.add(user)
			db.session.commit()
		except Exception:
			db.session.rollback()
			flash("An error occurred while creating the user.", "error")
			return redirect(url_for("dashboard.manage_users"))

		flash("User created successfully.", "success")
		log_event(
			action="admin_user_create",
			message="Admin created a new user.",
			status="success",
			resource="dashboard.manage_users",
			extra={"created_username": new_username, "created_is_admin": is_admin_flag},
		)
		return redirect(url_for("dashboard.manage_users"))

	users = User.query.order_by(User.username.asc()).all()
	# Compute per-user storage stats so admins can see how much space
	# each account is consuming.
	user_storage: dict[int, dict] = {}
	for u in users:
		try:
			user_storage[u.id] = _compute_user_storage(u)
		except Exception:
			user_storage[u.id] = {
				"used_bytes": 0,
				"used_mb": 0.0,
				"quota_mb": current_app.config.get("STORAGE_QUOTA_MB", 2048),
				"used_pct": 0.0,
				"remaining_mb": 0.0,
				"status": "unknown",
			}

	return render_template("users.html", users=users, user_storage=user_storage)


@dashboard_bp.route("/admin/users/<int:user_id>/password", methods=["POST"])
@login_required
@admin_required
def admin_change_user_password(user_id: int):
	"""Allow admins to change passwords of other users.

	Constraints:
	- Admins cannot change passwords of other admins.
	- Admins cannot change their own password here (must use profile page
	  with current password).
	"""

	target = User.query.get_or_404(user_id)

	if target.id == current_user.id:
		flash("Use the profile page to change your own password.", "error")
		return redirect(url_for("dashboard.manage_users"))

	if getattr(target, "is_admin", False):
		flash("You cannot change the password of another admin user.", "error")
		return redirect(url_for("dashboard.manage_users"))

	new_password = request.form.get("new_password") or ""
	confirm_password = request.form.get("confirm_password") or ""

	if not new_password or not confirm_password:
		flash("Please provide a new password and its confirmation.", "error")
		return redirect(url_for("dashboard.manage_users"))

	if new_password != confirm_password:
		flash("New password and confirmation do not match.", "error")
		return redirect(url_for("dashboard.manage_users"))

	if len(new_password) < 8:
		flash("The new password must be at least 8 characters long.", "error")
		return redirect(url_for("dashboard.manage_users"))

	target.password = generate_password_hash(new_password)
	try:
		db.session.commit()
	except Exception:
		db.session.rollback()
		flash("An error occurred while updating the password.", "error")
		return redirect(url_for("dashboard.manage_users"))

	flash("Password updated successfully.", "success")
	log_event(
		action="admin_password_change_other",
		message="Admin changed password of another user.",
		status="success",
		resource="dashboard.admin_change_user_password",
		extra={"target_user_id": target.id, "target_username": target.username},
	)
	return redirect(url_for("dashboard.manage_users"))


def build_dashboard_data(user: User | None):
	"""Calcula KPIs y datasets del dashboard para el usuario (o global)."""

	now = datetime.utcnow()
	today = date.today()
	start_24h = now - timedelta(hours=24)
	start_7d = now - timedelta(days=6)

	# Ficheros / análisis base
	files_q = File.query
	analyses_q = Analysis.query
	alerts_q = Alert.query

	# Si el usuario no es admin, limitamos todas las métricas a sus
	# propios ficheros/análisis/alertas.
	if user is not None and not getattr(user, "is_admin", False):
		files_q = files_q.filter(File.user_id == user.id)
		analyses_q = analyses_q.filter(Analysis.user_id == user.id)
		alerts_q = alerts_q.filter(Alert.user_id == user.id)

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

	# Almacenamiento: para admins se muestra el uso global; para usuarios
	# normales, sólo su propio espacio consumido.
	if user is not None and not getattr(user, "is_admin", False):
		storage_stats = _compute_user_storage(user)
		storage_used_mb = storage_stats["used_mb"]
		storage_quota_mb = storage_stats["quota_mb"]
		storage_used_pct = storage_stats["used_pct"]
	else:
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
	ft_query = db.session.query(File.file_type, db.func.count(File.id))
	if user is not None and not getattr(user, "is_admin", False):
		ft_query = ft_query.filter(File.user_id == user.id)
	ft_rows = ft_query.group_by(File.file_type).all()
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
		alerts_q.order_by(Alert.is_read.asc(), Alert.created_at.desc())
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
	recent_files_q = (
		db.session.query(File, Analysis)
		.join(Analysis, Analysis.file_id == File.id)
		.order_by(Analysis.analyzed_at.desc())
	)
	if user is not None and not getattr(user, "is_admin", False):
		recent_files_q = recent_files_q.filter(File.user_id == user.id)
	recent_files = recent_files_q.limit(10).all()

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


@dashboard_bp.route("/yara/rules", methods=["GET"])
@login_required
def yara_rules_index():
	"""Listado sencillo de reglas YARA configuradas en el sistema.

	Muestra los ficheros de reglas bajo YARA_RULES_PATH (cuando éste es
	un directorio) o un único fichero cuando apunta a una ruta de
	fichero. Desde aquí se puede navegar a la edición/alta/borrado de
	reglas.
	"""

	rules_root = _get_yara_rules_root()
	if rules_root is None:
		flash("YARA is disabled or YARA_RULES_PATH is not a valid path.", "error")
		return render_template(
			"yara_rules.html",
			rules=[],
			is_dir=False,
			rules_root=None,
		)

	# Construimos listado de reglas según sea directorio o fichero único.
	is_dir = rules_root.is_dir()
	rules: list[dict] = []
	if is_dir:
		for ext in (".yar", ".yara", ".rule"):
			for path in sorted(rules_root.rglob(f"*{ext}")):
				if not path.is_file():
					continue
				rel = path.relative_to(rules_root)
				stat = path.stat()
				rules.append(
					{
						"name": str(rel),
						"size": stat.st_size,
						"mtime": datetime.fromtimestamp(stat.st_mtime),
					}
				)
	else:
		if rules_root.is_file():
			stat = rules_root.stat()
			rules.append(
				{
					"name": rules_root.name,
					"size": stat.st_size,
					"mtime": datetime.fromtimestamp(stat.st_mtime),
				}
			)

	return render_template(
		"yara_rules.html",
		is_dir=is_dir,
		rules_root=str(rules_root),
		rules=rules,
		can_manage_yara=getattr(current_user, "is_admin", False),
	)


def _resolve_yara_rule_path(rel_path: str) -> Path | None:
	"""Resuelve una ruta relativa de regla dentro del directorio raíz.

	Incluye una comprobación básica para evitar que rutas manipuladas
	salgan del directorio YARA_RULES_PATH.
	"""

	rules_root = _get_yara_rules_root()
	if rules_root is None:
		return None

	# Para el caso de fichero único, ignoramos rel_path y devolvemos
	# directamente la ruta configurada.
	if not rules_root.is_dir():
		return rules_root if rules_root.is_file() else None

	try:
		target = (rules_root / rel_path).resolve()
	except Exception:
		return None

	try:
		root_resolved = rules_root.resolve()
	except Exception:
		root_resolved = rules_root

	if not str(target).startswith(str(root_resolved)):
		return None

	return target


@dashboard_bp.route("/yara/rules/edit", methods=["GET", "POST"])
@login_required
@admin_required
def yara_rule_edit():
	"""Vista para editar el contenido de un fichero de reglas YARA."""

	rel_path = (request.values.get("path") or "").strip()
	path = _resolve_yara_rule_path(rel_path) if rel_path else _get_yara_rules_root()
	if path is None or not path.exists() or not path.is_file():
		flash("Selected YARA rule file does not exist.", "error")
		return redirect(url_for("dashboard.yara_rules_index"))

	if request.method == "POST":
		content = request.form.get("content") or ""
		try:
			path.write_text(content, encoding="utf-8")
		except Exception:
			flash("Error while saving the YARA rule file.", "error")
			return redirect(
				url_for("dashboard.yara_rule_edit", path=rel_path or path.name)
			)

		flash("YARA rule file saved.", "success")
		return redirect(url_for("dashboard.yara_rules_index"))

	try:
		current_content = path.read_text(encoding="utf-8")
	except Exception:
		current_content = ""

	return render_template(
		"yara_rule_edit.html",
		file_path=str(path),
		rel_path=rel_path or path.name,
		content=current_content,
	)


@dashboard_bp.route("/yara/rules/delete", methods=["POST"])
@login_required
@admin_required
def yara_rule_delete():
	"""Elimina un fichero de regla YARA dentro del directorio configurado."""

	rel_path = (request.form.get("path") or "").strip()
	path = _resolve_yara_rule_path(rel_path)
	if path is None or not path.exists() or not path.is_file():
		flash("Selected YARA rule file does not exist.", "error")
		return redirect(url_for("dashboard.yara_rules_index"))

	try:
		path.unlink()
	except Exception:
		flash("Error while deleting the YARA rule file.", "error")
		return redirect(url_for("dashboard.yara_rules_index"))

	flash("YARA rule file deleted.", "success")
	return redirect(url_for("dashboard.yara_rules_index"))


@dashboard_bp.route("/yara/rules/upload", methods=["POST"])
@login_required
@admin_required
def yara_rule_upload():
	"""Sube un nuevo fichero de regla YARA al directorio configurado."""

	rules_root = _get_yara_rules_root()
	if rules_root is None or not rules_root.is_dir():
		flash("YARA rules root is not a directory; upload is disabled.", "error")
		return redirect(url_for("dashboard.yara_rules_index"))

	file = request.files.get("rule_file")
	if not file or not file.filename:
		flash("Please select a YARA rule file to upload.", "error")
		return redirect(url_for("dashboard.yara_rules_index"))

	ext = os.path.splitext(file.filename)[1].lower()
	if ext not in {".yar", ".yara", ".rule"}:
		flash("Unsupported file extension for YARA rule.", "error")
		return redirect(url_for("dashboard.yara_rules_index"))

	filename = secure_filename(file.filename)
	target = rules_root / filename
	try:
		file.save(str(target))
	except Exception:
		flash("Error while saving the uploaded YARA rule file.", "error")
		return redirect(url_for("dashboard.yara_rules_index"))

	flash("YARA rule file uploaded.", "success")
	return redirect(url_for("dashboard.yara_rules_index"))



MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB
# Extensiones permitidas para subida y análisis desde el dashboard.
# Incluimos formatos Office con soporte de macros (docm/xlsm/pptm)
# para poder detectar VBA malicioso.
ALLOWED_EXTENSIONS = {
	"exe",
	"pdf",
	"doc",
	"docx",
	"docm",
	"xls",
	"xlsx",
	"xlsm",
	"ppt",
	"pptx",
	"pptm",
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


def _compute_hashes(path: Path) -> dict[str, str]:
	"""Compute basic integrity hashes (MD5, SHA1, SHA256) for a file.

	This is a lightweight wrapper kept close to the upload code so
	that the File model always stores a stable checksum snapshot at
	upload time, independent from the analysis lifecycle.
	"""

	import hashlib

	md5 = hashlib.md5()
	sha1 = hashlib.sha1()
	sha256 = hashlib.sha256()

	with path.open("rb") as fh:
		for chunk in iter(lambda: fh.read(8192), b""):
			md5.update(chunk)
			sha1.update(chunk)
			sha256.update(chunk)

	return {
		"md5": md5.hexdigest(),
		"sha1": sha1.hexdigest(),
		"sha256": sha256.hexdigest(),
	}


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
	# Admins see all logs; normal users only see their own activity
	if not getattr(current_user, "is_admin", False):
		query = query.filter(Log.user_id == current_user.id)
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
	checksums = _compute_hashes(Path(full_path))

	new_file = File(
		user_id=current_user.id,
		filename_original=original_name,
		filename_stored=stored_name,
		file_type=ext.replace(".", "").upper(),
		mime_type=file.mimetype,
		size=size_bytes,
		upload_date=datetime.utcnow(),
		storage_path=full_path,
		md5=checksums.get("md5"),
		sha1=checksums.get("sha1"),
		sha256=checksums.get("sha256"),
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
	"""Unified view for uploaded files and their analyses.

	Muestra dos pestañas (Files / Analyses) en la misma página. La
	pestaña activa se controla mediante el parámetro de query
	`tab=files|analyses`.
	"""

	active_tab = request.args.get("tab", "files").lower()
	if active_tab not in {"files", "analyses"}:
		active_tab = "files"

	# Archivos subidos
	q_files = (
		db.session.query(File, Analysis, User)
		.outerjoin(Analysis, Analysis.file_id == File.id)
		.outerjoin(User, User.id == File.user_id)
		.order_by(File.upload_date.desc())
	)
	# Admins see all files; normal users only see their own uploads
	if not getattr(current_user, "is_admin", False):
		q_files = q_files.filter(File.user_id == current_user.id)

	files_payload: list[dict] = []
	for f, a, u in q_files.all():
		files_payload.append(
			{
				"id": f.id,
				"filename_original": f.filename_original,
				"filename_stored": f.filename_stored,
				"file_type": f.file_type,
				"mime_type": f.mime_type,
				"size": f.size,
				"size_human": _human_size(f.size),
				"upload_date": f.upload_date,
				"storage_path": f.storage_path,
				"sha256": getattr(a, "sha256", None),
				"md5": getattr(a, "md5", None),
				"sha1": getattr(a, "sha1", None),
				"final_verdict": getattr(a, "final_verdict", None),
				"user_username": getattr(u, "username", None),
			}
		)

	# Analyses completos (mantenemos el payload que usaba la vista antigua)
	q_analyses = (
		db.session.query(Analysis, File, User)
		.join(File, Analysis.file_id == File.id)
		.join(User, Analysis.user_id == User.id)
		.order_by(Analysis.analyzed_at.desc())
	)
	# Admins see all analyses; normal users only see their own analyses
	if not getattr(current_user, "is_admin", False):
		q_analyses = q_analyses.filter(Analysis.user_id == current_user.id)

	rows: list[dict] = []
	for a, f, u in q_analyses.all():
		rows.append(
			{
				"id": a.id,
				"analyzed_at": a.analyzed_at,
				"filename_original": f.filename_original,
				"file_type": f.file_type,
				"mime_type": f.mime_type,
				"size_human": _human_size(f.size),
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

	return render_template(
		"files.html",
		files=files_payload,
		analyses=rows,
		active_tab=active_tab,
	)


@dashboard_bp.route("/analysis", methods=["GET"])
@login_required
def analysis_list():
	"""Redirect to the unified Files/Analyses view with the
	pestaña de análisis activada."""

	return redirect(url_for("dashboard.files", tab="analyses"))


@dashboard_bp.route("/analysis/<int:analysis_id>/report", methods=["GET"])
@login_required
def analysis_report(analysis_id: int):
	"""Detailed report for a specific analysis.

	Displays all available data: hashes, metadata, engines results,
	YARA rules, macros, stego, audio, etc.
	"""

	analysis = Analysis.query.get_or_404(analysis_id)
	# Admins can see any report; normal users only their own analyses
	if not getattr(current_user, "is_admin", False) and analysis.user_id != current_user.id:
		flash("You do not have permission to view this analysis report.", "error")
		return redirect(url_for("dashboard.files", tab="analyses"))

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


@dashboard_bp.route("/analysis/<int:analysis_id>/export/json", methods=["GET"])
@login_required
def analysis_export_json(analysis_id: int):
	"""Export the full analysis report as JSON.

	Includes core Analysis fields, associated File information,
	alerts and parsed engine results where possible.
	"""

	analysis = Analysis.query.get_or_404(analysis_id)
	if not getattr(current_user, "is_admin", False) and analysis.user_id != current_user.id:
		flash("You do not have permission to export this analysis.", "error")
		return redirect(url_for("dashboard.files", tab="analyses"))
	file_obj = analysis.file
	alerts = (
		Alert.query.filter_by(analysis_id=analysis.id)
		.order_by(Alert.created_at.desc())
		.all()
	)

	def _parse_json_safe(value):
		if not value:
			return None
		try:
			return json.loads(value)
		except Exception:
			return value

	data = {
		"analysis": {
			"id": analysis.id,
			"file_id": analysis.file_id,
			"user_id": analysis.user_id,
			"analyzed_at": analysis.analyzed_at.isoformat() if analysis.analyzed_at else None,
			"md5": analysis.md5,
			"sha1": analysis.sha1,
			"sha256": analysis.sha256,
			"mime_type": analysis.mime_type,
			"macro_detected": analysis.macro_detected,
			"stego_detected": analysis.stego_detected,
			"sandbox_score": analysis.sandbox_score,
			"final_verdict": analysis.final_verdict,
			"summary": analysis.summary,
			"engine_version": analysis.engine_version,
			"ruleset_version": analysis.ruleset_version,
			"yara_result": _parse_json_safe(analysis.yara_result),
			"antivirus_result": _parse_json_safe(analysis.antivirus_result),
			"virustotal_result": _parse_json_safe(analysis.virustotal_result),
			"audio_analysis": _parse_json_safe(analysis.audio_analysis),
			"additional_results": _parse_json_safe(analysis.additional_results),
		},
		"file": None,
		"alerts": [],
	}

	if file_obj is not None:
		data["file"] = {
			"id": file_obj.id,
			"user_id": file_obj.user_id,
			"filename_original": file_obj.filename_original,
			"filename_stored": file_obj.filename_stored,
			"storage_path": file_obj.storage_path,
			"upload_date": file_obj.upload_date.isoformat() if file_obj.upload_date else None,
			"size": file_obj.size,
			"file_type": file_obj.file_type,
			"mime_type": file_obj.mime_type,
			"md5": file_obj.md5,
			"sha1": file_obj.sha1,
			"sha256": file_obj.sha256,
		}

	for a in alerts:
		data["alerts"].append(
			{
				"id": a.id,
				"user_id": a.user_id,
				"file_id": a.file_id,
				"analysis_id": a.analysis_id,
				"title": a.title,
				"severity": a.severity,
				"description": a.description,
				"is_read": a.is_read,
				"created_at": a.created_at.isoformat() if a.created_at else None,
			}
		)

	return jsonify(data)


@dashboard_bp.route("/analysis/<int:analysis_id>/export/pdf", methods=["GET"])
@login_required
def analysis_export_pdf(analysis_id: int):
	"""Export a rich, dark-mode PDF version of the analysis.

	The layout tries to mirror the structure and colors of the
	HTML analysis report: dark background, highlighted sections,
	engine blocks, macros, steganography and alerts. It includes
	as much structured information as possible from the Analysis
	object and its related metadata, while keeping long payloads
	(macro code, full base64 blobs) summarized to previews.
	"""

	from reportlab.lib.pagesizes import A4
	from reportlab.pdfgen import canvas
	from reportlab.lib import colors

	analysis = Analysis.query.get_or_404(analysis_id)
	if not getattr(current_user, "is_admin", False) and analysis.user_id != current_user.id:
		flash("You do not have permission to export this analysis.", "error")
		return redirect(url_for("dashboard.files", tab="analyses"))
	file_obj = analysis.file
	user = analysis.user
	alerts = (
		Alert.query.filter_by(analysis_id=analysis.id)
		.order_by(Alert.created_at.desc())
		.all()
	)

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

	# File information similar to the HTML report
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

	# Macro details from additional_results
	macro_details = {}
	if isinstance(additional_meta, dict):
		macro_details = additional_meta.get("macro_details") or {}
		if not isinstance(macro_details, dict):
			macro_details = {}

	# Sandbox dynamic analysis details from additional_results
	sandbox_details = None
	if isinstance(additional_meta, dict):
		sandbox_details = additional_meta.get("sandbox") or None
		if sandbox_details is not None and not isinstance(sandbox_details, dict):
			sandbox_details = None

	# Steganography details from additional_results
	stego_details = None
	if isinstance(additional_meta, dict):
		stego_details = additional_meta.get("steganography") or None
		if stego_details is not None and not isinstance(stego_details, dict):
			stego_details = None

	buffer = BytesIO()
	width, height = A4
	margin_x = 40
	margin_y = 40
	content_top = height - 60 - 24  # below header bar
	y = content_top

	bg_page = colors.HexColor("#020617")
	bg_header = colors.HexColor("#111827")
	text_main = colors.HexColor("#e5e7eb")
	text_muted = colors.HexColor("#9ca3af")
	accent_primary = colors.HexColor("#60a5fa")
	accent_success = colors.HexColor("#22c55e")
	accent_warning = colors.HexColor("#eab308")
	accent_danger = colors.HexColor("#ef4444")
	accent_secondary = colors.HexColor("#6b7280")
	border_soft = colors.HexColor("#1f2937")

	pdf = canvas.Canvas(buffer, pagesize=A4)
	pdf.setTitle(f"Forenalyze analysis #{analysis.id}")

	page_index = 0
	content_width = width - 2 * margin_x

	def _verdict_color(verdict: str | None):
		v = (verdict or "").lower()
		if v == "clean":
			return accent_success
		if v == "suspicious":
			return accent_warning
		if v in {"malicious", "critical"}:
			return accent_danger
		return accent_secondary

	def _start_page():
		"""Start a new dark-themed page with header and footer."""
		nonlocal page_index, y
		if page_index > 0:
			pdf.showPage()

		# Background
		pdf.setFillColor(bg_page)
		pdf.setStrokeColor(bg_page)
		pdf.rect(0, 0, width, height, fill=1, stroke=0)

		# Header bar with "logo" and verdict badge
		pdf.setFillColor(bg_header)
		pdf.rect(0, height - 60, width, 60, fill=1, stroke=0)

		pdf.setFillColor(text_main)
		pdf.setFont("Helvetica-Bold", 18)
		pdf.drawString(margin_x, height - 30, "Forenalyze")
		pdf.setFont("Helvetica", 9)
		pdf.setFillColor(text_muted)
		pdf.drawString(margin_x, height - 45, "Digital file analysis report")

		# Verdict badge on the right
		badge_w = 120
		badge_h = 22
		badge_x = width - margin_x - badge_w
		badge_y = height - 38
		badge_color = _verdict_color(analysis.final_verdict)
		pdf.setFillColor(badge_color)
		pdf.roundRect(badge_x, badge_y - badge_h + 4, badge_w, badge_h, 4, fill=1, stroke=0)
		pdf.setFillColor(text_main)
		pdf.setFont("Helvetica-Bold", 10)
		pdf.drawCentredString(badge_x + badge_w / 2, badge_y - 8, (analysis.final_verdict or "N/D").upper())

		# Top-right meta: analysis id + engine version
		pdf.setFont("Helvetica", 8)
		pdf.setFillColor(text_muted)
		engine = analysis.engine_version or "1.0"
		ruleset = analysis.ruleset_version or "default"
		pdf.drawRightString(width - margin_x, height - 20, f"Analysis #{analysis.id} · Engine {engine} / rules {ruleset}")

		# Footer with page number
		page_index += 1
		pdf.setFont("Helvetica", 8)
		pdf.setFillColor(text_muted)
		pdf.drawRightString(width - margin_x, margin_y - 20, f"Page {page_index}")

		# Reset drawing state for content
		pdf.setFillColor(text_main)
		pdf.setStrokeColor(border_soft)
		pdf.setFont("Helvetica", 9)
		y = content_top

	def _ensure_space(lines: int = 1, leading: int = 12):
		"""Ensure there is room for N lines; start a new page if needed."""
		nonlocal y
		needed = lines * leading + 24
		if y - needed < margin_y:
			_start_page()

	def _draw_section_title(title: str, accent_color=accent_primary):
		"""Draw a colored section title similar to a card header."""
		nonlocal y
		_ensure_space(2)
		bar_height = 16
		pdf.setFillColor(bg_header)
		pdf.rect(margin_x - 6, y - bar_height + 4, content_width + 12, bar_height, fill=1, stroke=0)
		pdf.setFillColor(accent_color)
		pdf.setFont("Helvetica-Bold", 11)
		pdf.drawString(margin_x, y - 8, title)
		y -= 22
		pdf.setFillColor(text_main)
		pdf.setFont("Helvetica", 9)

	def _draw_label_value(label: str, value: str | None):
		"""Draw a single line label: value pair, wrapped if needed."""
		nonlocal y
		text = f"{label}: {value if value not in (None, '') else 'N/D'}"
		wrapped = textwrap.wrap(text, width=100)
		for i, line in enumerate(wrapped):
			_ensure_space(1)
			pdf.drawString(margin_x, y, line)
			y -= 12

	def _draw_wrapped(text: str, bullet: str | None = None, width_chars: int = 100):
		nonlocal y
		if not text:
			return
		for raw in text.split("\n"):
			t = raw.strip()
			if not t:
				continue
			wrapped = textwrap.wrap(t, width=width_chars) or [t]
			for line in wrapped:
				_ensure_space(1)
				if bullet:
					pdf.drawString(margin_x, y, f"{bullet} {line}")
				else:
					pdf.drawString(margin_x, y, line)
				y -= 12

	def _draw_kv_block(pairs: list[tuple[str, str | None]]):
		for label, value in pairs:
			_draw_label_value(label, value)
		_y_spacer(4)

	def _y_spacer(px: int = 8):
		nonlocal y
		y -= px

	# Begin first page
	_start_page()

	# Header-level contextual line (file / user / analyzed at)
	filename = file_info.get("filename_original") or "(unknown file)"
	uploaded = file_info.get("upload_date")
	analyzed_at = analysis.analyzed_at
	owner = getattr(user, "username", None)
	info_line = f"File: {filename}"
	if owner:
		info_line += f" · User: {owner}"
	if uploaded:
		info_line += f" · Uploaded: {uploaded}"
	if analyzed_at:
		info_line += f" · Analyzed: {analyzed_at}"
	_draw_wrapped(info_line, width_chars=105)
	_y_spacer(6)

	# 1) File overview
	_draw_section_title("File overview")
	size_val = file_info.get("size")
	size_human = _human_size(size_val) if size_val is not None else "0 B"
	_draw_kv_block(
		[
			("Original name", filename),
			("Stored name", file_info.get("filename_stored")),
			("Type", file_info.get("file_type") or file_info.get("mime_type")),
			("MIME", file_info.get("mime_type")),
			("Size", size_human),
			("Storage path", file_info.get("storage_path")),
		]
	)

	# 2) Hashes
	_draw_section_title("Hashes")
	_draw_kv_block(
		[
			("MD5", file_info.get("md5")),
			("SHA1", file_info.get("sha1")),
			("SHA256", file_info.get("sha256")),
		]
	)

	# 3) Engines and verdict
	_draw_section_title("Engines & verdict")
	_draw_kv_block(
		[
			("Final verdict", analysis.final_verdict),
			("Macro detected", analysis.macro_detected),
			("Steganography detected", analysis.stego_detected),
			("Sandbox score", str(analysis.sandbox_score) if analysis.sandbox_score is not None else None),
		]
	)

	# Sandbox dynamic analysis block (optional)
	if sandbox_details or analysis.sandbox_score is not None:
		_draw_section_title("Sandbox / dynamic analysis", accent_color=accent_secondary)
		status = None
		engine = None
		family = None
		tags = []
		summary = None
		if isinstance(sandbox_details, dict):
			status = sandbox_details.get("status")
			engine = sandbox_details.get("engine")
			family = sandbox_details.get("malware_family")
			tags = sandbox_details.get("tags") or []
			summary = sandbox_details.get("summary")
		pairs: list[tuple[str, str | None]] = []
		pairs.append(("Status", status or ("N/D")))
		pairs.append(("Engine", engine or "cuckoo"))
		pairs.append(("Score", str(analysis.sandbox_score) if analysis.sandbox_score is not None else None))
		if family:
			pairs.append(("Malware family", str(family)))
		if tags:
			pairs.append(("Tags", ", ".join(str(t) for t in tags)))
		_draw_kv_block(pairs)
		if summary:
			_draw_wrapped(summary, width_chars=100)

	if clam_status or clam_detail:
		_draw_section_title("ClamAV / Antivirus", accent_color=accent_secondary)
		_draw_kv_block(
			[
				("Status", clam_status),
				("Detection", clam_detection),
			]
		)
		if clam_message:
			_draw_wrapped(clam_message, width_chars=100)
		if clam_detail:
			_draw_wrapped("Technical detail:", width_chars=100)
			_draw_wrapped(str(clam_detail)[:4000], bullet="·", width_chars=100)

	# YARA matches block
	if isinstance(yara_matches, list) and yara_matches:
		_draw_section_title("YARA rules", accent_color=accent_secondary)
		for m in yara_matches:
			rule_name = m.get("rule") or "(unnamed rule)"
			namespace = m.get("namespace") or "N/A"
			tags = ", ".join(m.get("tags") or [])
			meta = m.get("meta") or {}
			_draw_wrapped(f"Rule: {rule_name} (namespace: {namespace})", bullet="-", width_chars=100)
			if tags:
				_draw_wrapped(f"Tags: {tags}", width_chars=100)
			if meta:
				_draw_wrapped(f"Meta: {meta}", width_chars=100)
			_y_spacer(2)
	elif isinstance(yara_matches, list):
		_draw_section_title("YARA rules", accent_color=accent_secondary)
		_draw_wrapped("No YARA matches have been recorded.", width_chars=100)

	# VirusTotal block
	_draw_section_title("VirusTotal")
	if vt_data:
		if vt_summary:
			_draw_wrapped(vt_summary, width_chars=100)
		if vt_stats:
			stats_pairs = []
			for key, value in vt_stats.items():
				try:
					v_int = int(value or 0)
				except Exception:
					continue
				if v_int <= 0:
					continue
				stats_pairs.append((key.replace("-", " "), str(v_int)))
			if stats_pairs:
				for label, v in stats_pairs:
					_draw_wrapped(f"{label.capitalize()}: {v}", bullet="·", width_chars=100)
		if vt_total is not None and vt_positives is not None:
			_draw_wrapped(f"Engines that detect the file: {vt_positives}/{vt_total}", width_chars=100)
		elif vt_total is not None:
			_draw_wrapped(f"Engines analyzed: {vt_total}", width_chars=100)
		if file_info.get("sha256"):
			_draw_wrapped(
				f"Link: https://www.virustotal.com/gui/file/{file_info.get('sha256')}",
				width_chars=100,
			)
	else:
		_draw_wrapped("There is no VirusTotal information for this analysis.", width_chars=100)

	# 4) Macro analysis block
	if macro_details:
		_draw_section_title("Macro analysis (VBA)")
		macro_count = macro_details.get("macro_count")
		code_size = macro_details.get("code_size")
		indicators = macro_details.get("indicators") or []
		modules = macro_details.get("modules") or []
		_draw_kv_block(
			[
				("Macro count", str(macro_count) if macro_count is not None else None),
				("Total VBA size", f"{code_size} bytes" if code_size is not None else None),
				("Indicators", f"{len(indicators)} suspicious patterns" if indicators else "None recorded"),
			]
		)
		if indicators:
			_draw_wrapped("Suspicious indicators:", width_chars=100)
			for ind in indicators:
				itype = ind.get("type") or "keyword"
				kw = ind.get("keyword") or "?"
				desc = ind.get("description") or ""
				line = f"[{itype}] {kw}"
				if desc:
					line += f" - {desc}"
				_draw_wrapped(line, bullet="-", width_chars=100)
		if modules:
			_y_spacer(4)
			_draw_wrapped("Extracted VBA modules (previews):", width_chars=100)
			for m in modules:
				name = m.get("vba_filename") or "Module"
				fname = m.get("filename") or ""
				spath = m.get("stream_path") or ""
				length = m.get("length") or 0
				header = name
				if fname:
					header += f" ({fname})"
				if spath:
					header += f" [{spath}]"
				header += f" · {length} chars"
				_draw_wrapped(header, bullet="-", width_chars=100)
				code_preview = m.get("code_preview") or ""
				if code_preview:
					_draw_wrapped(code_preview[:1200], width_chars=100)
				_y_spacer(4)
	elif analysis.macro_detected == "yes":
		_draw_section_title("Macro analysis (VBA)")
		_draw_wrapped(
			"Macros have been detected in this document, but detailed VBA extraction is not available.",
			width_chars=100,
		)

	# 5) Steganography and hidden content
	if stego_details or analysis.stego_detected in {"possible", "yes", "no"}:
		_draw_section_title("Hidden content & steganography")
		status_line = None
		if stego_details and isinstance(stego_details, dict):
			st = stego_details.get("status") or analysis.stego_detected
			status_line = f"Status: {st}"
		elif analysis.stego_detected:
			status_line = f"Status: {analysis.stego_detected}"
		if status_line:
			_draw_wrapped(status_line, width_chars=100)
		if stego_details and isinstance(stego_details, dict):
			methods = stego_details.get("methods") or []
			if methods:
				_draw_wrapped("Methods:", width_chars=100)
				for m in methods:
					_draw_wrapped(str(m), bullet="-", width_chars=100)
			notes = stego_details.get("notes") or []
			if notes:
				_y_spacer(2)
				_draw_wrapped("Notes:", width_chars=100)
				for n in notes:
					_draw_wrapped(str(n), bullet="-", width_chars=100)
			messages = stego_details.get("messages") or []
			if messages:
				_y_spacer(2)
				_draw_wrapped("Extracted text candidates:", width_chars=100)
				for msg in messages:
					source = msg.get("source") or "LSB"
					length = msg.get("length") or 0
					preview = msg.get("preview") or ""
					_draw_wrapped(f"[{source}] {length} characters", bullet="-", width_chars=100)
					_draw_wrapped(preview[:800], width_chars=100)
			base64_list = stego_details.get("base64") or []
			if base64_list:
				_y_spacer(2)
				_draw_wrapped("Decoded base64 payloads (previews):", width_chars=100)
				for b in base64_list:
					source = b.get("source") or "base64"
					dtype = b.get("decoded_type") or "text"
					length = b.get("decoded_length")
					line = f"[{source}] type={dtype}"
					if length is not None:
						line += f" · {length} bytes"
					_draw_wrapped(line, bullet="-", width_chars=100)
					decoded_preview = b.get("decoded_preview") or ""
					if decoded_preview:
						_draw_wrapped(decoded_preview[:800], width_chars=100)

	# 6) Audio analysis (if any)
	if audio_info or audio_spectrogram:
		_draw_section_title("Audio analysis")
		if isinstance(audio_info, dict):
			for k, v in audio_info.items():
				_draw_label_value(str(k), str(v))
		elif audio_info:
			_draw_wrapped(str(audio_info), width_chars=100)
		if audio_spectrogram:
			_draw_wrapped(
				f"Spectrogram generated at static/{audio_spectrogram} (see HTML report).",
				width_chars=100,
			)

	# 7) Additional metadata (excluding keys already expanded)
	if isinstance(additional_meta, dict):
		remaining = {
			k: v
			for k, v in additional_meta.items()
			if k not in {"macro_details", "steganography", "audio_spectrogram"}
		}
		if remaining:
			_draw_section_title("Additional metadata")
			for k, v in remaining.items():
				_draw_wrapped(f"{k}: {v}", bullet="-", width_chars=100)

	# 8) Related alerts
	_draw_section_title("Related alerts")
	if alerts:
		for a in alerts:
			sev = (a.severity or "info").lower()
			title = a.title or "Alert"
			desc = a.description or ""
			created_at = a.created_at if a.created_at else ""
			base = f"[{sev}] {title} ({created_at})"
			_draw_wrapped(base, bullet="-", width_chars=100)
			if desc:
				_draw_wrapped(desc, width_chars=100)
	else:
		_draw_wrapped("There are no alerts associated with this analysis.", width_chars=100)

	# 9) Engine information
	_draw_section_title("Engine information")
	_draw_kv_block(
		[
			("Engine version", analysis.engine_version or "N/D"),
			("Ruleset version", analysis.ruleset_version or "N/D"),
			("Analysis ID", f"#{analysis.id}"),
		]
	)

	# 10) Summary (final narrative)
	_draw_section_title("Summary")
	summary_text = analysis.summary or "(no summary available)"
	_draw_wrapped(summary_text, width_chars=105)

	pdf.save()
	buffer.seek(0)

	filename_safe = f"analysis_{analysis.id}.pdf"
	return send_file(
		buffer,
		mimetype="application/pdf",
		as_attachment=True,
		download_name=filename_safe,
	)


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


@dashboard_bp.route("/analysis/<int:analysis_id>/macro_payload", methods=["GET"])
@login_required
def macro_payload(analysis_id: int):
	"""Devuelve el código completo de un módulo VBA como JSON.

	Se utiliza desde el informe de análisis para poblar un modal con
	el módulo seleccionado cuando el usuario solicita ver el código
	completo. Trabaja sobre additional_results['macro_details'].
	"""

	index = request.args.get("index", "0")
	try:
		idx = int(index)
	except ValueError:
		idx = 0

	analysis = Analysis.query.get_or_404(analysis_id)

	try:
		additional_meta = json.loads(analysis.additional_results) if analysis.additional_results else {}
	except Exception:
		additional_meta = {}

	macro = additional_meta.get("macro_details") or {}
	modules = macro.get("modules") or []
	if not isinstance(modules, list) or not modules:
		return jsonify({"error": "No macro modules are available for this analysis."}), 404

	if idx < 0 or idx >= len(modules):
		return jsonify({"error": "Requested module index is out of range."}), 404

	entry = modules[idx] or {}
	content = entry.get("code_full") or entry.get("code_preview") or ""
	label_parts = []
	if entry.get("vba_filename"):
		label_parts.append(str(entry.get("vba_filename")))
	if entry.get("filename"):
		label_parts.append(f"({entry.get('filename')})")
	label = " ".join(label_parts) if label_parts else "VBA macro module"

	return jsonify(
		{
			"index": idx,
			"label": label,
			"content": str(content),
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



