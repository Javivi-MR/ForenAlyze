from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, Optional

from flask import Request, current_app, has_request_context, request
from flask_login import current_user

from app.extensions import db
from app.models import Log, User


def _get_client_ip(req: Request | None) -> Optional[str]:
    if req is None:
        return None

    # Soporta entornos detrás de proxys reversos
    forwarded_for = req.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        # Tomamos la primera IP de la cadena
        ip = forwarded_for.split(",")[0].strip()
        if ip:
            return ip

    return req.remote_addr


def log_event(
    *,
    action: str,
    message: str | None = None,
    status: str | None = "success",
    resource: str | None = None,
    user: User | None = None,
    extra: Dict[str, Any] | None = None,
) -> None:
    """Registra un evento de actividad de forma centralizada.

    - `action`: etiqueta corta del evento (login, logout, upload, analysis_completed...).
    - `message`: descripción legible para humanos.
    - `status`: estado asociado (success, failed, warning, info...).
    - `resource`: identificador lógico del recurso o vista.
    - `user`: usuario explícito (p.ej. en hilos en background). Si no se pasa,
      se intenta usar `current_user` cuando haya contexto de petición.
    - `extra`: diccionario con detalles (se almacena como JSON en `details`).
    """

    try:
        # Contexto de usuario
        user_obj: User | None = user
        if user_obj is None and hasattr(current_user, "is_authenticated"):
            try:
                if current_user.is_authenticated:
                    user_obj = current_user
            except Exception:
                # current_user puede lanzar si no hay contexto de app/login
                user_obj = None

        user_id = getattr(user_obj, "id", None)
        username = getattr(user_obj, "username", None)

        # Contexto de red / cliente (solo si hay request)
        ip_addr = None
        user_agent_str = None
        if has_request_context():
            try:
                ip_addr = _get_client_ip(request)
                ua = request.user_agent.string if request.user_agent else None
                if ua:
                    user_agent_str = ua[:255]
            except Exception:
                ip_addr = None
                user_agent_str = None

        log = Log(
            created_at=datetime.utcnow(),
            user_id=user_id,
            username=username,
            ip_address=ip_addr,
            user_agent=user_agent_str,
            action=action,
            resource=resource,
            status=status,
            message=message,
            details=json.dumps(extra, ensure_ascii=False) if extra else None,
        )

        db.session.add(log)
        db.session.commit()

    except Exception as exc:
        # Los errores de logging nunca deben tumbar la petición principal.
        try:
            current_app.logger.exception("Error persisting audit log: %s", exc)
        except Exception:
            pass
        try:
            db.session.rollback()
        except Exception:
            pass
