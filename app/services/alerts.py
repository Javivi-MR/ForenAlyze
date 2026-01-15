from datetime import date, datetime

from app.extensions import db
from app.models import Alert, Analysis


MALICIOUS_DAILY_THRESHOLD = 10


def create_alerts_for_analysis(analysis: Analysis):
    """Genera alertas asociadas a un análisis recién completado.

    Debe llamarse con la sesión activa (sin hacer commit dentro).
    """

    file_obj = analysis.file
    user_id = file_obj.user_id if file_obj else None

    alerts: list[Alert] = []

    # Malware / crítico
    if analysis.final_verdict in ("malicious", "critical"):
        alerts.append(
            Alert(
                user_id=user_id,
                file_id=analysis.file_id,
                analysis_id=analysis.id,
                severity="danger",
                title="Malware detectado",
                description=analysis.antivirus_result
                or "Detección maliciosa en análisis automático.",
                is_read=False,
                created_at=datetime.utcnow(),
            )
        )

    # Macros sospechosas
    if getattr(analysis, "macro_detected", "no") == "yes":
        alerts.append(
            Alert(
                user_id=user_id,
                file_id=analysis.file_id,
                analysis_id=analysis.id,
                severity="warning",
                title="Macros sospechosas",
                description="Se han detectado macros en el documento.",
                is_read=False,
                created_at=datetime.utcnow(),
            )
        )

    # Esteganografía
    if getattr(analysis, "stego_detected", "no") == "possible":
        alerts.append(
            Alert(
                user_id=user_id,
                file_id=analysis.file_id,
                analysis_id=analysis.id,
                severity="warning",
                title="Posible esteganografía",
                description="Se han detectado indicios de esteganografía en el archivo.",
                is_read=False,
                created_at=datetime.utcnow(),
            )
        )

    # Umbral diario de archivos maliciosos
    today = date.today()
    malicious_today = (
        Analysis.query.filter(
            Analysis.analyzed_at >= datetime.combine(today, datetime.min.time()),
            Analysis.analyzed_at <= datetime.combine(today, datetime.max.time()),
            Analysis.final_verdict.in_(["malicious", "critical"]),
        ).count()
    )

    if malicious_today > MALICIOUS_DAILY_THRESHOLD:
        alerts.append(
            Alert(
                user_id=user_id,
                file_id=analysis.file_id,
                analysis_id=analysis.id,
                severity="danger",
                title="Umbral diario de archivos maliciosos superado",
                description=(
                    f"Se han detectado {malicious_today} archivos maliciosos en las "
                    "últimas 24 horas."
                ),
                is_read=False,
                created_at=datetime.utcnow(),
            )
        )

    for a in alerts:
        db.session.add(a)

    # No hacemos commit aquí; lo gestiona el llamador.
    return alerts

