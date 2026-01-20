from datetime import date, datetime

from app.extensions import db
from app.models import Alert, Analysis


MALICIOUS_DAILY_THRESHOLD = 10


def create_alerts_for_analysis(analysis: Analysis):
    """Generate alerts associated with a freshly completed analysis.

    Must be called with an active session (no commit inside).
    """

    file_obj = analysis.file
    user_id = file_obj.user_id if file_obj else None

    alerts: list[Alert] = []

    # Malware / critical
    if analysis.final_verdict in ("malicious", "critical"):
        alerts.append(
            Alert(
                user_id=user_id,
                file_id=analysis.file_id,
                analysis_id=analysis.id,
                severity="danger",
                title="Malware detected",
                description=analysis.antivirus_result
                or "Malicious detection in automatic analysis.",
                is_read=False,
                created_at=datetime.utcnow(),
            )
        )

    # Suspicious macros
    if getattr(analysis, "macro_detected", "no") == "yes":
        alerts.append(
            Alert(
                user_id=user_id,
                file_id=analysis.file_id,
                analysis_id=analysis.id,
                severity="warning",
                title="Suspicious macros",
                description="Macros have been detected in the document.",
                is_read=False,
                created_at=datetime.utcnow(),
            )
        )

    # Steganography
    stego_status = getattr(analysis, "stego_detected", "no")
    if stego_status in {"possible", "yes"}:
        alerts.append(
            Alert(
                user_id=user_id,
                file_id=analysis.file_id,
                analysis_id=analysis.id,
                severity="warning" if stego_status == "possible" else "danger",
                title="Possible steganography" if stego_status == "possible" else "Steganography detected",
                description="Possible steganography has been detected in the file."
                if stego_status == "possible"
                else "Hidden content or strong steganography indicators have been found in this file.",
                is_read=False,
                created_at=datetime.utcnow(),
            )
        )

    # Daily threshold of malicious files
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
                title="Daily malicious files threshold exceeded",
                description=(
                    f"{malicious_today} malicious files have been detected in the "
                    "last 24 hours."
                ),
                is_read=False,
                created_at=datetime.utcnow(),
            )
        )

    # Generic "report ready" notification for the user.
    # This allows the bell to show new reports even when
    # they are not malicious.
    if file_obj is not None:
        filename = file_obj.filename_original or "file"
    else:
        filename = "file"

    alerts.append(
        Alert(
            user_id=user_id,
            file_id=analysis.file_id,
            analysis_id=analysis.id,
            severity="info",
            title="Report ready",
            description=(
                f"The report for file \"{filename}\" is ready for review."
            ),
            is_read=False,
            created_at=datetime.utcnow(),
        )
    )

    for a in alerts:
        db.session.add(a)

    # No hacemos commit aquí; lo gestiona el llamador.
    return alerts

