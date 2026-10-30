"""
Audit logging utility for Secure Online Voting System.
"""

from typing import Optional
from flask import request, session
from datetime import datetime, timezone
from models import db, AuditLog


def log_audit(
    action: str,
    details: Optional[str] = None,
    actor_id: Optional[int] = None,
    actor_email: Optional[str] = None
) -> None:
    """
    Record an audit log entry.
    Extracts current user/IP from Flask context if available.
    """
    try:
        ip_address = None
        if request:
            ip_address = request.headers.get("X-Forwarded-For", request.remote_addr)
            if actor_id is None and session:
                actor_id = session.get("user_id")
            if actor_email is None and session:
                actor_email = session.get("user_email")

        entry = AuditLog(
            timestamp=datetime.now(timezone.utc),
            actor_id=actor_id,
            actor_email=actor_email,
            action=action,
            details=details,
            ip_address=ip_address
        )
        db.session.add(entry)
        db.session.commit()
    except Exception as e:
        # Avoid crashing primary operations if logging encounters an issue
        try:
            db.session.rollback()
        except Exception:
            pass
