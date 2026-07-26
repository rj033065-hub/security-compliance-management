"""
services/log_service.py
Activity logging helper – records every important action into the ActivityLog table.
"""
from flask_login import current_user
from flask import request as flask_request
from models import db, ActivityLog


def log_activity(action: str, details: str = ''):
    """Write a row to activity_logs. Safe to call even outside request context."""
    try:
        if current_user and current_user.is_authenticated:
            user_id   = current_user.id
            user_name = current_user.email
            user_role = current_user.role
        else:
            user_id   = None
            user_name = 'System'
            user_role = 'System'

        ip = flask_request.remote_addr if flask_request else None

        log = ActivityLog(
            user_id    = user_id,
            user_name  = user_name,
            user_role  = user_role,
            action     = action,
            details    = details,
            ip_address = ip,
        )
        db.session.add(log)
        db.session.commit()
    except Exception:
        db.session.rollback()
