"""
Authentication & Authorization helpers and password validators.
"""

import re
from functools import wraps
from typing import Optional, Tuple
from flask import session, flash, redirect, url_for, request, abort, g
from models import User


def validate_password_strength(password: str) -> Tuple[bool, Optional[str]]:
    """
    Validate password complexity:
    - Minimum 8 characters
    - At least 1 uppercase letter
    - At least 1 lowercase letter
    - At least 1 digit
    - At least 1 special character
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter (A-Z)."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter (a-z)."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one digit (0-9)."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>\-_+=\[\]]", password):
        return False, "Password must contain at least one special character."
    return True, None


def get_current_user() -> Optional[User]:
    """Retrieve the currently logged-in user from the database."""
    user_id = session.get("user_id")
    if not user_id:
        return None
    if not hasattr(g, "current_user") or g.current_user is None or g.current_user.id != user_id:
        from models import db
        g.current_user = db.session.get(User, user_id)
    return g.current_user


def login_required(f):
    """Decorator to require login for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("auth.login", next=request.url))
        user = get_current_user()
        if not user:
            session.clear()
            flash("Session expired or user not found. Please log in again.", "warning")
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator to require admin role for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in with administrator credentials.", "warning")
            return redirect(url_for("auth.login", next=request.url))
        user = get_current_user()
        if not user or user.role != "admin":
            flash("Access denied. Administrator privileges required.", "danger")
            abort(403)
        return f(*args, **kwargs)
    return decorated_function
