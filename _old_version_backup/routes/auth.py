"""
Authentication routes: Register, Login, Logout with Argon2, Lockout, and Rate Limiting.
"""

from datetime import datetime, timezone
from flask import Blueprint, render_template, redirect, url_for, flash, request, session, current_app
from models import db, User
from forms import LoginForm, RegisterForm
from audit_utils import log_audit

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    """Voter registration endpoint with password complexity and unique checks."""
    if "user_id" in session:
        return redirect(url_for("voter.dashboard"))

    form = RegisterForm()
    if form.validate_on_submit():
        # Check unique email
        existing_email = User.query.filter_by(email=form.email.data.strip().lower()).first()
        if existing_email:
            flash("An account with this email address already exists.", "danger")
            return render_template("auth/register.html", form=form)

        # Check unique voter ID
        existing_voter_id = User.query.filter_by(voter_id=form.voter_id.data.strip().upper()).first()
        if existing_voter_id:
            flash("An account with this Voter ID already exists.", "danger")
            return render_template("auth/register.html", form=form)

        # Create new voter user
        user = User(
            name=form.name.data.strip(),
            email=form.email.data.strip().lower(),
            voter_id=form.voter_id.data.strip().upper(),
            role="voter"
        )
        user.set_password(form.password.data)

        db.session.add(user)
        db.session.commit()

        log_audit(
            action="USER_REGISTERED",
            details=f"New voter registered: {user.voter_id}",
            actor_id=user.id,
            actor_email=user.email
        )

        flash("Registration successful! You may now log in to participate in active elections.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html", form=form)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """Login endpoint with lockout protection and rate limiting."""
    if "user_id" in session:
        user = db.session.get(User, session["user_id"])
        if user and user.role == "admin":
            return redirect(url_for("admin.dashboard"))
        return redirect(url_for("voter.dashboard"))

    form = LoginForm()
    if form.validate_on_submit():
        ident = form.identifier.data.strip()
        user = User.query.filter(
            (User.email == ident.lower()) | (User.voter_id == ident.upper())
        ).first()

        if user:
            # Check lockout
            if user.is_locked():
                remaining = int((user.locked_until.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).total_seconds() / 60) + 1
                log_audit(
                    action="LOGIN_BLOCKED_LOCKED",
                    details=f"Locked account attempted login: {user.email}",
                    actor_id=user.id,
                    actor_email=user.email
                )
                flash(f"Account is temporarily locked due to repeated failed logins. Please try again in {remaining} minute(s).", "danger")
                return render_template("auth/login.html", form=form)

            # Check password
            if user.check_password(form.password.data):
                user.reset_failed_attempts()
                db.session.commit()

                # Setup session
                session.clear()
                session["user_id"] = user.id
                session["user_name"] = user.name
                session["user_email"] = user.email
                session["user_role"] = user.role
                session.permanent = True

                log_audit(
                    action="LOGIN_SUCCESS",
                    details=f"Successful login for {user.role} {user.email}",
                    actor_id=user.id,
                    actor_email=user.email
                )

                flash(f"Welcome back, {user.name}!", "success")
                next_page = request.args.get("next")
                if next_page and next_page.startswith("/"):
                    return redirect(next_page)
                if user.role == "admin":
                    return redirect(url_for("admin.dashboard"))
                return redirect(url_for("voter.dashboard"))
            else:
                max_attempts = current_app.config.get("MAX_LOGIN_ATTEMPTS", 5)
                lockout_min = current_app.config.get("LOCKOUT_MINUTES", 15)
                is_now_locked = user.record_failed_attempt(max_attempts=max_attempts, lockout_minutes=lockout_min)
                db.session.commit()

                if is_now_locked:
                    log_audit(
                        action="ACCOUNT_LOCKED",
                        details=f"Account locked after {user.failed_attempts} failed attempts: {user.email}",
                        actor_id=user.id,
                        actor_email=user.email
                    )
                    flash(f"Too many failed login attempts. Account is locked for {lockout_min} minutes.", "danger")
                else:
                    remaining_attempts = max_attempts - user.failed_attempts
                    log_audit(
                        action="LOGIN_FAILED_BAD_PASSWORD",
                        details=f"Failed password attempt for {user.email}. Remaining: {remaining_attempts}",
                        actor_id=user.id,
                        actor_email=user.email
                    )
                    flash(f"Invalid credentials. {remaining_attempts} attempt(s) remaining before account lockout.", "danger")
        else:
            log_audit(
                action="LOGIN_FAILED_UNKNOWN_USER",
                details=f"Failed login attempt for nonexistent identifier: {ident}"
            )
            flash("Invalid email/voter ID or password.", "danger")

    return render_template("auth/login.html", form=form)


@auth_bp.route("/logout", methods=["GET", "POST"])
def logout():
    """Logout endpoint."""
    user_id = session.get("user_id")
    user_email = session.get("user_email")
    if user_id:
        log_audit(
            action="LOGOUT",
            details="User logged out",
            actor_id=user_id,
            actor_email=user_email
        )
    session.clear()
    flash("You have been securely logged out.", "info")
    return redirect(url_for("auth.login"))
