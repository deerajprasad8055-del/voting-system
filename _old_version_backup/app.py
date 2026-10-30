"""
Main Application Factory and Entrypoint for Secure Online Voting System.
Configures Flask, SQLAlchemy, CSRF, Limiter, Security Headers, and Blueprints.
"""

import os
from datetime import datetime, timezone
from flask import Flask, render_template, request, session, g
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from config import config_by_name
from models import db, User
from auth_utils import get_current_user

csrf = CSRFProtect()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)


def create_app(config_name=None):
    """Factory to create and configure the Flask application."""
    if config_name is None:
        config_name = os.environ.get("FLASK_ENV", "development")

    app = Flask(__name__)
    app.config.from_object(config_by_name.get(config_name, config_by_name["development"]))

    # Initialize extensions
    db.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    # Register blueprints
    from routes.auth import auth_bp
    from routes.voter import voter_bp
    from routes.admin import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(voter_bp)
    app.register_blueprint(admin_bp)

    # Apply Rate Limiting to sensitive auth routes
    limiter.limit("10 per minute")(auth_bp)

    # Security Headers Middleware
    @app.after_request
    def set_security_headers(response):
        # Strict Content Security Policy allowing Chart.js and Google Fonts
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com data:; "
            "img-src 'self' data:; "
            "connect-src 'self';"
        )
        response.headers["Content-Security-Policy"] = csp
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        return response

    # Global Context Processor for Templates
    @app.context_processor
    def inject_globals():
        user = get_current_user()
        return {
            "current_user": user,
            "now": datetime.now(timezone.utc),
            "app_name": "Cryptovote",
            "app_full_title": "Secure Hybrid RSA+AES Online Voting System"
        }

    # Error Handlers
    @app.errorhandler(400)
    def bad_request(e):
        return render_template("errors/400.html", error=e), 400

    @app.errorhandler(403)
    def forbidden(e):
        return render_template("errors/403.html", error=e), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template("errors/404.html", error=e), 404

    @app.errorhandler(429)
    def ratelimit_handler(e):
        return render_template("errors/429.html", error=e), 429

    @app.errorhandler(500)
    def internal_error(e):
        return render_template("errors/500.html", error=e), 500

    # Ensure tables exist
    with app.app_context():
        db.create_all()

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
