# Routes package for Secure Online Voting System
from routes.auth import auth_bp
from routes.voter import voter_bp
from routes.admin import admin_bp

__all__ = ["auth_bp", "voter_bp", "admin_bp"]
