import os
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    # Security: Secret key for Flask sessions & CSRF
    SECRET_KEY = os.environ.get('SECRET_KEY', 'securevote-super-secret-production-grade-key-2026-xyz!')
    
    # Security: Passphrase used to encrypt the RSA Private Key on disk
    RSA_PASSPHRASE = os.environ.get('RSA_PASSPHRASE', 'SecureVoteDefaultKeyPassphrase2026!')
    
    # Database
    DATABASE = os.environ.get('DATABASE', os.path.join(BASE_DIR, 'securevote.db'))
    
    # RSA Key storage
    KEYS_DIR = os.path.join(BASE_DIR, 'keys')
    PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, 'private.pem')
    PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, 'public.pem')
    
    # Session security hardening
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=15)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    # Default to False for localhost HTTP development, True when behind HTTPS
    SESSION_COOKIE_SECURE = os.environ.get('FLASK_ENV') == 'production'
    
    # Brute-force protection: Lock account for 5 mins after 5 failed attempts
    MAX_FAILED_LOGINS = 5
    LOCKOUT_DURATION_MINUTES = 5

