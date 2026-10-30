"""
Database Models for Secure Online Voting System.
Includes User, Election, Candidate, VoterStatus, Ballot, and AuditLog.
Enforces separation between Voter participation (VoterStatus) and cast votes (Ballot).
"""

from datetime import datetime, timezone, timedelta
from typing import Optional
from flask_sqlalchemy import SQLAlchemy
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError

db = SQLAlchemy()
ph = PasswordHasher()


class User(db.Model):
    """
    User model for voters and administrators.
    Passwords hashed with Argon2id. Supports account lockout on consecutive failed attempts.
    """
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    voter_id = db.Column(db.String(50), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="voter")  # 'voter' or 'admin'
    failed_attempts = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationship to voter participation tracking
    voter_statuses = db.relationship("VoterStatus", backref="user", lazy=True, cascade="all, delete-orphan")

    def set_password(self, password: str) -> None:
        """Hash and set user password using Argon2id."""
        self.password_hash = ph.hash(password)

    def check_password(self, password: str) -> bool:
        """Verify user password against Argon2 hash."""
        try:
            return ph.verify(self.password_hash, password)
        except (VerifyMismatchError, InvalidHashError):
            return False

    def is_locked(self) -> bool:
        """Check if account is temporarily locked due to failed attempts."""
        if self.locked_until is None:
            return False
        # Normalize comparison to UTC
        now = datetime.now(timezone.utc)
        locked_until_dt = self.locked_until
        if locked_until_dt.tzinfo is None:
            locked_until_dt = locked_until_dt.replace(tzinfo=timezone.utc)
        return now < locked_until_dt

    def record_failed_attempt(self, max_attempts: int = 5, lockout_minutes: int = 15) -> bool:
        """
        Record a failed login attempt. If threshold reached, lock the account.
        Returns True if the account is now locked.
        """
        self.failed_attempts += 1
        if self.failed_attempts >= max_attempts:
            self.locked_until = datetime.now(timezone.utc) + timedelta(minutes=lockout_minutes)
            return True
        return False

    def reset_failed_attempts(self) -> None:
        """Reset failed login attempts and clear lockout on successful login."""
        self.failed_attempts = 0
        self.locked_until = None

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


class Election(db.Model):
    """
    Election model.
    Stores metadata, public key, status, and certified signed results.
    """
    __tablename__ = "elections"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), nullable=False, default="draft")  # draft, open, closed, tallied
    public_key_pem = db.Column(db.Text, nullable=False)
    result_json = db.Column(db.Text, nullable=True)
    result_signature = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    candidates = db.relationship("Candidate", backref="election", lazy=True, cascade="all, delete-orphan", order_by="Candidate.id")
    ballots = db.relationship("Ballot", backref="election", lazy=True, cascade="all, delete-orphan", order_by="Ballot.id")
    voter_statuses = db.relationship("VoterStatus", backref="election", lazy=True, cascade="all, delete-orphan")

    def is_within_voting_window(self) -> bool:
        """Check if current time is between start_time and end_time."""
        now = datetime.now(timezone.utc)
        st = self.start_time.replace(tzinfo=timezone.utc) if self.start_time.tzinfo is None else self.start_time
        et = self.end_time.replace(tzinfo=timezone.utc) if self.end_time.tzinfo is None else self.end_time
        return st <= now <= et

    def is_active_for_voting(self) -> bool:
        """Active if status is 'open' and within scheduled window."""
        return self.status == "open" and self.is_within_voting_window()


class Candidate(db.Model):
    """
    Candidate model for an election.
    """
    __tablename__ = "candidates"

    id = db.Column(db.Integer, primary_key=True)
    election_id = db.Column(db.Integer, db.ForeignKey("elections.id"), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    party = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)


class VoterStatus(db.Model):
    """
    Tracks whether a user has voted in a specific election.
    Contains NO link to which candidate was chosen or which ballot was cast.
    Enforces One-Person-One-Vote via unique constraint on (user_id, election_id).
    """
    __tablename__ = "voter_statuses"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    election_id = db.Column(db.Integer, db.ForeignKey("elections.id"), nullable=False)
    has_voted = db.Column(db.Boolean, nullable=False, default=False)
    voted_at = db.Column(db.DateTime, nullable=True)

    __table_args__ = (
        db.UniqueConstraint("user_id", "election_id", name="uq_user_election"),
    )


class Ballot(db.Model):
    """
    Encrypted Ballot stored anonymously.
    Has NO foreign key or reference to user_id or voter.
    Forms a cryptographic SHA-256 hash chain with previous ballot.
    """
    __tablename__ = "ballots"

    id = db.Column(db.Integer, primary_key=True)
    election_id = db.Column(db.Integer, db.ForeignKey("elections.id"), nullable=False)
    encrypted_vote = db.Column(db.Text, nullable=False)  # Base64 AES-256-GCM ciphertext + tag
    wrapped_key = db.Column(db.Text, nullable=False)     # Base64 RSA-OAEP encrypted AES key
    nonce = db.Column(db.Text, nullable=False)           # Base64 96-bit AES-GCM nonce
    prev_hash = db.Column(db.String(64), nullable=False) # SHA-256 of previous ballot in chain
    ballot_hash = db.Column(db.String(64), nullable=False, index=True) # SHA-256 of this ballot
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class AuditLog(db.Model):
    """
    Tamper-evident audit log for election lifecycle and authentication events.
    NEVER logs vote content or choices.
    """
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    actor_id = db.Column(db.Integer, nullable=True)
    actor_email = db.Column(db.String(120), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
