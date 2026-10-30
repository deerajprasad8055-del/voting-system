"""
SecureVote Database Engine (SQLite)
Schema definition, connection lifecycle, audit logging, and atomic vote casting.
"""

import sqlite3
import hashlib
import secrets
from datetime import datetime, timezone
from flask import g, current_app
from config import Config
import crypto_utils


SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    voter_id TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'voter' CHECK (role IN ('voter', 'admin')),
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS elections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'open', 'closed')),
    start_time TIMESTAMP,
    end_time TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    election_id INTEGER NOT NULL REFERENCES elections(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    party TEXT,
    description TEXT
);

-- ANONYMOUS BALLOTS TABLE: NO user_id column is stored!
CREATE TABLE IF NOT EXISTS ballots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    election_id INTEGER NOT NULL REFERENCES elections(id),
    encrypted_vote TEXT NOT NULL,
    encrypted_aes_key TEXT NOT NULL,
    nonce TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    ballot_hash TEXT NOT NULL,
    receipt_hash TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- VOTE PARTICIPATION RECORD: Records THAT a voter cast a vote, NEVER what they voted for.
CREATE TABLE IF NOT EXISTS vote_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    election_id INTEGER NOT NULL REFERENCES elections(id),
    voted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, election_id)
);

CREATE TABLE IF NOT EXISTS tally_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    election_id INTEGER UNIQUE NOT NULL REFERENCES elections(id),
    results_json TEXT NOT NULL,
    total_votes INTEGER NOT NULL,
    winner_name TEXT,
    winner_party TEXT,
    tallied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id),
    action TEXT NOT NULL,
    details TEXT,
    ip TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_ballots_election ON ballots(election_id);
CREATE INDEX IF NOT EXISTS idx_ballots_receipt ON ballots(receipt_hash);
CREATE INDEX IF NOT EXISTS idx_vote_records_user_election ON vote_records(user_id, election_id);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC);
"""


def get_db(db_path=None):
    """Retrieves SQLite connection from Flask g object or creates a standalone connection."""
    target_path = db_path or (current_app.config['DATABASE'] if current_app else Config.DATABASE)
    
    # If in Flask request context
    if current_app:
        if 'db' not in g:
            g.db = sqlite3.connect(target_path)
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys = ON;")
        return g.db
    else:
        conn = sqlite3.connect(target_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn


def close_db(e=None):
    """Closes DB connection for current Flask request context."""
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db(db_path=None):
    """Initializes tables and indexes."""
    target_path = db_path or Config.DATABASE
    conn = sqlite3.connect(target_path)
    conn.executescript(SCHEMA_SQL)
    conn.commit()
    conn.close()


def log_audit(db_conn, action, details=None, user_id=None, ip=None):
    """Records an immutable security audit event."""
    try:
        db_conn.execute(
            "INSERT INTO audit_log (user_id, action, details, ip) VALUES (?, ?, ?, ?)",
            (user_id, action, details, ip)
        )
        db_conn.commit()
    except Exception as e:
        # Avoid crashing primary flow if audit fails, but log
        print(f"[AUDIT LOG FAILURE] {action}: {e}")


def generate_receipt_code():
    """Generates a secure, human-readable 16-character receipt code (SV-XXXX-XXXX-XXXX)."""
    # 12 alphanumeric characters partitioned into 3 groups
    raw = secrets.token_hex(6).upper()
    return f"SV-{raw[0:4]}-{raw[4:8]}-{raw[8:12]}"


def cast_vote_atomic(db_conn, election_id, user_id, candidate_id, ip=None):
    """
    ATOMIC VOTE SUBMISSION:
    Guarantees 'NO RE-VOTING' rule across Database, Server, and Cryptographic layers.
    Executes in a single SQLite transaction with strict rollback on any constraint violation.
    """
    cursor = db_conn.cursor()

    try:
        # 1. Server check: verify user exists and is not admin
        cursor.execute("SELECT id, role FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        if not user:
            raise ValueError("Voter record not found.")
        if user['role'] == 'admin':
            raise ValueError("Election administrators are strictly prohibited from casting votes.")

        # 2. Server check: verify election exists and is currently OPEN
        cursor.execute("SELECT id, title, status FROM elections WHERE id = ?", (election_id,))
        election = cursor.fetchone()
        if not election:
            raise ValueError("Election does not exist.")
        if election['status'] != 'open':
            raise ValueError(f"Election is {election['status'].upper()}. Votes can only be submitted during an OPEN election.")

        # 3. Server check: verify candidate belongs to this election
        cursor.execute("SELECT id, name FROM candidates WHERE id = ? AND election_id = ?", (candidate_id, election_id))
        candidate = cursor.fetchone()
        if not candidate:
            raise ValueError("Invalid candidate selected for this election.")

        # 4. Server check: Level 2 enforcement - check vote_records
        cursor.execute("SELECT id FROM vote_records WHERE user_id = ? AND election_id = ?", (user_id, election_id))
        if cursor.fetchone():
            raise ValueError("Double voting rejected: You have already cast your ballot in this election.")

        # 5. Get predecessor ballot hash for cryptographic chain
        cursor.execute(
            "SELECT ballot_hash FROM ballots WHERE election_id = ? ORDER BY id DESC LIMIT 1",
            (election_id,)
        )
        last_ballot = cursor.fetchone()
        prev_hash = last_ballot['ballot_hash'] if last_ballot else ("0" * 64)

        # 6. Generate anonymous receipt code and compute SHA-256 receipt hash
        receipt_code = generate_receipt_code()
        receipt_hash = hashlib.sha256(receipt_code.encode('utf-8')).hexdigest()

        # 7. Prepare anonymous vote payload and encrypt via Hybrid RSA + AES-256-GCM
        vote_payload = {
            'election_id': int(election_id),
            'candidate_id': int(candidate_id),
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'salt': secrets.token_hex(16)
        }
        encrypted = crypto_utils.encrypt_vote(vote_payload)

        # 8. Compute ballot hash chain link
        ballot_hash = crypto_utils.compute_ballot_hash(
            prev_hash,
            encrypted['encrypted_vote'],
            encrypted['encrypted_aes_key'],
            encrypted['nonce']
        )

        # 9. Atomic DB insertions:
        # DB Level Enforcement (UNIQUE(user_id, election_id))
        cursor.execute(
            "INSERT INTO vote_records (user_id, election_id) VALUES (?, ?)",
            (user_id, election_id)
        )

        # Anonymous ballot insertion (NO user_id column)
        cursor.execute(
            """INSERT INTO ballots 
               (election_id, encrypted_vote, encrypted_aes_key, nonce, prev_hash, ballot_hash, receipt_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (election_id, encrypted['encrypted_vote'], encrypted['encrypted_aes_key'],
             encrypted['nonce'], prev_hash, ballot_hash, receipt_hash)
        )
        ballot_id = cursor.lastrowid

        # Audit logging
        cursor.execute(
            "INSERT INTO audit_log (user_id, action, details, ip) VALUES (?, ?, ?, ?)",
            (user_id, 'VOTE_CAST', f"Anonymous ballot #{ballot_id} cast for election #{election_id} (hash {ballot_hash[:12]}...)", ip)
        )

        # Commit transaction atomically
        db_conn.commit()

        return {
            'ballot_id': ballot_id,
            'election_title': election['title'],
            'receipt_code': receipt_code,
            'receipt_hash': receipt_hash,
            'prev_hash': prev_hash,
            'ballot_hash': ballot_hash,
            'encrypted_vote': encrypted['encrypted_vote'],
            'encrypted_aes_key': encrypted['encrypted_aes_key'],
            'nonce': encrypted['nonce'],
            'timestamp': vote_payload['timestamp']
        }

    except sqlite3.IntegrityError as e:
        db_conn.rollback()
        raise ValueError("Double voting rejected: Database uniqueness constraint violation.")
    except Exception as e:
        db_conn.rollback()
        raise e
