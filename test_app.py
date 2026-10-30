"""
SecureVote Test Suite
Tests cryptographic security, vote anonymity, no re-voting enforcement,
tamper detection, role-based access control, and results protection.
"""

import os
import json
import sqlite3
import pytest
from datetime import datetime, timezone, timedelta

from app import create_app
from config import Config
import database
import crypto_utils


@pytest.fixture
def app_instance(tmp_path):
    """Creates a temporary test application instance with an isolated database and keys."""
    test_db = str(tmp_path / "test_securevote.db")
    test_keys_dir = str(tmp_path / "keys")
    os.makedirs(test_keys_dir, exist_ok=True)

    test_config = {
        'TESTING': True,
        'WTF_CSRF_ENABLED': False,  # Simplified testing for POST endpoints
        'DATABASE': test_db,
        'KEYS_DIR': test_keys_dir,
        'PRIVATE_KEY_PATH': os.path.join(test_keys_dir, 'private.pem'),
        'PUBLIC_KEY_PATH': os.path.join(test_keys_dir, 'public.pem'),
        'RSA_PASSPHRASE': 'TestPassphrase123!',
        'SECRET_KEY': 'test-secret-key-xyz'
    }

    app = create_app(test_config)

    # Initialize keys and DB in test context
    with app.app_context():
        crypto_utils.generate_rsa_keypair(
            keys_dir=test_keys_dir,
            passphrase=test_config['RSA_PASSPHRASE'],
            force=True
        )
        database.init_db(test_db)

        # Seed sample data
        conn = database.get_db()
        from werkzeug.security import generate_password_hash
        conn.execute(
            """INSERT INTO users (full_name, email, voter_id, password_hash, role)
               VALUES (?, ?, ?, ?, ?)""",
            ("Admin User", "admin@test.com", "ADM-001", generate_password_hash("Admin@123", method='scrypt'), "admin")
        )
        conn.execute(
            """INSERT INTO users (full_name, email, voter_id, password_hash, role)
               VALUES (?, ?, ?, ?, ?)""",
            ("Voter One", "voter1@test.com", "VOT-001", generate_password_hash("Voter@123", method='scrypt'), "voter")
        )
        conn.execute(
            """INSERT INTO users (full_name, email, voter_id, password_hash, role)
               VALUES (?, ?, ?, ?, ?)""",
            ("Voter Two", "voter2@test.com", "VOT-002", generate_password_hash("Voter@123", method='scrypt'), "voter")
        )

        # Create Open Election #1
        cursor = conn.cursor()
        cursor.execute("INSERT INTO elections (title, description, status) VALUES (?, ?, 'open')",
                       ("General Election 2026", "National voting"))
        el_id = cursor.lastrowid
        cursor.execute("INSERT INTO candidates (election_id, name, party, description) VALUES (?, 'Candidate A', 'Party 1', 'Desc A')", (el_id,))
        cursor.execute("INSERT INTO candidates (election_id, name, party, description) VALUES (?, 'Candidate B', 'Party 2', 'Desc B')", (el_id,))

        # Create Draft Election #2
        cursor.execute("INSERT INTO elections (title, description, status) VALUES (?, ?, 'draft')",
                       ("Draft Election", "Upcoming"))

        conn.commit()

    yield app


@pytest.fixture
def client(app_instance):
    return app_instance.test_client()


# ==============================================================================
# 1. CRYPTOGRAPHIC ENCRYPTION & DECRYPTION (RSA-2048 + AES-256-GCM)
# ==============================================================================
def test_vote_encryption_decryption(app_instance):
    """Test 1: Proves that a vote encrypts and decrypts correctly using RSA + AES-256-GCM."""
    with app_instance.app_context():
        pub_key = crypto_utils.load_public_key(app_instance.config['PUBLIC_KEY_PATH'])
        priv_key = crypto_utils.load_private_key(
            app_instance.config['PRIVATE_KEY_PATH'],
            passphrase=app_instance.config['RSA_PASSPHRASE']
        )

        original_vote = {
            'election_id': 1,
            'candidate_id': 42,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'salt': 'abcdef1234567890'
        }

        # Encrypt vote
        encrypted = crypto_utils.encrypt_vote(original_vote, public_key=pub_key)
        assert 'encrypted_vote' in encrypted
        assert 'encrypted_aes_key' in encrypted
        assert 'nonce' in encrypted

        # Decrypt vote
        decrypted = crypto_utils.decrypt_vote(
            encrypted['encrypted_vote'],
            encrypted['encrypted_aes_key'],
            encrypted['nonce'],
            private_key=priv_key
        )

        assert decrypted['election_id'] == original_vote['election_id']
        assert decrypted['candidate_id'] == original_vote['candidate_id']
        assert decrypted['salt'] == original_vote['salt']


# ==============================================================================
# 2. VOTE ANONYMITY: DATABASE NEVER CONTAINS PLAINTEXT CANDIDATE IDS OR USER LINKS
# ==============================================================================
def test_database_never_contains_plaintext_candidate_ids(app_instance):
    """
    Test 2: Proves the DB never contains plaintext candidate IDs or user_ids in the ballots table.
    """
    with app_instance.app_context():
        db = database.get_db()
        candidate_id = 1
        user_id = 2  # Voter One

        receipt = database.cast_vote_atomic(
            db_conn=db,
            election_id=1,
            user_id=user_id,
            candidate_id=candidate_id,
            ip="127.0.0.1"
        )
        assert receipt['ballot_id'] is not None

        # Inspect raw ballots table
        ballot = db.execute("SELECT * FROM ballots WHERE id = ?", (receipt['ballot_id'],)).fetchone()

        # Ballots table must NOT have user_id column
        assert 'user_id' not in ballot.keys()

        # Check raw ciphertext and wrapped keys do NOT contain plaintext candidate_id
        raw_ciphertext = ballot['encrypted_vote']
        raw_key = ballot['encrypted_aes_key']
        raw_nonce = ballot['nonce']

        # Ensure plain string "candidate_id" or candidate ID value is nowhere in ciphertext
        assert f'"candidate_id": {candidate_id}' not in raw_ciphertext
        assert f'"candidate_id": {candidate_id}' not in raw_key
        assert f'"candidate_id": {candidate_id}' not in raw_nonce

        # Inspect vote_records table: contains user_id and election_id, but NO candidate info
        vote_record = db.execute("SELECT * FROM vote_records WHERE user_id = ? AND election_id = ?", (user_id, 1)).fetchone()
        assert vote_record is not None
        assert 'candidate_id' not in vote_record.keys()
        assert 'encrypted_vote' not in vote_record.keys()


# ==============================================================================
# 3. THE NO RE-VOTING RULE: SECOND VOTE IS STRICTLY REJECTED
# ==============================================================================
def test_second_vote_rejected(app_instance, client):
    """
    Test 3: Enforces NO RE-VOTING across all 3 levels:
    - Level 1 (DB constraint): SQLite UNIQUE(user_id, election_id) raises IntegrityError
    - Level 2 (Server atomic transaction): rejects duplicate vote before insert
    - Level 3 (UI route): redirects to dashboard with flash warning
    """
    with app_instance.app_context():
        db = database.get_db()
        user_id = 2  # Voter One
        election_id = 1

        # Cast first vote -> must succeed
        res1 = database.cast_vote_atomic(db, election_id, user_id, candidate_id=1)
        assert res1['ballot_id'] is not None

        # Cast second vote via atomic database helper -> must be rejected!
        with pytest.raises(ValueError) as excinfo:
            database.cast_vote_atomic(db, election_id, user_id, candidate_id=2)
        assert "already cast" in str(excinfo.value) or "rejected" in str(excinfo.value)

        # Directly attempt to insert into vote_records -> DB Level 1 UNIQUE constraint must trigger
        with pytest.raises(sqlite3.IntegrityError):
            db.execute("INSERT INTO vote_records (user_id, election_id) VALUES (?, ?)", (user_id, election_id))

    # Test via Web Client: Level 3 Route rejection
    with client.session_transaction() as sess:
        sess['user_id'] = 2
        sess['role'] = 'voter'
        sess['full_name'] = 'Voter One'

    # GET /vote/1 should redirect to /dashboard
    response = client.get('/vote/1', follow_redirects=True)
    assert b"You have already voted in this election" in response.data

    # POST /vote/1 should also redirect to /dashboard and fail
    post_response = client.post('/vote/1', data={'candidate_id': '2'}, follow_redirects=True)
    assert b"You have already voted in this election" in response.data or b"Double voting rejected" in post_response.data

    # Verify ballots table only has 1 ballot
    with app_instance.app_context():
        db = database.get_db()
        count = db.execute("SELECT COUNT(*) FROM ballots WHERE election_id = 1").fetchone()[0]
        assert count == 1


# ==============================================================================
# 4. TAMPER DETECTION: HASH CHAIN AND AES-GCM AUTH TAG
# ==============================================================================
def test_ballot_tampering_detected(app_instance):
    """
    Test 4:
    a) Modifying a stored ballot's ciphertext triggers hash chain verification failure.
    b) Tampered ciphertext triggers AES-GCM authentication tag failure (TamperError) upon decryption.
    """
    with app_instance.app_context():
        db = database.get_db()

        # Cast 2 legitimate ballots
        b1 = database.cast_vote_atomic(db, election_id=1, user_id=2, candidate_id=1)
        b2 = database.cast_vote_atomic(db, election_id=1, user_id=3, candidate_id=2)

        # Verify initial chain is valid
        is_valid, broken_id, msg, _ = crypto_utils.verify_chain(1, db)
        assert is_valid is True
        assert broken_id is None

        # --- A: Tamper with ballot 1 ciphertext in DB ---
        tampered_ciphertext = "A" * len(b1['encrypted_vote'])
        db.execute("UPDATE ballots SET encrypted_vote = ? WHERE id = ?", (tampered_ciphertext, b1['ballot_id']))
        db.commit()

        # Check 1: Hash chain detection
        is_valid, broken_id, msg, ballots_checked = crypto_utils.verify_chain(1, db)
        assert is_valid is False
        assert broken_id == b1['ballot_id']
        assert "tampered" in msg.lower() or "mismatch" in msg.lower()

        # Check 2: AES-GCM decryption detection
        priv_key = crypto_utils.load_private_key(
            app_instance.config['PRIVATE_KEY_PATH'],
            passphrase=app_instance.config['RSA_PASSPHRASE']
        )

        with pytest.raises(crypto_utils.TamperError) as excinfo:
            crypto_utils.decrypt_vote(
                tampered_ciphertext,
                b1['encrypted_aes_key'],
                b1['nonce'],
                private_key=priv_key
            )
        assert "tamper" in str(excinfo.value).lower() or "tag" in str(excinfo.value).lower()


# ==============================================================================
# 5. ROLE-BASED ACCESS CONTROL (NON-ADMINS CANNOT ACCESS ADMIN ROUTES)
# ==============================================================================
def test_non_admin_cannot_access_admin_routes(client):
    """
    Test 5: Non-admins and unauthenticated users cannot access /admin, /admin/audit, /admin/tally.
    """
    # 1. Unauthenticated request -> redirects to login
    res = client.get('/admin', follow_redirects=False)
    assert res.status_code == 302
    assert '/login' in res.headers['Location']

    # 2. Logged in as regular voter -> returns 403 Forbidden
    with client.session_transaction() as sess:
        sess['user_id'] = 2
        sess['role'] = 'voter'
        sess['full_name'] = 'Voter One'

    res_admin = client.get('/admin')
    assert res_admin.status_code == 403

    res_tally = client.get('/admin/tally/1')
    assert res_tally.status_code == 403

    res_audit = client.get('/admin/audit')
    assert res_audit.status_code == 403

    # 3. Log in as admin -> returns 200 OK
    with client.session_transaction() as sess:
        sess['user_id'] = 1
        sess['role'] = 'admin'
        sess['full_name'] = 'Admin User'

    res_admin_ok = client.get('/admin')
    assert res_admin_ok.status_code == 200


# ==============================================================================
# 6. RESULTS HIDING: HIDDEN UNTIL ELECTION IS CLOSED AND TALLIED
# ==============================================================================
def test_results_hidden_until_election_closed(client, app_instance):
    """
    Test 6: Results are strictly protected and hidden while election is open or draft.
    Only after closing and tallying are results revealed.
    """
    # Election 1 is OPEN -> results route must block / redirect
    res_open = client.get('/results/1', follow_redirects=True)
    assert b"Results are strictly protected" in res_open.data

    # Election 2 is DRAFT -> results route must block / redirect
    res_draft = client.get('/results/2', follow_redirects=True)
    assert b"Results are strictly protected" in res_draft.data

    # Close Election 1 and tally it
    with app_instance.app_context():
        db = database.get_db()
        # Cast a vote first
        database.cast_vote_atomic(db, election_id=1, user_id=2, candidate_id=1)
        # Close election
        db.execute("UPDATE elections SET status = 'closed' WHERE id = 1")
        db.commit()

    # Now election is closed, but not yet tallied
    res_closed_untallied = client.get('/results/1')
    assert b"tallying by the election administrator is pending" in res_closed_untallied.data

    # Now execute tally via admin POST
    with client.session_transaction() as sess:
        sess['user_id'] = 1
        sess['role'] = 'admin'
        sess['full_name'] = 'Admin User'

    tally_post = client.post('/admin/tally/1', follow_redirects=True)
    assert b"Cryptographic tally complete" in tally_post.data

    # Results should now be fully viewable by anyone
    res_final = client.get('/results/1')
    assert res_final.status_code == 200
    assert b"Official Tally Results" in res_final.data
    assert b"Candidate A" in res_final.data


# ==============================================================================
# 7. SECURITY HARDENING: ACCOUNT LOCKOUT AFTER 5 FAILED ATTEMPTS
# ==============================================================================
def test_account_lockout_after_five_failed_attempts(client, app_instance):
    """
    Test 7: 5 consecutive failed login attempts locks the account for 5 minutes.
    """
    email = "voter2@test.com"
    wrong_pw = "WrongPassword999!"

    # 4 failed attempts
    for i in range(1, 5):
        resp = client.post('/login', data={'email': email, 'password': wrong_pw}, follow_redirects=True)
        assert b"Invalid email or password" in resp.data

    # 5th failed attempt -> Triggers lockout
    resp5 = client.post('/login', data={'email': email, 'password': wrong_pw}, follow_redirects=True)
    assert b"Account locked for 5 minutes" in resp5.data

    # 6th attempt (even with correct password) -> Blocked due to active lockout
    resp6 = client.post('/login', data={'email': email, 'password': 'Voter@123'}, follow_redirects=True)
    assert b"Account is temporarily locked" in resp6.data

