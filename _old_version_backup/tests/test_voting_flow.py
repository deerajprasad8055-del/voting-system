"""
Tests for user authentication, voting workflow, authorization, and tally certification.
"""

from datetime import datetime, timezone, timedelta
import json
import pytest
from models import db, User, Election, Candidate, VoterStatus, Ballot
from crypto_utils import load_private_key, verify_result


def test_user_registration_and_password_strength(client, app):
    """Test voter registration with password complexity enforcement."""
    # 1. Weak password rejected
    resp = client.post("/register", data={
        "name": "Jane Doe",
        "email": "jane@test.com",
        "voter_id": "VOT-JANE1",
        "password": "simple",
        "confirm_password": "simple"
    }, follow_redirects=True)
    assert b"Password must be at least 8 characters" in resp.data or b"uppercase" in resp.data

    # 2. Strong password accepted
    resp = client.post("/register", data={
        "name": "Jane Doe",
        "email": "jane@test.com",
        "voter_id": "VOT-JANE1",
        "password": "StrongPassword2026!",
        "confirm_password": "StrongPassword2026!"
    }, follow_redirects=True)
    assert b"Registration successful" in resp.data

    with app.app_context():
        user = User.query.filter_by(email="jane@test.com").first()
        assert user is not None
        assert user.check_password("StrongPassword2026!") is True
        assert user.check_password("WrongPassword") is False


def test_login_lockout_after_failed_attempts(client, voter_user, app):
    """Test account lockout triggered after 5 consecutive failed login attempts."""
    # Issue 5 incorrect password attempts
    for _ in range(5):
        resp = client.post("/login", data={
            "identifier": voter_user.email,
            "password": "WrongPassword123!"
        }, follow_redirects=True)

    with app.app_context():
        u = db.session.get(User, voter_user.id)
        assert u.failed_attempts == 5
        assert u.is_locked() is True

    # 6th attempt should be blocked as locked
    resp = client.post("/login", data={
        "identifier": voter_user.email,
        "password": "Voter@Test2026!"
    }, follow_redirects=True)
    assert b"temporarily locked" in resp.data


def test_successful_vote_casting_and_receipt(client, voter_user, test_election, app):
    """Test successful ballot encryption and receipt generation."""
    # Log in as voter
    with client.session_transaction() as sess:
        sess["user_id"] = voter_user.id
        sess["user_email"] = voter_user.email
        sess["user_role"] = "voter"

    candidates = test_election.candidates
    chosen_candidate = candidates[0]

    # Cast vote
    resp = client.post(f"/vote/{test_election.id}", data={
        "candidate_id": chosen_candidate.id,
        "confirm_accuracy": "y"
    }, follow_redirects=True)

    assert b"Ballot Successfully Cast" in resp.data or b"Official Ballot Tracking Hash" in resp.data

    with app.app_context():
        # Check participation recorded
        vs = VoterStatus.query.filter_by(user_id=voter_user.id, election_id=test_election.id).first()
        assert vs is not None
        assert vs.has_voted is True

        # Check anonymous ballot stored
        ballots = Ballot.query.filter_by(election_id=test_election.id).all()
        assert len(ballots) == 1
        b = ballots[0]
        assert b.prev_hash == "GENESIS"
        assert len(b.ballot_hash) == 64


def test_double_voting_rejected(client, voter_user, test_election, app):
    """Test that a user cannot vote twice in the same election."""
    with client.session_transaction() as sess:
        sess["user_id"] = voter_user.id
        sess["user_email"] = voter_user.email
        sess["user_role"] = "voter"

    candidate_id = test_election.candidates[0].id

    # 1. First vote succeeds
    resp1 = client.post(f"/vote/{test_election.id}", data={
        "candidate_id": candidate_id,
        "confirm_accuracy": "y"
    }, follow_redirects=True)
    assert resp1.status_code == 200

    # 2. Second vote is blocked
    resp2 = client.post(f"/vote/{test_election.id}", data={
        "candidate_id": candidate_id,
        "confirm_accuracy": "y"
    }, follow_redirects=True)
    assert b"already cast your ballot" in resp2.data or b"already voted" in resp2.data

    with app.app_context():
        ballots = Ballot.query.filter_by(election_id=test_election.id).all()
        assert len(ballots) == 1  # Exactly one ballot registered


def test_voting_outside_window_rejected(client, voter_user, election_keypair, app):
    """Voting is rejected when outside scheduled window or when election is not open."""
    now = datetime.now(timezone.utc)

    # Future election
    with app.app_context():
        future_el = Election(
            title="Future Election",
            start_time=now + timedelta(days=2),
            end_time=now + timedelta(days=5),
            status="open",
            public_key_pem=election_keypair["pub_pem"]
        )
        db.session.add(future_el)
        db.session.commit()
        future_id = future_el.id

    with client.session_transaction() as sess:
        sess["user_id"] = voter_user.id
        sess["user_email"] = voter_user.email
        sess["user_role"] = "voter"

    resp = client.get(f"/vote/{future_id}", follow_redirects=True)
    assert b"outside its active voting time window" in resp.data or b"not open" in resp.data


def test_non_admin_cannot_access_admin_routes(client, voter_user):
    """Voters cannot access administrator endpoints."""
    with client.session_transaction() as sess:
        sess["user_id"] = voter_user.id
        sess["user_email"] = voter_user.email
        sess["user_role"] = "voter"

    # Attempt accessing admin dashboard
    resp = client.get("/admin/dashboard")
    assert resp.status_code == 403


def test_full_election_tally_and_signature(client, admin_user, multiple_voters, test_election, election_keypair, app):
    """
    Full End-to-End Election Cycle:
    1. 5 voters cast encrypted ballots for candidates
    2. Admin closes election
    3. Admin tallies with RSA private key & passphrase
    4. Verify exact candidate vote totals and RSA-PSS signature
    """
    candidates = test_election.candidates
    c1, c2, c3 = candidates[0], candidates[1], candidates[2]

    # Votes distribution: c1 gets 3 votes, c2 gets 1 vote, c3 gets 1 vote
    votes_plan = [c1.id, c1.id, c2.id, c1.id, c3.id]

    for voter, chosen_c_id in zip(multiple_voters, votes_plan):
        with client.session_transaction() as sess:
            sess["user_id"] = voter.id
            sess["user_email"] = voter.email
            sess["user_role"] = "voter"

        resp = client.post(f"/vote/{test_election.id}", data={
            "candidate_id": chosen_c_id,
            "confirm_accuracy": "y"
        }, follow_redirects=True)
        assert resp.status_code == 200

    # Admin closes election
    with client.session_transaction() as sess:
        sess["user_id"] = admin_user.id
        sess["user_email"] = admin_user.email
        sess["user_role"] = "admin"

    resp_close = client.post(f"/admin/election/{test_election.id}/status/closed", follow_redirects=True)
    assert resp_close.status_code == 200

    # Admin tallies election using private key and passphrase
    resp_tally = client.post(f"/admin/election/{test_election.id}/tally", data={
        "private_key_text": election_keypair["priv_pem"],
        "passphrase": election_keypair["passphrase"]
    }, follow_redirects=True)

    assert resp_tally.status_code == 200
    assert b"successfully decrypted, tallied, and cryptographically certified" in resp_tally.data

    with app.app_context():
        el = db.session.get(Election, test_election.id)
        assert el.status == "tallied"
        assert el.result_json is not None
        assert el.result_signature is not None

        tally_data = json.loads(el.result_json)
        assert tally_data["total_ballots"] == 5
        assert tally_data["invalid_ballots"] == 0

        # Verify candidate counts
        cand_map = {c["candidate_id"]: c["votes"] for c in tally_data["candidates"]}
        assert cand_map[c1.id] == 3
        assert cand_map[c2.id] == 1
        assert cand_map[c3.id] == 1

        # Verify cryptographic RSA-PSS signature
        is_valid = verify_result(
            tally_json=el.result_json,
            signature_b64=el.result_signature,
            public_key=el.public_key_pem
        )
        assert is_valid is True


def test_public_receipt_verification(client, voter_user, test_election, app):
    """Test looking up a ballot receipt on the public verification page."""
    with client.session_transaction() as sess:
        sess["user_id"] = voter_user.id
        sess["user_email"] = voter_user.email
        sess["user_role"] = "voter"

    client.post(f"/vote/{test_election.id}", data={
        "candidate_id": test_election.candidates[0].id,
        "confirm_accuracy": "y"
    }, follow_redirects=True)

    with app.app_context():
        ballot = Ballot.query.filter_by(election_id=test_election.id).first()
        b_hash = ballot.ballot_hash

    # Public verification lookup
    resp = client.post("/verify", data={"ballot_hash": b_hash})
    assert b"Ballot Confirmed Intact" in resp.data
    assert b"Cryptographic Chain Verification: Passed" in resp.data
