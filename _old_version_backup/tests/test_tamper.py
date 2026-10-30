"""
Tamper resistance tests: Verifies that database-level manipulation of ballots
breaks the hash chain and prevents unauthorized tallying.
"""

import pytest
from models import db, Ballot, Election, Candidate
from crypto_utils import verify_chain


def test_ballot_tamper_detection_in_database(client, multiple_voters, test_election, app):
    """Test modifying a ballot record directly in SQLite breaks verify_chain."""
    # 3 voters cast votes
    for i in range(3):
        with client.session_transaction() as sess:
            sess["user_id"] = multiple_voters[i].id
            sess["user_email"] = multiple_voters[i].email
            sess["user_role"] = "voter"

        client.post(f"/vote/{test_election.id}", data={
            "candidate_id": test_election.candidates[0].id,
            "confirm_accuracy": "y"
        }, follow_redirects=True)

    with app.app_context():
        ballots = Ballot.query.filter_by(election_id=test_election.id).order_by(Ballot.id.asc()).all()
        assert len(ballots) == 3

        # Chain initially valid
        is_valid, broken_idx, _ = verify_chain(ballots)
        assert is_valid is True

        # Malicious actor tampers with ballot #1 in DB
        target_ballot = ballots[1]
        target_ballot.encrypted_vote = "maliciously_altered_ciphertext_base64=="
        db.session.commit()

        # Re-fetch ballots and check integrity
        tampered_ballots = Ballot.query.filter_by(election_id=test_election.id).order_by(Ballot.id.asc()).all()
        is_valid, broken_idx, msg = verify_chain(tampered_ballots)
        assert is_valid is False
        assert broken_idx == 1
        assert "Ballot content tampered" in msg


def test_ballot_deletion_detection_in_database(client, multiple_voters, test_election, app):
    """Test deleting an intermediate ballot directly from DB breaks the hash chain."""
    for i in range(4):
        with client.session_transaction() as sess:
            sess["user_id"] = multiple_voters[i].id
            sess["user_email"] = multiple_voters[i].email
            sess["user_role"] = "voter"

        client.post(f"/vote/{test_election.id}", data={
            "candidate_id": test_election.candidates[0].id,
            "confirm_accuracy": "y"
        }, follow_redirects=True)

    with app.app_context():
        ballots = Ballot.query.filter_by(election_id=test_election.id).order_by(Ballot.id.asc()).all()
        assert len(ballots) == 4

        # Malicious actor deletes ballot at index 1
        db.session.delete(ballots[1])
        db.session.commit()

        remaining = Ballot.query.filter_by(election_id=test_election.id).order_by(Ballot.id.asc()).all()
        assert len(remaining) == 3

        is_valid, broken_idx, msg = verify_chain(remaining)
        assert is_valid is False
        assert broken_idx == 1  # Link between index 0 and what was index 2 is broken
        assert "Hash chain broken" in msg


def test_tally_aborts_on_tampered_ballot(client, admin_user, multiple_voters, test_election, election_keypair, app):
    """Admin tallying must abort and refuse to certify if hash chain is compromised."""
    for i in range(3):
        with client.session_transaction() as sess:
            sess["user_id"] = multiple_voters[i].id
            sess["user_email"] = multiple_voters[i].email
            sess["user_role"] = "voter"

        client.post(f"/vote/{test_election.id}", data={
            "candidate_id": test_election.candidates[0].id,
            "confirm_accuracy": "y"
        }, follow_redirects=True)

    # Tamper with ballot
    with app.app_context():
        b = Ballot.query.filter_by(election_id=test_election.id).first()
        b.nonce = "tampered_nonce=="
        db.session.commit()

    # Admin closes election
    with client.session_transaction() as sess:
        sess["user_id"] = admin_user.id
        sess["user_email"] = admin_user.email
        sess["user_role"] = "admin"

    client.post(f"/admin/election/{test_election.id}/status/closed")

    # Admin attempts tally
    resp = client.post(f"/admin/election/{test_election.id}/tally", data={
        "private_key_text": election_keypair["priv_pem"],
        "passphrase": election_keypair["passphrase"]
    }, follow_redirects=True)

    assert b"TALLY ABORTED" in resp.data
    assert b"Hash chain integrity failure" in resp.data

    with app.app_context():
        el = db.session.get(Election, test_election.id)
        assert el.status == "closed"  # Remains closed, not tallied
        assert el.result_signature is None
