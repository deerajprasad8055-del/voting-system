"""
Pytest configuration and fixtures for testing the Secure Online Voting System.
"""

import pytest
from datetime import datetime, timezone, timedelta
from app import create_app
from models import db, User, Election, Candidate, VoterStatus, Ballot, AuditLog
from crypto_utils import generate_rsa_keypair

TEST_PASSPHRASE = "TestPassphrase2026!SecureKey"


@pytest.fixture(scope="session")
def election_keypair():
    """Generate reusable RSA-2048 keypair for testing session."""
    pub_bytes, priv_bytes = generate_rsa_keypair(TEST_PASSPHRASE)
    return {
        "pub_pem": pub_bytes.decode("utf-8"),
        "priv_pem": priv_bytes.decode("utf-8"),
        "passphrase": TEST_PASSPHRASE
    }


@pytest.fixture
def app():
    """Create test application instance with in-memory SQLite database."""
    test_app = create_app("testing")
    with test_app.app_context():
        db.create_all()
        yield test_app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    """Test client."""
    return app.test_client()


@pytest.fixture
def admin_user(app):
    """Create test admin user."""
    admin = User(
        name="Admin Test",
        email="admin@test.gov",
        voter_id="ADM-001",
        role="admin"
    )
    admin.set_password("Admin@Test2026!")
    db.session.add(admin)
    db.session.commit()
    return admin


@pytest.fixture
def voter_user(app):
    """Create test voter user."""
    voter = User(
        name="Voter Test",
        email="voter@test.com",
        voter_id="VOT-1001",
        role="voter"
    )
    voter.set_password("Voter@Test2026!")
    db.session.add(voter)
    db.session.commit()
    return voter


@pytest.fixture
def multiple_voters(app):
    """Create 5 test voters."""
    voters = []
    for i in range(1, 6):
        v = User(
            name=f"Voter {i}",
            email=f"voter{i}@test.com",
            voter_id=f"VOT-200{i}",
            role="voter"
        )
        v.set_password("Voter@Test2026!")
        db.session.add(v)
        voters.append(v)
    db.session.commit()
    return voters


@pytest.fixture
def test_election(app, election_keypair):
    """Create an active test election with 3 candidates."""
    now = datetime.now(timezone.utc)
    election = Election(
        title="2026 General Election",
        description="Official Test Election",
        start_time=now - timedelta(hours=1),
        end_time=now + timedelta(days=1),
        status="open",
        public_key_pem=election_keypair["pub_pem"]
    )
    db.session.add(election)
    db.session.flush()

    c1 = Candidate(election_id=election.id, name="Candidate Alpha", party="Party A", description="Policy A")
    c2 = Candidate(election_id=election.id, name="Candidate Beta", party="Party B", description="Policy B")
    c3 = Candidate(election_id=election.id, name="Candidate Gamma", party="Party C", description="Policy C")

    db.session.add_all([c1, c2, c3])
    db.session.commit()
    return election
