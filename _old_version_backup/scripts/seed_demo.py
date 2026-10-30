"""
Seed script to initialize demo database with:
- 1 Admin user
- 5 Verified Voter users
- 1 Active Open Election with RSA-2048 public key
- 3 Candidates
- Generates demo_private_key.pem on disk for admin tallying testing
"""

import os
import sys
from datetime import datetime, timezone, timedelta

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import create_app
from models import db, User, Election, Candidate, VoterStatus, Ballot, AuditLog
from crypto_utils import generate_rsa_keypair

DEMO_PASSPHRASE = "DemoElectionPassphrase2026!"


def seed():
    app = create_app("development")
    with app.app_context():
        print("[*] Resetting and initializing database tables...")
        db.drop_all()
        db.create_all()

        print("[*] Generating RSA-2048 keypair for Demo Election...")
        pub_bytes, priv_bytes = generate_rsa_keypair(DEMO_PASSPHRASE)
        pub_pem_str = pub_bytes.decode("utf-8")
        priv_pem_str = priv_bytes.decode("utf-8")

        # Save private key locally for testing and demonstration
        key_file_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "demo_private_key.pem"))
        with open(key_file_path, "wb") as f:
            f.write(priv_bytes)
        print(f"[+] Saved demo private key to: {key_file_path}")

        # 1. Create Admin
        admin = User(
            name="Chief Election Officer",
            email="admin@election.gov",
            voter_id="ADMIN-001",
            role="admin"
        )
        admin.set_password("Admin@Secure2026!")
        db.session.add(admin)

        # 2. Create 5 Voters
        voters_data = [
            ("Alice Walker", "alice@vote.com", "VOTER-1001", "Voter@Secure2026!"),
            ("Bob Miller", "bob@vote.com", "VOTER-1002", "Voter@Secure2026!"),
            ("Charlie Davis", "charlie@vote.com", "VOTER-1003", "Voter@Secure2026!"),
            ("Diana Prince", "diana@vote.com", "VOTER-1004", "Voter@Secure2026!"),
            ("Edward Norton", "edward@vote.com", "VOTER-1005", "Voter@Secure2026!")
        ]

        for name, email, vid, pw in voters_data:
            voter = User(
                name=name,
                email=email,
                voter_id=vid,
                role="voter"
            )
            voter.set_password(pw)
            db.session.add(voter)

        # 3. Create Demo Election (Open and Active)
        now = datetime.now(timezone.utc)
        election = Election(
            title="2026 Presidential & Technology Council Election",
            description="National general election for digital infrastructure modernization and executive council leadership.",
            start_time=now - timedelta(days=1),
            end_time=now + timedelta(days=7),
            status="open",
            public_key_pem=pub_pem_str
        )
        db.session.add(election)
        db.session.flush()  # assign election ID

        # 4. Create 3 Candidates
        candidates_data = [
            (
                "Dr. Elena Vance",
                "Cyber-Liberty Party",
                "Champion of privacy rights, open-source governance, and post-quantum encryption standards."
            ),
            (
                "Marcus Sterling",
                "National Progress Coalition",
                "Focusing on infrastructure modernization, clean energy transition, and AI-assisted healthcare."
            ),
            (
                "Aria Thorne",
                "Digital Democracy Alliance",
                "Advocating for transparent participatory budgeting, direct civic engagement, and ethical AI."
            )
        ]

        for c_name, c_party, c_desc in candidates_data:
            candidate = Candidate(
                election_id=election.id,
                name=c_name,
                party=c_party,
                description=c_desc
            )
            db.session.add(candidate)

        # 5. Add initial audit log
        audit = AuditLog(
            action="SYSTEM_INITIALIZED",
            details="Demo election and test accounts populated with cryptographic keys.",
            actor_email="admin@election.gov"
        )
        db.session.add(audit)

        db.session.commit()

        print("\n" + "=" * 70)
        print("[+] DEMO ENVIRONMENT POPULATED SUCCESSFULLY!")
        print("=" * 70)
        print("Admin Credentials:")
        print("  - Email:    admin@election.gov")
        print("  - Password: Admin@Secure2026!")
        print("\nVoter Credentials (Password: Voter@Secure2026!):")
        for name, email, vid, _ in voters_data:
            print(f"  - {name:<15} Email: {email:<18} Voter ID: {vid}")
        print("\nDemo Election:")
        print(f"  - Title:      {election.title}")
        print(f"  - Status:     {election.status.upper()}")
        print(f"  - Passphrase: {DEMO_PASSPHRASE}")
        print(f"  - Key File:   demo_private_key.pem")
        print("=" * 70 + "\n")


if __name__ == "__main__":
    seed()
