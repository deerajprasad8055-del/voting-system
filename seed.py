"""
SecureVote Seed Script
Initializes the database, generates cryptographic keys, and seeds:
- 1 Administrator (admin@securevote.com / Admin@123)
- 3 Certified Voters (alice, bob, charlie / Voter@123)
- 1 Open General Election with 4 Candidates
"""

import os
import sqlite3
from werkzeug.security import generate_password_hash
from config import Config
import database
import crypto_utils


def seed():
    print("--------------------------------------------------")
    print("Initializing SecureVote Cryptographic Infrastructure...")
    print("--------------------------------------------------")

    # 1. Ensure RSA Keypair exists
    priv_path, pub_path = crypto_utils.generate_rsa_keypair()
    print(f"[OK] RSA-2048 Keypair ready:\n     Private: {priv_path}\n     Public:  {pub_path}")

    # 2. Initialize Database Schema
    db_path = Config.DATABASE
    database.init_db(db_path)
    print(f"[OK] Database schema initialized at: {db_path}")

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # 3. Seed Users
    users_data = [
        {
            'full_name': 'Election Administrator',
            'email': 'admin@securevote.com',
            'voter_id': 'ADM-0001',
            'password': 'Admin@123',
            'role': 'admin'
        },
        {
            'full_name': 'Alice Johnson',
            'email': 'alice@securevote.com',
            'voter_id': 'VOT-1001',
            'password': 'Voter@123',
            'role': 'voter'
        },
        {
            'full_name': 'Bob Smith',
            'email': 'bob@securevote.com',
            'voter_id': 'VOT-1002',
            'password': 'Voter@123',
            'role': 'voter'
        },
        {
            'full_name': 'Charlie Brown',
            'email': 'charlie@securevote.com',
            'voter_id': 'VOT-1003',
            'password': 'Voter@123',
            'role': 'voter'
        }
    ]

    print("\nSeeding Users...")
    for u in users_data:
        existing = cursor.execute("SELECT id FROM users WHERE email = ?", (u['email'],)).fetchone()
        if not existing:
            pw_hash = generate_password_hash(u['password'], method='scrypt')
            cursor.execute(
                """INSERT INTO users (full_name, email, voter_id, password_hash, role)
                   VALUES (?, ?, ?, ?, ?)""",
                (u['full_name'], u['email'], u['voter_id'], pw_hash, u['role'])
            )
            print(f"  + Created user: {u['email']} [{u['role']}] ({u['voter_id']})")
        else:
            print(f"  . User already exists: {u['email']}")

    # 4. Seed Demo Open Election
    print("\nSeeding Open General Election...")
    existing_election = cursor.execute("SELECT id FROM elections WHERE title = ?", ("2026 National Presidential Election",)).fetchone()

    if not existing_election:
        cursor.execute(
            """INSERT INTO elections (title, description, status)
               VALUES (?, ?, 'open')""",
            ("2026 National Presidential Election",
             "Official secure general election for the Executive President. Cryptographically sealed with RSA-2048 and AES-256-GCM authenticated encryption.")
        )
        election_id = cursor.lastrowid
        print(f"  + Created Election #{election_id}: '2026 National Presidential Election' [OPEN]")

        candidates = [
            (election_id, "Dr. Evelyn Reed", "Tech & Science Coalition", "Pioneering technological infrastructure, digital identity security, and public healthcare."),
            (election_id, "Marcus Sterling", "Economic Freedom Party", "Promoting small business growth, balanced budgets, and sustainable market reform."),
            (election_id, "Sarah Jenkins", "Green Horizon Alliance", "Championing renewable energy, climate resilience, and equitable community programs."),
            (election_id, "David O'Connor", "Civic Unity Movement", "Fostering democratic integrity, bipartisan collaboration, and transparent governance.")
        ]
        cursor.executemany(
            "INSERT INTO candidates (election_id, name, party, description) VALUES (?, ?, ?, ?)",
            candidates
        )
        print(f"  + Added {len(candidates)} candidates.")
    else:
        print("  . Election '2026 National Presidential Election' already exists.")

    # 5. Seed initial audit log
    cursor.execute(
        "INSERT INTO audit_log (action, details, ip) VALUES ('SYSTEM_INIT', 'Database and cryptographic engine initialized via seed script.', '127.0.0.1')"
    )

    conn.commit()
    conn.close()

    print("\n==================================================")
    print("Seed Complete! Demo Credentials:")
    print("  Administrator: admin@securevote.com / Admin@123")
    print("  Demo Voter 1:  alice@securevote.com / Voter@123")
    print("  Demo Voter 2:  bob@securevote.com   / Voter@123")
    print("  Demo Voter 3:  charlie@securevote.com / Voter@123")
    print("==================================================")


if __name__ == '__main__':
    seed()

