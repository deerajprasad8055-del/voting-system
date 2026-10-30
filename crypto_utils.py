"""
SecureVote Cryptographic Engine
Implements Hybrid Encryption (RSA-2048 + AES-256-GCM) and Hash-Chained Auditing.
"""

import os
import json
import base64
import hashlib
import secrets
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from config import Config


class TamperError(Exception):
    """Raised when cryptographic integrity check fails (AES-GCM tag mismatch, invalid RSA wrap, or chain break)."""
    pass


def generate_rsa_keypair(keys_dir=None, passphrase=None, force=False):
    """
    Generates an RSA-2048 keypair on first run.
    Saves public key to keys/public.pem (SubjectPublicKeyInfo).
    Saves private key to keys/private.pem encrypted with passphrase (BestAvailableEncryption).
    """
    keys_dir = keys_dir or Config.KEYS_DIR
    passphrase = passphrase or Config.RSA_PASSPHRASE
    
    os.makedirs(keys_dir, exist_ok=True)
    priv_path = os.path.join(keys_dir, 'private.pem')
    pub_path = os.path.join(keys_dir, 'public.pem')
    
    if os.path.exists(priv_path) and os.path.exists(pub_path) and not force:
        return priv_path, pub_path

    # Generate RSA 2048-bit key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    # Encrypt private key with passphrase using PKCS8 + BestAvailableEncryption
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode('utf-8'))
    )

    # Export public key
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(priv_path, 'wb') as f:
        f.write(pem_private)
        
    with open(pub_path, 'wb') as f:
        f.write(pem_public)

    return priv_path, pub_path


def load_public_key(pub_path=None):
    """Loads RSA public key from PEM file."""
    pub_path = pub_path or Config.PUBLIC_KEY_PATH
    if not os.path.exists(pub_path):
        generate_rsa_keypair()
    with open(pub_path, 'rb') as f:
        return serialization.load_pem_public_key(f.read())


def load_private_key(priv_path=None, passphrase=None):
    """Loads and decrypts RSA private key from PEM file using passphrase."""
    priv_path = priv_path or Config.PRIVATE_KEY_PATH
    passphrase = passphrase or Config.RSA_PASSPHRASE
    if not os.path.exists(priv_path):
        generate_rsa_keypair(passphrase=passphrase)
    with open(priv_path, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=passphrase.encode('utf-8'))


def encrypt_vote(vote_dict, public_key=None):
    """
    Hybrid Encryption of a vote:
    1. Generates a fresh random 256-bit AES key and a 96-bit nonce for EVERY vote.
    2. Encrypts vote JSON (election_id, candidate_id, timestamp, random salt) with AES-256-GCM.
    3. Encrypts (wraps) the AES key with the RSA-2048 public key using OAEP with SHA-256.
    4. Returns base64 strings: encrypted_vote, encrypted_aes_key, nonce.
    """
    if public_key is None:
        public_key = load_public_key()

    # Ensure vote payload has timestamp and random salt for entropy
    payload = dict(vote_dict)
    if 'timestamp' not in payload:
        payload['timestamp'] = datetime.now(timezone.utc).isoformat()
    if 'salt' not in payload:
        payload['salt'] = secrets.token_hex(16)

    json_bytes = json.dumps(payload, sort_keys=True).encode('utf-8')

    # 1. Generate 256-bit (32 bytes) AES key & 96-bit (12 bytes) nonce
    aes_key = os.urandom(32)
    nonce = os.urandom(12)

    # 2. Encrypt with AES-256-GCM (returns ciphertext + 16-byte auth tag)
    aesgcm = AESGCM(aes_key)
    ciphertext_and_tag = aesgcm.encrypt(nonce, json_bytes, None)

    # 3. Wrap AES key with RSA public key using OAEP + SHA-256
    wrapped_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 4. Return as base64-encoded strings
    return {
        'encrypted_vote': base64.b64encode(ciphertext_and_tag).decode('ascii'),
        'encrypted_aes_key': base64.b64encode(wrapped_aes_key).decode('ascii'),
        'nonce': base64.b64encode(nonce).decode('ascii')
    }


def decrypt_vote(encrypted_vote_b64, encrypted_aes_key_b64, nonce_b64, private_key=None, passphrase=None):
    """
    Unwraps the AES key with the RSA private key, then decrypts and validates AES-256-GCM.
    Raises TamperError if RSA unwrap fails or AES-GCM authentication tag verification fails.
    """
    if private_key is None:
        private_key = load_private_key(passphrase=passphrase)

    # Decode base64 components
    try:
        ciphertext_and_tag = base64.b64decode(encrypted_vote_b64)
        wrapped_aes_key = base64.b64decode(encrypted_aes_key_b64)
        nonce = base64.b64decode(nonce_b64)
    except Exception as e:
        raise TamperError(f"Corrupted base64 payload structure: {e}")

    # Unwrap the AES key using RSA private key
    try:
        aes_key = private_key.decrypt(
            wrapped_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        raise TamperError(f"RSA key unwrapping failed! Wrapped key is invalid or tampered: {e}")

    # Decrypt AES-256-GCM and verify tag
    try:
        aesgcm = AESGCM(aes_key)
        decrypted_json_bytes = aesgcm.decrypt(nonce, ciphertext_and_tag, None)
    except InvalidTag as e:
        raise TamperError("AES-GCM authentication tag mismatch! Ballot ciphertext has been tampered with or corrupted.")
    except Exception as e:
        raise TamperError(f"AES decryption failed: {e}")

    try:
        return json.loads(decrypted_json_bytes.decode('utf-8'))
    except Exception as e:
        raise TamperError(f"Decrypted payload is not valid JSON: {e}")


def compute_ballot_hash(prev_hash, encrypted_vote, encrypted_aes_key, nonce):
    """
    Computes ballot SHA-256 hash in a cryptographic hash chain:
    ballot_hash = SHA256(previous_ballot_hash + encrypted_vote + encrypted_aes_key + nonce).
    Prevents modification, deletion, or reordering of stored ballots.
    """
    prev = prev_hash if prev_hash else ("0" * 64)
    chain_input = f"{prev}:{encrypted_vote}:{encrypted_aes_key}:{nonce}".encode('utf-8')
    return hashlib.sha256(chain_input).hexdigest()


def verify_chain(election_id, db_conn):
    """
    Recomputes the cryptographic hash chain for all ballots in an election.
    Returns:
        (is_valid: bool, broken_ballot_id: int|None, message: str, ballots_checked: list)
    """
    cursor = db_conn.cursor()
    cursor.execute(
        """SELECT id, election_id, encrypted_vote, encrypted_aes_key, nonce, prev_hash, ballot_hash, created_at 
           FROM ballots 
           WHERE election_id = ? 
           ORDER BY id ASC""",
        (election_id,)
    )
    ballots = cursor.fetchall()

    if not ballots:
        return True, None, "No ballots cast yet. Chain is intact.", []

    ballots_checked = []
    expected_prev = "0" * 64

    for idx, b in enumerate(ballots):
        ballot_id = b['id']
        actual_prev = b['prev_hash']
        stored_hash = b['ballot_hash']

        # 1. Verify previous hash pointer matches predecessor
        if actual_prev != expected_prev:
            msg = (f"Ballot #{ballot_id} chain link broken! "
                   f"Previous hash '{actual_prev[:12]}...' does not match expected predecessor '{expected_prev[:12]}...'.")
            ballots_checked.append({
                'id': ballot_id,
                'prev_hash': actual_prev,
                'stored_hash': stored_hash,
                'computed_hash': None,
                'status': 'FAIL',
                'reason': msg
            })
            return False, ballot_id, msg, ballots_checked

        # 2. Recompute current ballot hash
        computed_hash = compute_ballot_hash(
            actual_prev,
            b['encrypted_vote'],
            b['encrypted_aes_key'],
            b['nonce']
        )

        if computed_hash != stored_hash:
            msg = (f"Ballot #{ballot_id} payload tampered! "
                   f"Stored hash '{stored_hash[:12]}...' does not match computed hash '{computed_hash[:12]}...'.")
            ballots_checked.append({
                'id': ballot_id,
                'prev_hash': actual_prev,
                'stored_hash': stored_hash,
                'computed_hash': computed_hash,
                'status': 'FAIL',
                'reason': msg
            })
            return False, ballot_id, msg, ballots_checked

        ballots_checked.append({
            'id': ballot_id,
            'prev_hash': actual_prev,
            'stored_hash': stored_hash,
            'computed_hash': computed_hash,
            'status': 'PASS',
            'reason': 'Cryptographically verified'
        })

        # Advance expected predecessor
        expected_prev = stored_hash

    return True, None, f"All {len(ballots)} ballots successfully verified in cryptographic hash chain.", ballots_checked

