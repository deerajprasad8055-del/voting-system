"""
Cryptographic Utilities for Secure Online Voting System
Implements RSA-2048 + AES-256-GCM Hybrid Encryption, SHA-256 Hash Chaining,
and RSA-PSS Digital Signatures using the `cryptography` library.
"""

import os
import json
import base64
import hashlib
from datetime import datetime, timezone
from typing import Tuple, Dict, Any, List, Optional, Union

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature, InvalidTag


def generate_rsa_keypair(passphrase: str, key_size: int = 2048) -> Tuple[bytes, bytes]:
    """
    Generate an RSA keypair (default 2048-bit).
    The private key is encrypted with the provided admin passphrase using BestAvailableEncryption.
    Returns (public_key_pem_bytes, private_key_pem_bytes).
    """
    if not passphrase or len(passphrase.strip()) == 0:
        raise ValueError("A non-empty passphrase is required to protect the private key.")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode("utf-8"))
    )

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return public_pem, private_pem


def load_public_key(pem_data_or_path: Union[str, bytes]) -> rsa.RSAPublicKey:
    """
    Load an RSA public key from PEM string, bytes, or a file path.
    """
    if isinstance(pem_data_or_path, str):
        if os.path.isfile(pem_data_or_path):
            with open(pem_data_or_path, "rb") as f:
                pem_bytes = f.read()
        else:
            pem_bytes = pem_data_or_path.encode("utf-8")
    elif isinstance(pem_data_or_path, bytes):
        pem_bytes = pem_data_or_path
    else:
        raise TypeError("Public key data must be string, bytes, or file path.")

    return serialization.load_pem_public_key(pem_bytes)


def load_private_key(
    pem_data_or_path: Union[str, bytes],
    passphrase: Optional[Union[str, bytes]] = None
) -> rsa.RSAPrivateKey:
    """
    Load an encrypted RSA private key from PEM string, bytes, or a file path using the passphrase.
    """
    if isinstance(pem_data_or_path, str):
        if os.path.isfile(pem_data_or_path):
            with open(pem_data_or_path, "rb") as f:
                pem_bytes = f.read()
        else:
            pem_bytes = pem_data_or_path.encode("utf-8")
    elif isinstance(pem_data_or_path, bytes):
        pem_bytes = pem_data_or_path
    else:
        raise TypeError("Private key data must be string, bytes, or file path.")

    pw_bytes = None
    if passphrase is not None:
        pw_bytes = passphrase.encode("utf-8") if isinstance(passphrase, str) else passphrase

    return serialization.load_pem_private_key(pem_bytes, password=pw_bytes)


def aes_encrypt(
    plaintext_bytes: bytes,
    associated_data: Optional[bytes] = None
) -> Tuple[bytes, bytes, bytes]:
    """
    Encrypt plaintext bytes using AES-256-GCM.
    Generates a fresh 256-bit AES key and a fresh 96-bit (12-byte) nonce.
    Returns (ciphertext_with_tag, nonce, aes_key).
    """
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, associated_data)
    return ciphertext, nonce, aes_key


def aes_decrypt(
    ciphertext: bytes,
    nonce: bytes,
    aes_key: bytes,
    associated_data: Optional[bytes] = None
) -> bytes:
    """
    Decrypt ciphertext using AES-256-GCM.
    Verifies authentication tag and associated data integrity.
    Raises InvalidTag if tampered.
    """
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data)


def rsa_wrap_key(aes_key: bytes, public_key: rsa.RSAPublicKey) -> bytes:
    """
    Wrap (encrypt) AES symmetric key using RSA-OAEP with SHA-256 and MGF1-SHA256.
    """
    return public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def rsa_unwrap_key(wrapped_key: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Unwrap (decrypt) AES symmetric key using RSA-OAEP with SHA-256 and MGF1-SHA256.
    """
    return private_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def encrypt_vote(
    candidate_id: int,
    election_id: int,
    public_key: Union[rsa.RSAPublicKey, str, bytes]
) -> Dict[str, str]:
    """
    Encrypt a voter's ballot using Hybrid Encryption (AES-256-GCM + RSA-OAEP).
    The ballot plaintext includes candidate_id, election_id, and a random 16-byte ballot_salt
    so that identical votes produce completely distinct ciphertexts.
    Binds election_id as AES-GCM associated data.
    Returns dict with base64 encoded 'encrypted_vote', 'wrapped_key', 'nonce'.
    """
    if not isinstance(public_key, rsa.RSAPublicKey):
        public_key = load_public_key(public_key)

    ballot_salt = os.urandom(16).hex()
    payload = {
        "candidate_id": int(candidate_id),
        "election_id": int(election_id),
        "ballot_salt": ballot_salt,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    plaintext_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
    associated_data = f"election_id:{election_id}".encode("utf-8")

    ciphertext, nonce, aes_key = aes_encrypt(plaintext_bytes, associated_data=associated_data)
    wrapped_key = rsa_wrap_key(aes_key, public_key)

    return {
        "encrypted_vote": base64.b64encode(ciphertext).decode("ascii"),
        "wrapped_key": base64.b64encode(wrapped_key).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii")
    }


def decrypt_vote(
    record: Union[Dict[str, Any], Any],
    private_key: Union[rsa.RSAPrivateKey, str, bytes],
    passphrase: Optional[str] = None
) -> Dict[str, Any]:
    """
    Decrypt an encrypted ballot record using the election's RSA private key.
    Unwraps the AES key, then verifies and decrypts the AES-256-GCM ciphertext.
    """
    if not isinstance(private_key, rsa.RSAPrivateKey):
        private_key = load_private_key(private_key, passphrase)

    if isinstance(record, dict):
        encrypted_vote_b64 = record["encrypted_vote"]
        wrapped_key_b64 = record["wrapped_key"]
        nonce_b64 = record["nonce"]
        election_id = record.get("election_id")
    else:
        encrypted_vote_b64 = getattr(record, "encrypted_vote")
        wrapped_key_b64 = getattr(record, "wrapped_key")
        nonce_b64 = getattr(record, "nonce")
        election_id = getattr(record, "election_id", None)

    ciphertext = base64.b64decode(encrypted_vote_b64)
    wrapped_key = base64.b64decode(wrapped_key_b64)
    nonce = base64.b64decode(nonce_b64)

    aes_key = rsa_unwrap_key(wrapped_key, private_key)
    associated_data = f"election_id:{election_id}".encode("utf-8") if election_id is not None else None
    
    plaintext_bytes = aes_decrypt(ciphertext, nonce, aes_key, associated_data=associated_data)
    return json.loads(plaintext_bytes.decode("utf-8"))


def compute_ballot_hash(
    record_or_prev_hash: Union[Dict[str, Any], Any, str],
    previous_hash: Optional[str] = None,
    wrapped_key: Optional[str] = None,
    nonce: Optional[str] = None
) -> str:
    """
    Compute SHA-256 hash of a ballot node in the hash chain:
    SHA-256(prev_hash | encrypted_vote | wrapped_key | nonce)
    Supports being called as compute_ballot_hash(record, prev_hash)
    or compute_ballot_hash(record) or compute_ballot_hash(prev_hash, enc, wk, nonce).
    """
    if isinstance(record_or_prev_hash, dict):
        prev = previous_hash or record_or_prev_hash.get("prev_hash", "GENESIS")
        enc = record_or_prev_hash.get("encrypted_vote", "")
        wk = record_or_prev_hash.get("wrapped_key", "")
        n = record_or_prev_hash.get("nonce", "")
    elif hasattr(record_or_prev_hash, "encrypted_vote"):
        prev = previous_hash or getattr(record_or_prev_hash, "prev_hash", "GENESIS")
        enc = getattr(record_or_prev_hash, "encrypted_vote", "")
        wk = getattr(record_or_prev_hash, "wrapped_key", "")
        n = getattr(record_or_prev_hash, "nonce", "")
    else:
        # Positional arguments: compute_ballot_hash(prev_hash, encrypted_vote, wrapped_key, nonce)
        prev = str(record_or_prev_hash)
        enc = str(previous_hash or "")
        wk = str(wrapped_key or "")
        n = str(nonce or "")

    raw = f"{prev}|{enc}|{wk}|{n}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def verify_chain(ballots: List[Any]) -> Tuple[bool, int, str]:
    """
    Verify the integrity of a sequence of ballots in an election hash chain.
    Returns (is_valid: bool, broken_index: int, message: str).
    If valid, returns (True, -1, "Chain is valid").
    If broken, returns (False, index_of_first_broken_link, description).
    """
    if not ballots:
        return True, -1, "Chain is empty and valid."

    expected_prev = "GENESIS"
    for idx, ballot in enumerate(ballots):
        prev = ballot.get("prev_hash") if isinstance(ballot, dict) else getattr(ballot, "prev_hash", None)
        curr_hash = ballot.get("ballot_hash") if isinstance(ballot, dict) else getattr(ballot, "ballot_hash", None)
        
        if prev != expected_prev:
            return False, idx, f"Hash chain broken at index {idx}: expected prev_hash '{expected_prev}', got '{prev}'."

        calculated_hash = compute_ballot_hash(ballot, prev)
        if curr_hash != calculated_hash:
            return False, idx, f"Ballot content tampered at index {idx}: expected hash '{calculated_hash}', got '{curr_hash}'."

        expected_prev = curr_hash

    return True, -1, "All ballots in the chain are cryptographically valid and untampered."


def sign_result(
    tally_json: Union[str, Dict[str, Any]],
    private_key: Union[rsa.RSAPrivateKey, str, bytes],
    passphrase: Optional[str] = None
) -> str:
    """
    Sign election tally JSON using RSA-PSS with SHA-256 and MGF1-SHA256.
    Returns base64 encoded signature.
    """
    if isinstance(tally_json, dict):
        tally_str = json.dumps(tally_json, sort_keys=True)
    else:
        tally_str = str(tally_json)

    if not isinstance(private_key, rsa.RSAPrivateKey):
        private_key = load_private_key(private_key, passphrase)

    signature = private_key.sign(
        tally_str.encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode("ascii")


def verify_result(
    tally_json: Union[str, Dict[str, Any]],
    signature_b64: str,
    public_key: Union[rsa.RSAPublicKey, str, bytes]
) -> bool:
    """
    Verify election tally JSON signature using RSA-PSS with SHA-256 and MGF1-SHA256.
    Returns True if valid, False otherwise.
    """
    if isinstance(tally_json, dict):
        tally_str = json.dumps(tally_json, sort_keys=True)
    else:
        tally_str = str(tally_json)

    if not isinstance(public_key, rsa.RSAPublicKey):
        public_key = load_public_key(public_key)

    try:
        sig_bytes = base64.b64decode(signature_b64)
        public_key.verify(
            sig_bytes,
            tally_str.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except (InvalidSignature, ValueError, Exception):
        return False
