"""
Tests for cryptographic primitives: RSA-2048, AES-256-GCM, Hash Chaining, and RSA-PSS.
"""

import json
import base64
import pytest
from cryptography.exceptions import InvalidTag

from crypto_utils import (
    generate_rsa_keypair, load_public_key, load_private_key,
    aes_encrypt, aes_decrypt, rsa_wrap_key, rsa_unwrap_key,
    encrypt_vote, decrypt_vote, compute_ballot_hash, verify_chain,
    sign_result, verify_result
)


def test_rsa_key_generation_and_loading():
    """Test RSA-2048 generation, encryption with passphrase, and loading."""
    passphrase = "SecretTestPassphrase123!"
    pub_pem, priv_pem = generate_rsa_keypair(passphrase)

    assert b"BEGIN PUBLIC KEY" in pub_pem
    assert b"BEGIN ENCRYPTED PRIVATE KEY" in priv_pem

    # Load public key
    pub_key = load_public_key(pub_pem)
    assert pub_key is not None
    assert pub_key.key_size == 2048

    # Load private key with correct passphrase
    priv_key = load_private_key(priv_pem, passphrase)
    assert priv_key is not None
    assert priv_key.key_size == 2048


def test_rsa_private_key_wrong_passphrase():
    """Loading private key with wrong passphrase must fail."""
    passphrase = "CorrectPassphrase!"
    _, priv_pem = generate_rsa_keypair(passphrase)

    with pytest.raises(Exception):
        load_private_key(priv_pem, "WrongPassphrase123!")


def test_aes_256_gcm_roundtrip_and_tampering():
    """Test AES-256-GCM authenticated encryption and tamper detection."""
    plaintext = b"Official vote payload data"
    associated_data = b"election:101"

    ciphertext, nonce, key = aes_encrypt(plaintext, associated_data=associated_data)

    # 1. Successful decrypt
    decrypted = aes_decrypt(ciphertext, nonce, key, associated_data=associated_data)
    assert decrypted == plaintext

    # 2. Tampered ciphertext must raise InvalidTag
    tampered_ct = bytearray(ciphertext)
    tampered_ct[0] ^= 0xFF
    with pytest.raises(InvalidTag):
        aes_decrypt(bytes(tampered_ct), nonce, key, associated_data=associated_data)

    # 3. Tampered nonce must raise InvalidTag
    tampered_nonce = bytearray(nonce)
    tampered_nonce[0] ^= 0xFF
    with pytest.raises(InvalidTag):
        aes_decrypt(ciphertext, bytes(tampered_nonce), key, associated_data=associated_data)

    # 4. Modified associated data must raise InvalidTag
    with pytest.raises(InvalidTag):
        aes_decrypt(ciphertext, nonce, key, associated_data=b"election:999")


def test_rsa_key_wrapping_roundtrip():
    """Test RSA-OAEP wrapping and unwrapping of AES keys."""
    passphrase = "WrapTestPassphrase!"
    pub_pem, priv_pem = generate_rsa_keypair(passphrase)
    pub_key = load_public_key(pub_pem)
    priv_key = load_private_key(priv_pem, passphrase)

    raw_aes_key = b"\x01" * 32  # 256-bit key
    wrapped = rsa_wrap_key(raw_aes_key, pub_key)
    assert len(wrapped) == 256  # 2048 bits / 8 = 256 bytes

    unwrapped = rsa_unwrap_key(wrapped, priv_key)
    assert unwrapped == raw_aes_key


def test_vote_encryption_roundtrip_many_trials():
    """Test encrypting and decrypting votes across multiple random trials."""
    passphrase = "VoteElectionPassphrase2026!"
    pub_pem, priv_pem = generate_rsa_keypair(passphrase)
    pub_key = load_public_key(pub_pem)
    priv_key = load_private_key(priv_pem, passphrase)

    for candidate_id in [1, 2, 42, 999]:
        for election_id in [1, 100, 2026]:
            enc_vote = encrypt_vote(candidate_id, election_id, pub_key)

            assert "encrypted_vote" in enc_vote
            assert "wrapped_key" in enc_vote
            assert "nonce" in enc_vote

            # Add election_id for decrypt record
            enc_vote["election_id"] = election_id
            decrypted = decrypt_vote(enc_vote, priv_key)

            assert decrypted["candidate_id"] == candidate_id
            assert decrypted["election_id"] == election_id
            assert "ballot_salt" in decrypted
            assert len(decrypted["ballot_salt"]) == 32  # 16 bytes hex


def test_same_candidate_produces_different_ciphertexts():
    """Identical votes must produce completely different ciphertexts and wrapped keys due to fresh salts & nonces."""
    passphrase = "SaltTestPassphrase!"
    pub_pem, _ = generate_rsa_keypair(passphrase)
    pub_key = load_public_key(pub_pem)

    vote1 = encrypt_vote(candidate_id=5, election_id=1, public_key=pub_key)
    vote2 = encrypt_vote(candidate_id=5, election_id=1, public_key=pub_key)

    assert vote1["encrypted_vote"] != vote2["encrypted_vote"]
    assert vote1["wrapped_key"] != vote2["wrapped_key"]
    assert vote1["nonce"] != vote2["nonce"]


def test_ballot_hash_chain_validity():
    """Test building and verifying a SHA-256 hash chain of ballots."""
    ballots = []
    prev_hash = "GENESIS"

    for i in range(5):
        record = {
            "prev_hash": prev_hash,
            "encrypted_vote": f"enc_payload_{i}",
            "wrapped_key": f"wrapped_key_{i}",
            "nonce": f"nonce_{i}"
        }
        b_hash = compute_ballot_hash(record, prev_hash)
        record["ballot_hash"] = b_hash
        ballots.append(record)
        prev_hash = b_hash

    is_valid, broken_idx, msg = verify_chain(ballots)
    assert is_valid is True
    assert broken_idx == -1


def test_ballot_hash_chain_detects_tampering_and_deletion():
    """Test that modifying any ballot or deleting one breaks verify_chain and points to broken index."""
    ballots = []
    prev_hash = "GENESIS"
    for i in range(5):
        record = {
            "prev_hash": prev_hash,
            "encrypted_vote": f"enc_{i}",
            "wrapped_key": f"wk_{i}",
            "nonce": f"n_{i}"
        }
        b_hash = compute_ballot_hash(record, prev_hash)
        record["ballot_hash"] = b_hash
        ballots.append(record)
        prev_hash = b_hash

    # Case 1: Tamper with ciphertext in ballot #2
    tampered_ballots = [dict(b) for b in ballots]
    tampered_ballots[2]["encrypted_vote"] = "tampered_ciphertext"
    is_valid, broken_idx, _ = verify_chain(tampered_ballots)
    assert is_valid is False
    assert broken_idx == 2

    # Case 2: Delete ballot #2
    deleted_ballots = [b for idx, b in enumerate(ballots) if idx != 2]
    is_valid, broken_idx, _ = verify_chain(deleted_ballots)
    assert is_valid is False
    assert broken_idx == 2  # Ballot originally at 3 is now at 2 and has mismatched prev_hash


def test_rsa_pss_digital_signature_and_verification():
    """Test RSA-PSS digital signing of tally JSON and signature verification."""
    passphrase = "SignPassphrase2026!"
    pub_pem, priv_pem = generate_rsa_keypair(passphrase)
    pub_key = load_public_key(pub_pem)
    priv_key = load_private_key(priv_pem, passphrase)

    tally_data = {
        "election_id": 1,
        "total_ballots": 100,
        "candidates": [
            {"candidate_id": 1, "name": "Alice", "votes": 60},
            {"candidate_id": 2, "name": "Bob", "votes": 40}
        ]
    }

    sig_b64 = sign_result(tally_data, priv_key)
    assert isinstance(sig_b64, str)
    assert len(sig_b64) > 0

    # 1. Valid signature passes
    assert verify_result(tally_data, sig_b64, pub_key) is True

    # 2. Tampered tally JSON must fail verification
    tampered_tally = dict(tally_data)
    tampered_tally["total_ballots"] = 101
    assert verify_result(tampered_tally, sig_b64, pub_key) is False

    # 3. Verification with different public key must fail
    other_pub_pem, _ = generate_rsa_keypair("OtherKeyPassphrase!")
    assert verify_result(tally_data, sig_b64, other_pub_pem) is False
