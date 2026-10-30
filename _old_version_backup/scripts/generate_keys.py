"""
Script to generate an RSA-2048 keypair for election encryption.
Saves public_key.pem (SubjectPublicKeyInfo) and private_key.pem (PKCS#8 encrypted with passphrase).
"""

import os
import sys
import argparse

# Add parent directory to path so crypto_utils can be imported
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from crypto_utils import generate_rsa_keypair


def main():
    parser = argparse.ArgumentParser(description="Generate RSA-2048 Keypair for Secure Election")
    parser.add_argument(
        "--passphrase",
        type=str,
        default="AdminElectionSecretPassphrase2026!",
        help="Passphrase to protect private key (default: 'AdminElectionSecretPassphrase2026!')"
    )
    parser.add_argument(
        "--out-dir",
        type=str,
        default=".",
        help="Directory to write public_key.pem and private_key.pem"
    )

    args = parser.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    pub_path = os.path.join(args.out_dir, "public_key.pem")
    priv_path = os.path.join(args.out_dir, "private_key.pem")

    print(f"[*] Generating RSA-2048 keypair encrypted with passphrase...")
    pub_bytes, priv_bytes = generate_rsa_keypair(args.passphrase)

    with open(pub_path, "wb") as f:
        f.write(pub_bytes)

    with open(priv_path, "wb") as f:
        f.write(priv_bytes)

    print(f"[+] Successfully generated RSA-2048 keypair!")
    print(f"    - Public Key:  {os.path.abspath(pub_path)}")
    print(f"    - Private Key: {os.path.abspath(priv_path)}")
    print(f"    - Passphrase:  {args.passphrase}")
    print(f"[*] Remember: Keep private_key.pem offline and secure until election tallying!")


if __name__ == "__main__":
    main()
