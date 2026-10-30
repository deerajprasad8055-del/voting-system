"""
Verification script for live Flask server running on http://127.0.0.1:5000.
Tests:
1. Voter login (Alice)
2. Vote casting (Candidate 1)
3. Receipt retrieval
4. Public verification lookup (/verify)
5. Voter logout & Admin login
6. Hash chain integrity check (/admin/election/1/verify-integrity)
7. Election closing
8. Election tallying with RSA private key and passphrase
9. Results viewing and CSV/JSON export download
"""

import sys
import re
import urllib.request
import urllib.parse
import http.cookiejar

BASE_URL = "http://127.0.0.1:5000"


class SessionClient:
    def __init__(self):
        self.cookie_jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookie_jar)
        )

    def get(self, path):
        url = urllib.parse.urljoin(BASE_URL, path)
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with self.opener.open(req) as resp:
            return resp.getcode(), resp.read().decode("utf-8")

    def post(self, path, data):
        url = urllib.parse.urljoin(BASE_URL, path)
        encoded_data = urllib.parse.urlencode(data).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=encoded_data,
            headers={
                "User-Agent": "Mozilla/5.0",
                "Content-Type": "application/x-www-form-urlencoded"
            }
        )
        with self.opener.open(req) as resp:
            return resp.getcode(), resp.read().decode("utf-8")

    def get_csrf(self, html):
        match = re.search(r'name=["\']csrf_token["\'][^>]*value=["\']([^"\']+)["\']', html)
        if match:
            return match.group(1)
        match = re.search(r'value=["\']([^"\']+)["\'][^>]*name=["\']csrf_token["\']', html)
        if match:
            return match.group(1)
        return ""


def run_live_verification():
    print("[*] Starting live HTTP verification against " + BASE_URL)

    # 1. Voter Alice Login
    client = SessionClient()
    code, html = client.get("/login")
    csrf = client.get_csrf(html)
    assert csrf, "CSRF token missing on login page"

    print("[*] 1. Logging in as Alice Walker...")
    code, html = client.post("/login", {
        "csrf_token": csrf,
        "identifier": "alice@vote.com",
        "password": "Voter@Secure2026!"
    })
    assert "Welcome back, Alice Walker!" in html or "Elections & Ballots" in html
    print("[+] Alice logged in successfully.")

    # 2. View Election and Vote
    code, html = client.get("/dashboard")
    match_el = re.search(r'/vote/(\d+)', html)
    assert match_el, "No vote link found on dashboard"
    election_id = match_el.group(1)

    code, html = client.get(f"/vote/{election_id}")
    csrf = client.get_csrf(html)
    match_cand = re.search(r'name=["\']candidate_id["\']\s+value=["\'](\d+)["\']', html)
    assert match_cand, "Candidate radio input not found"
    cand_id = match_cand.group(1)

    print(f"[*] 2. Casting encrypted ballot for Candidate #{cand_id} in Election #{election_id}...")
    code, html = client.post(f"/vote/{election_id}", {
        "csrf_token": csrf,
        "candidate_id": cand_id,
        "confirm_accuracy": "y"
    })
    assert "Ballot Successfully Cast!" in html
    match_hash = re.search(r'id=["\']ballotHashInput["\'][^>]*value=["\']([a-f0-9]{64})["\']', html)
    assert match_hash, "Ballot hash not found in receipt"
    ballot_hash = match_hash.group(1)
    print(f"[+] Ballot cast! Tracking Hash: {ballot_hash}")

    # 3. Public Verification
    print(f"[*] 3. Verifying ballot in public chain (/verify)...")
    code, html = client.get("/verify")
    csrf = client.get_csrf(html)
    code, html = client.post("/verify", {
        "csrf_token": csrf,
        "ballot_hash": ballot_hash
    })
    assert "Ballot Confirmed Intact" in html
    assert "Cryptographic Chain Verification: Passed" in html
    print("[+] Ballot verified in chain successfully!")

    # 4. Sign Out
    client.get("/logout")

    # 5. Admin Login
    print("[*] 4. Logging in as Administrator...")
    code, html = client.get("/login")
    csrf = client.get_csrf(html)
    code, html = client.post("/login", {
        "csrf_token": csrf,
        "identifier": "admin@election.gov",
        "password": "Admin@Secure2026!"
    })
    assert "Administrator Operations" in html or "Admin Dashboard" in html
    print("[+] Admin logged in.")

    # 6. Admin Verify Integrity
    print(f"[*] 5. Admin running hash chain integrity audit for Election #{election_id}...")
    code, html = client.get(f"/admin/election/{election_id}/verify-integrity")
    assert "Hash Chain Integrity: PASSED &amp; VERIFIED" in html or "PASSED" in html
    print("[+] Chain integrity verified by Admin.")

    # 7. Close Election
    print(f"[*] 6. Closing Election #{election_id}...")
    code, html = client.get("/admin/dashboard")
    csrf = client.get_csrf(html)
    code, html = client.post(f"/admin/election/{election_id}/status/closed", {
        "csrf_token": csrf
    })
    print("[+] Election closed.")

    # 8. Tally Election with Private Key
    with open("demo_private_key.pem", "r") as f:
        priv_pem_content = f.read()

    print(f"[*] 7. Tallying votes using RSA private key...")
    code, html = client.get(f"/admin/election/{election_id}/tally")
    csrf = client.get_csrf(html)
    code, html = client.post(f"/admin/election/{election_id}/tally", {
        "csrf_token": csrf,
        "private_key_text": priv_pem_content,
        "passphrase": "DemoElectionPassphrase2026!"
    })
    assert "Official Certified Results" in html
    assert "Certified Digital Signature" in html
    print("[+] Election tallied and certified with RSA-PSS signature!")

    # 9. Export Results
    print(f"[*] 8. Testing Results CSV and JSON exports...")
    code, json_resp = client.get(f"/admin/election/{election_id}/export/json")
    assert '"signature_rsa_pss"' in json_resp
    print("[+] JSON Export verified.")

    code, csv_resp = client.get(f"/admin/election/{election_id}/export/csv")
    assert "Rank,Candidate Name" in csv_resp
    print("[+] CSV Export verified.")

    print("\n=======================================================")
    print("[+] ALL LIVE FLASK HTTP FLOWS VERIFIED SUCCESSFULLY!")
    print("=======================================================\n")


if __name__ == "__main__":
    run_live_verification()
