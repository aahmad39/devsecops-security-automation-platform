import os
import sys

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

from database import Base, get_db  # noqa: E402
from main import app  # noqa: E402

TEST_DB_URL = "sqlite:///./test_vulntracker.db"
engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def reset_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def register_and_login(username="alice", email="alice@example.com", password="password123"):
    client.post("/auth/register", json={"username": username, "email": email, "password": password})
    resp = client.post("/auth/login", json={"username": username, "password": password})
    return resp.json()["access_token"]


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_register_user():
    resp = client.post("/auth/register", json={
        "username": "bob",
        "email": "bob@example.com",
        "password": "secret",
    })
    assert resp.status_code == 201
    assert resp.json()["username"] == "bob"


def test_register_duplicate_username():
    payload = {"username": "bob", "email": "bob@example.com", "password": "secret"}
    client.post("/auth/register", json=payload)
    resp = client.post("/auth/register", json={**payload, "email": "bob2@example.com"})
    assert resp.status_code == 400


def test_login_success():
    client.post("/auth/register", json={"username": "alice", "email": "alice@example.com", "password": "pw"})
    resp = client.post("/auth/login", json={"username": "alice", "password": "pw"})
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_login_wrong_password():
    client.post("/auth/register", json={"username": "alice", "email": "alice@example.com", "password": "pw"})
    resp = client.post("/auth/login", json={"username": "alice", "password": "wrong"})
    assert resp.status_code == 401


def test_create_scan():
    token = register_and_login()
    resp = client.post("/scans", json={
        "title": "Reflected XSS in search",
        "description": "User input is echoed without sanitisation",
        "severity": "high",
        "affected_component": "GET /search",
    }, headers=auth_headers(token))
    assert resp.status_code == 201
    assert resp.json()["title"] == "Reflected XSS in search"


def test_list_scans():
    token = register_and_login()
    client.post("/scans", json={
        "title": "Test finding",
        "severity": "low",
        "affected_component": "misc",
    }, headers=auth_headers(token))
    resp = client.get("/scans", headers=auth_headers(token))
    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_search_scans():
    # TODO: add assertions for search results
    token = register_and_login()
    client.post("/scans", json={
        "title": "SQL Injection via login",
        "severity": "critical",
        "affected_component": "POST /auth/login",
    }, headers=auth_headers(token))
    resp = client.get("/scans/search?q=SQL", headers=auth_headers(token))
    assert resp.status_code == 200


def test_update_scan_status():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Open redirect",
        "severity": "medium",
        "affected_component": "redirect handler",
    }, headers=auth_headers(token)).json()["id"]

    resp = client.patch(f"/scans/{scan_id}", json={"status": "in_progress"}, headers=auth_headers(token))
    assert resp.status_code == 200
    assert resp.json()["status"] == "in_progress"


def test_delete_scan():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Stale finding",
        "severity": "low",
        "affected_component": "misc",
    }, headers=auth_headers(token)).json()["id"]

    resp = client.delete(f"/scans/{scan_id}", headers=auth_headers(token))
    assert resp.status_code == 204


# ---------------------------------------------------------------------------
# Task 1 Shared Report Link Tests
# ---------------------------------------------------------------------------

def test_authorized_creation_of_share_link():
    token = register_and_login("charlie", "charlie@example.com", "pass123")
    scan_resp = client.post("/scans", json={
        "title": "Insecure CORS Policy",
        "severity": "medium",
        "affected_component": "FastAPI middleware",
    }, headers=auth_headers(token))
    scan_id = scan_resp.json()["id"]

    resp = client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(token))
    assert resp.status_code == 200
    data = resp.json()
    assert "share_url" in data
    assert "/share/" in data["share_url"]


def test_unauthenticated_creation_attempt():
    resp = client.post("/scans/1/share", json={})
    assert resp.status_code == 401 or resp.status_code == 403


def test_authenticated_user_without_permission_to_share():
    alice_token = register_and_login("alice_share", "alice_share@example.com", "pass123")
    bob_token = register_and_login("bob_share", "bob_share@example.com", "pass123")

    scan_resp = client.post("/scans", json={
        "title": "Confidential internal vulnerability",
        "severity": "critical",
        "affected_component": "auth module",
    }, headers=auth_headers(alice_token))
    scan_id = scan_resp.json()["id"]

    # Bob attempts to share Alice's scan
    resp = client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(bob_token))
    assert resp.status_code == 403
    assert "permission" in resp.json()["detail"].lower()


def test_share_scan_does_not_exist():
    token = register_and_login("david", "david@example.com", "pass123")
    resp = client.post("/scans/99999/share", json={}, headers=auth_headers(token))
    assert resp.status_code == 404


def test_valid_public_share_link():
    token = register_and_login("eve", "eve@example.com", "pass123")
    scan_resp = client.post("/scans", json={
        "title": "Publicly viewable vulnerability report",
        "description": "Details about external perimeter scan",
        "severity": "low",
        "affected_component": "edge proxy",
    }, headers=auth_headers(token))
    scan_id = scan_resp.json()["id"]

    share_resp = client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(token))
    share_url = share_resp.json()["share_url"]
    share_token = share_url.split("/share/")[1]

    # Access anonymously without Authorization header
    public_resp = client.get(f"/share/{share_token}")
    assert public_resp.status_code == 200
    data = public_resp.json()
    assert data["title"] == "Publicly viewable vulnerability report"
    assert data["severity"] == "low"
    assert "owner_id" not in data  # Ensure internal metadata/owner is not leaked
    assert "password_hash" not in data


def test_invalid_token():
    resp = client.get("/share/completely_invalid_random_token_1234567890")
    assert resp.status_code == 404
    assert "invalid or expired" in resp.json()["detail"].lower()


def test_expired_token():
    from datetime import datetime, timedelta
    import models

    token = register_and_login("frank", "frank@example.com", "pass123")
    scan_resp = client.post("/scans", json={
        "title": "Scan for expiration check",
        "severity": "low",
        "affected_component": "test",
    }, headers=auth_headers(token))
    scan_id = scan_resp.json()["id"]

    share_resp = client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(token))
    share_token = share_resp.json()["share_url"].split("/share/")[1]

    # Force expiration in test database
    db = TestingSessionLocal()
    from main import _hash_token
    token_h = _hash_token(share_token)
    record = db.query(models.ScanShareLink).filter(models.ScanShareLink.token_hash == token_h).first()
    record.expires_at = datetime.utcnow() - timedelta(minutes=5)
    db.commit()
    db.close()

    # Attempt public retrieval after expiry
    resp = client.get(f"/share/{share_token}")
    assert resp.status_code == 404
    assert "invalid or expired" in resp.json()["detail"].lower()


def test_token_with_password_and_correct_password():
    token = register_and_login("grace", "grace@example.com", "pass123")
    scan_resp = client.post("/scans", json={
        "title": "Protected Scan Report",
        "severity": "high",
        "affected_component": "database",
    }, headers=auth_headers(token))
    scan_id = scan_resp.json()["id"]

    share_resp = client.post(
        f"/scans/{scan_id}/share",
        json={"password": "StrongSecretPassword123!"},
        headers=auth_headers(token),
    )
    share_token = share_resp.json()["share_url"].split("/share/")[1]

    # Access with correct password
    resp = client.get(f"/share/{share_token}", params={"password": "StrongSecretPassword123!"})
    assert resp.status_code == 200
    assert resp.json()["title"] == "Protected Scan Report"


def test_token_with_password_and_incorrect_password():
    token = register_and_login("heidi", "heidi@example.com", "pass123")
    scan_resp = client.post("/scans", json={
        "title": "Protected Scan Report Heidi",
        "severity": "high",
        "affected_component": "api",
    }, headers=auth_headers(token))
    scan_id = scan_resp.json()["id"]

    share_resp = client.post(
        f"/scans/{scan_id}/share",
        json={"password": "CorrectSecretPassword"},
        headers=auth_headers(token),
    )
    share_token = share_resp.json()["share_url"].split("/share/")[1]

    resp = client.get(f"/share/{share_token}?password=WrongPassword")
    assert resp.status_code == 401
    assert "incorrect password" in resp.json()["detail"].lower()


def test_password_protected_link_accessed_without_password():
    token = register_and_login("ivan", "ivan@example.com", "pass123")
    scan_resp = client.post("/scans", json={
        "title": "Ivan Protected Scan",
        "severity": "medium",
        "affected_component": "api",
    }, headers=auth_headers(token))
    scan_id = scan_resp.json()["id"]

    share_resp = client.post(
        f"/scans/{scan_id}/share",
        json={"password": "SecretPassword123"},
        headers=auth_headers(token),
    )
    share_token = share_resp.json()["share_url"].split("/share/")[1]

    resp = client.get(f"/share/{share_token}")
    assert resp.status_code == 401
    assert "password required" in resp.json()["detail"].lower()


def test_unprotected_link_accessed_without_password():
    token = register_and_login("judy", "judy@example.com", "pass123")
    scan_resp = client.post("/scans", json={
        "title": "Open Unprotected Finding",
        "severity": "low",
        "affected_component": "frontend",
    }, headers=auth_headers(token))
    scan_id = scan_resp.json()["id"]

    share_resp = client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(token))
    share_token = share_resp.json()["share_url"].split("/share/")[1]

    resp = client.get(f"/share/{share_token}")
    assert resp.status_code == 200
    assert resp.json()["title"] == "Open Unprotected Finding"


def test_expiry_cannot_be_extended_beyond_24_hours():
    from datetime import datetime, timedelta
    import models

    token = register_and_login("mallory", "mallory@example.com", "pass123")
    scan_resp = client.post("/scans", json={
        "title": "Expiry Enforcement Scan",
        "severity": "low",
        "affected_component": "test",
    }, headers=auth_headers(token))
    scan_id = scan_resp.json()["id"]

    share_resp = client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(token))
    share_token = share_resp.json()["share_url"].split("/share/")[1]

    db = TestingSessionLocal()
    from main import _hash_token
    token_h = _hash_token(share_token)
    record = db.query(models.ScanShareLink).filter(models.ScanShareLink.token_hash == token_h).first()
    max_expected = datetime.utcnow() + timedelta(hours=24, minutes=1)
    min_expected = datetime.utcnow() + timedelta(hours=23, minutes=58)
    assert record.expires_at <= max_expected
    assert record.expires_at >= min_expected
    db.close()


def test_share_token_is_not_stored_in_plaintext():
    import models

    token = register_and_login("oscar", "oscar@example.com", "pass123")
    scan_resp = client.post("/scans", json={
        "title": "Plaintext Token Storage Check",
        "severity": "low",
        "affected_component": "test",
    }, headers=auth_headers(token))
    scan_id = scan_resp.json()["id"]

    share_resp = client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(token))
    raw_token = share_resp.json()["share_url"].split("/share/")[1]

    db = TestingSessionLocal()
    # Check that raw_token does NOT exist anywhere in the scan_share_links table
    all_links = db.query(models.ScanShareLink).all()
    for link in all_links:
        assert link.token_hash != raw_token
        assert raw_token not in (link.token_hash or "")
    db.close()


def test_password_is_not_stored_in_plaintext():
    import models

    token = register_and_login("peggy", "peggy@example.com", "pass123")
    scan_resp = client.post("/scans", json={
        "title": "Password Plaintext Check",
        "severity": "low",
        "affected_component": "test",
    }, headers=auth_headers(token))
    scan_id = scan_resp.json()["id"]

    raw_password = "SuperSecretPlaintextPassword99!"
    share_resp = client.post(
        f"/scans/{scan_id}/share",
        json={"password": raw_password},
        headers=auth_headers(token),
    )
    raw_token = share_resp.json()["share_url"].split("/share/")[1]

    db = TestingSessionLocal()
    from main import _hash_token
    record = db.query(models.ScanShareLink).filter(models.ScanShareLink.token_hash == _hash_token(raw_token)).first()
    assert record.password_hash != raw_password
    assert raw_password not in record.password_hash
    db.close()


def test_public_response_does_not_leak_internal_fields():
    token = register_and_login("sybil", "sybil@example.com", "pass123")
    scan_resp = client.post("/scans", json={
        "title": "Internal Leak Prevention Scan",
        "severity": "low",
        "affected_component": "internal",
    }, headers=auth_headers(token))
    scan_id = scan_resp.json()["id"]

    share_resp = client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(token))
    share_token = share_resp.json()["share_url"].split("/share/")[1]

    resp = client.get(f"/share/{share_token}")
    data = resp.json()
    assert "owner_id" not in data
    assert "owner" not in data
    assert "token_hash" not in data
    assert "password_hash" not in data
    assert "created_by_user_id" not in data


def test_tokens_for_different_shares_are_unpredictable_and_distinct():
    token = register_and_login("trent", "trent@example.com", "pass123")
    scan_resp = client.post("/scans", json={
        "title": "Entropy Test Scan",
        "severity": "low",
        "affected_component": "test",
    }, headers=auth_headers(token))
    scan_id = scan_resp.json()["id"]

    tokens = set()
    for _ in range(5):
        resp = client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(token))
        t = resp.json()["share_url"].split("/share/")[1]
        assert len(t) >= 40  # 32 bytes base64url is 43-44 chars
        tokens.add(t)
    assert len(tokens) == 5


def test_malformed_input_and_boundary_cases():
    # Extremely short token
    resp = client.get("/share/abc")
    assert resp.status_code == 404

    # Extremely long token
    resp = client.get(f"/share/{'x' * 200}")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Task 3 Security Remediation Tests
# ---------------------------------------------------------------------------

def test_jwt_none_algorithm_rejected():
    import base64
    import json
    # Craft an unsigned JWT token with alg: none to test algorithm confusion defense
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps({"sub": "alice"}).encode()).decode().rstrip("=")
    forged_token = f"{header}.{payload}."
    resp = client.get("/scans", headers={"Authorization": f"Bearer {forged_token}"})
    assert resp.status_code == 401


def test_search_scans_sql_injection_defense():
    token = register_and_login("sqli_tester", "sqli@example.com", "pass123")
    client.post("/scans", json={
        "title": "Legitimate Finding",
        "severity": "low",
        "affected_component": "ui",
    }, headers=auth_headers(token))

    # SQL Injection payload attempt
    sqli_payload = "' OR 1=1 -- "
    resp = client.get(f"/scans/search?q={sqli_payload}", headers=auth_headers(token))
    assert resp.status_code == 200
    # Should safely return 0 results because no record contains literal "' OR 1=1 -- "
    assert resp.json()["count"] == 0


def test_idor_get_scan_prevented():
    alice_token = register_and_login("alice_idor", "alice_idor@example.com", "pass123")
    bob_token = register_and_login("bob_idor", "bob_idor@example.com", "pass123")

    alice_scan_id = client.post("/scans", json={
        "title": "Alice Private Vulnerability",
        "severity": "critical",
        "affected_component": "internal auth",
    }, headers=auth_headers(alice_token)).json()["id"]

    # Bob attempts to view Alice's scan directly by ID
    resp = client.get(f"/scans/{alice_scan_id}", headers=auth_headers(bob_token))
    assert resp.status_code == 404


def test_idor_search_scans_prevented():
    alice_token = register_and_login("alice_search", "alice_search@example.com", "pass123")
    bob_token = register_and_login("bob_search", "bob_search@example.com", "pass123")

    client.post("/scans", json={
        "title": "Secret Alice Project Finding",
        "severity": "high",
        "affected_component": "payments",
    }, headers=auth_headers(alice_token))

    # Bob searches for Alice's finding
    resp = client.get("/scans/search?q=Secret", headers=auth_headers(bob_token))
    assert resp.status_code == 200
    assert resp.json()["count"] == 0


def test_cors_origin_restriction():
    resp = client.get("/health", headers={"Origin": "https://malicious-attacker-site.com"})
    assert "Access-Control-Allow-Origin" not in resp.headers


def test_share_link_weak_password_rejected():
    token = register_and_login("weak_pw_tester", "weak@example.com", "pass123")
    scan_id = client.post("/scans", json={
        "title": "Weak Password Finding",
        "severity": "medium",
        "affected_component": "share",
    }, headers=auth_headers(token)).json()["id"]

    # Attempt to protect share link with a password shorter than 8 chars
    resp = client.post(
        f"/scans/{scan_id}/share",
        json={"password": "short"},
        headers=auth_headers(token),
    )
    assert resp.status_code == 400
    assert "at least 8 characters" in resp.json()["detail"]
