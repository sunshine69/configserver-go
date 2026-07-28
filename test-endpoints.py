#!/usr/bin/env python3
"""
Test suite for config-server-go endpoints based on Spring Cloud Config specs.

Endpoints tested (ignoring Format-Specific Text Endpoints per instruction):
1. GET /{app}/{profile}[/{label}]     - JSON Environment Endpoint
2. GET /{app}/{profile}/{label}/{path} - Plain Text / Raw File Endpoint
3. POST /encrypt                       - Encrypt endpoint
4. POST /decrypt                       - Decrypt endpoint
5. POST /upload                        - Upload endpoint
6. POST /delete                        - Delete endpoint
7. GET /list                           - List endpoint
"""

import sys
import os
import time

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from simple_upload import load_env

import requests

# ── Configuration ─────────────────────────────────────────────────────────────
env = load_env()
BASE_URL = env.get("CONFIG_SERVER_URL", "http://localhost:7777")
USERNAME = env.get("USERNAME", "user2")
PASSWORD = env.get("PASSWORD", "changeme")
PROJECT = env.get("PROJECT", "myapp.mydomain")
PROFILE = env.get("PROFILE", "default")
LABEL = env.get("LABEL", "")

AUTH = (USERNAME, PASSWORD)

# Test data directory
TEST_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test-data")

results = []

def add_result(test_name, passed, detail=""):
    results.append({"test": test_name, "passed": passed, "detail": detail})

def assert_status(expected_status, response, test_name):
    if response.status_code == expected_status:
        add_result(test_name, True)
        return True
    else:
        add_result(test_name, False, f"Expected {expected_status}, got {response.status_code}")
        return False

def assert_json_field(response, test_name, field, expected_value):
    data = response.json()
    actual = data.get(field)
    if actual == expected_value:
        add_result(test_name, True)
        return True
    else:
        add_result(test_name, False, f"Expected {field}={expected_value}, got {field}={actual}")
        return False

def assert_contains(response, test_name, expected_in_body):
    body = response.text if response.text else ""
    if expected_in_body in body:
        add_result(test_name, True)
        return True
    else:
        add_result(test_name, False, f"Expected '{expected_in_body}' in response body, got: {body[:500]}")
        return False

# ═══════════════════════════════════════════════════════════════════════════════
# SETUP: Upload test data using the python upload helper
# ═══════════════════════════════════════════════════════════════════════════════

def upload_test_data():
    """Upload test data files to the server using simple_upload.py."""
    global LABEL, TEST_DATA_DIR
    if LABEL == "":
        LABEL = "main"
    os.system(f"python3 simple_upload.py -path {TEST_DATA_DIR} -label {LABEL}")

# ═══════════════════════════════════════════════════════════════════════════════
# TEST: POST /upload — Upload endpoint
# ═══════════════════════════════════════════════════════════════════════════════

def test_upload_without_label():
    """Upload a file without label parameter."""
    test_name = "POST /upload (without label)"
    fpath = os.path.join(TEST_DATA_DIR, "dev.yaml")
    with open(fpath, "r") as f:
        content = f.read()

    params = {"app": PROJECT, "profile": PROFILE, "ext": ".yaml", "path": "dev.yaml"}
    resp = requests.post(f"{BASE_URL}/upload", auth=AUTH, params=params, data=content)

    if resp.status_code == 200 and "uploaded" in resp.json().get("description", "").lower():
        add_result(test_name, True)
    else:
        add_result(test_name, False, f"status={resp.status_code}, body={resp.text[:300]}")

def test_upload_with_label():
    """Upload a file with label parameter."""
    test_name = "POST /upload (with label)"
    fpath = os.path.join(TEST_DATA_DIR, "prod.json")
    with open(fpath, "r") as f:
        content = f.read()

    params = {"app": PROJECT, "profile": PROFILE, "label": "main", "ext": ".json", "path": "prod.json"}
    resp = requests.post(f"{BASE_URL}/upload", auth=AUTH, params=params, data=content)

    if resp.status_code == 200 and "uploaded" in resp.json().get("description", "").lower():
        add_result(test_name, True)
    else:
        add_result(test_name, False, f"status={resp.status_code}, body={resp.text[:300]}")

def test_upload_with_special_char_label():
    """Upload a file with a label containing special characters like parentheses."""
    test_name = "POST /upload (with special char label)"
    fpath = os.path.join(TEST_DATA_DIR, "dev.yaml")
    with open(fpath, "r") as f:
        content = f.read()

    # Label with parentheses and hyphens: feature(_)beta-testing
    special_label = "feature(_)beta-testing"
    params = {"app": PROJECT, "profile": PROFILE, "label": special_label, "ext": ".yaml", "path": "dev.yaml"}
    resp = requests.post(f"{BASE_URL}/upload", auth=AUTH, params=params, data=content)

    if resp.status_code == 200 and "uploaded" in resp.json().get("description", "").lower():
        add_result(test_name, True)
    else:
        add_result(test_name, False, f"status={resp.status_code}, body={resp.text[:300]}")

def test_upload_invalid_ext():
    """Upload a file with unsupported extension."""
    test_name = "POST /upload (invalid ext)"
    content = "hello"
    params = {"app": PROJECT, "profile": PROFILE, "ext": ".txt", "path": "test.txt"}
    resp = requests.post(f"{BASE_URL}/upload", auth=AUTH, params=params, data=content)

    if resp.status_code == 400:
        add_result(test_name, True)
    else:
        add_result(test_name, False, f"Expected 400, got {resp.status_code}")

def test_upload_invalid_app():
    """Upload with invalid app name."""
    test_name = "POST /upload (invalid app)"
    content = "hello"
    params = {"app": "app/invalid", "profile": PROFILE, "ext": ".yaml", "path": "test.yaml"}
    resp = requests.post(f"{BASE_URL}/upload", auth=AUTH, params=params, data=content)

    if resp.status_code == 400:
        add_result(test_name, True)
    else:
        add_result(test_name, False, f"Expected 400, got {resp.status_code}")

def test_upload_missing_app():
    """Upload with missing app parameter."""
    test_name = "POST /upload (missing app)"
    content = "hello"
    params = {"profile": PROFILE, "ext": ".yaml", "path": "test.yaml"}
    resp = requests.post(f"{BASE_URL}/upload", auth=AUTH, params=params, data=content)

    if resp.status_code == 400:
        add_result(test_name, True)
    else:
        add_result(test_name, False, f"Expected 400, got {resp.status_code}")

# ═══════════════════════════════════════════════════════════════════════════════
# TEST: GET /{app}/{profile}[/{label}] — JSON Environment Endpoint
# ═══════════════════════════════════════════════════════════════════════════════

def test_get_env_basic():
    """GET /{app}/{profile} — basic JSON Environment response."""
    test_name = "GET /{app}/{profile} (basic)"
    resp = requests.get(f"{BASE_URL}/{PROJECT}/{PROFILE}", auth=AUTH)

    if not assert_status(200, resp, test_name):
        return
    # Check response has required fields
    data = resp.json()
    if data.get("name") == PROJECT and "profiles" in data and "propertySources" in data:
        add_result(test_name, True)
    else:
        add_result(test_name, False, f"Missing expected fields in response: {data}")

def test_get_env_with_label():
    """GET /{app}/{profile}/{label} — with label."""
    test_name = "GET /{app}/{profile}/{label} (with label)"
    resp = requests.get(f"{BASE_URL}/{PROJECT}/{PROFILE}/main", auth=AUTH)

    if not assert_status(200, resp, test_name):
        return
    data = resp.json()
    if data.get("name") == PROJECT and data.get("label") == "main" and "propertySources" in data:
        add_result(test_name, True)
    else:
        add_result(test_name, False, f"Response: {data}")

def test_get_env_with_special_char_label():
    """GET /{app}/{profile}/{label} — with label containing special characters like parentheses."""
    test_name = "GET /{app}/{profile}/{label} (with special char label)"
    # Label with parentheses and hyphens: feature(_)beta-testing
    special_label = "feature(_)beta-testing"
    resp = requests.get(f"{BASE_URL}/{PROJECT}/{PROFILE}/{special_label}", auth=AUTH)

    if not assert_status(200, resp, test_name):
        return
    data = resp.json()
    if data.get("name") == PROJECT and data.get("label") == "feature(_)beta-testing" and "propertySources" in data:
        add_result(test_name, True)
    else:
        add_result(test_name, False, f"Response: {data}")

def test_get_env_file_ext():
    """GET /{app}/{profile}.yaml — request specific extension."""
    test_name = "GET /{app}/{profile}.yaml (file ext)"
    resp = requests.get(f"{BASE_URL}/{PROJECT}/{PROFILE}.yaml", auth=AUTH)

    # This should return raw file content (application/octet-stream)
    if resp.status_code == 200 and "localhost" in resp.text:
        add_result(test_name, True)
    else:
        add_result(test_name, False, f"status={resp.status_code}, body={resp.text[:300]}")

def test_get_env_not_found():
    """GET /{app}/{profile} where config does not exist."""
    test_name = "GET /{app}/{profile} (not found)"
    resp = requests.get(f"{BASE_URL}/nonexistent/nonexistent", auth=AUTH)

    if resp.status_code == 404:
        add_result(test_name, True)
    else:
        add_result(test_name, False, f"Expected 404, got {resp.status_code}")

def test_get_env_multiple_profiles():
    """GET /{app}/{profile1},{profile2} — multiple profiles."""
    test_name = "GET /{app}/{profile1},{profile2} (multiple profiles)"
    resp = requests.get(f"{BASE_URL}/{PROJECT}/default,main", auth=AUTH)

    if resp.status_code == 200:
        data = resp.json()
        if "default" in data.get("profiles", []) and "main" in data.get("profiles", []):
            add_result(test_name, True)
        else:
            add_result(test_name, False, f"Expected profiles to include both default and main: {data}")
    else:
        add_result(test_name, False, f"status={resp.status_code}, body={resp.text[:300]}")

# ═══════════════════════════════════════════════════════════════════════════════
# TEST: GET /{app}/{profile}/{label}/{path} — Plain Text / Raw File Endpoint
# ═══════════════════════════════════════════════════════════════════════════════

def test_get_raw_file_by_path():
    """GET /{app}/{profile}/{label}/{path} — serve raw file by path."""
    test_name = "GET /{app}/{profile}/{label}/{path} (raw file)"
    resp = requests.get(f"{BASE_URL}/{PROJECT}/default/main/dev.yaml", auth=AUTH,
                       headers={"Accept": "application/octet-stream"})

    if resp.status_code == 200 and "localhost" in resp.text:
        add_result(test_name, True)
    else:
        add_result(test_name, False, f"status={resp.status_code}, body={resp.text[:300]}")

def test_get_raw_file_default_label():
    """GET /{app}/{profile}/{path}?useDefaultLabel=true — omit label."""
    test_name = "GET /{app}/{profile}/{path}?useDefaultLabel=true"
    resp = requests.get(f"{BASE_URL}/{PROJECT}/default/dev.yaml?useDefaultLabel=true", auth=AUTH,
                       headers={"Accept": "application/octet-stream"})

    if resp.status_code == 200 and "localhost" in resp.text:
        add_result(test_name, True)
    else:
        add_result(test_name, False, f"status={resp.status_code}, body={resp.text[:300]}")

def test_get_raw_file_not_found():
    """GET /{app}/{profile}/{label}/{path} where file does not exist."""
    test_name = "GET /{app}/{profile}/{label}/{path} (not found)"
    resp = requests.get(f"{BASE_URL}/{PROJECT}/default/main/nonexistent.yaml", auth=AUTH,
                       headers={"Accept": "application/octet-stream"})

    if resp.status_code == 404:
        add_result(test_name, True)
    else:
        add_result(test_name, False, f"Expected 404, got {resp.status_code}")

def test_get_raw_file_with_special_char_label():
    """GET /{app}/{profile}/{label}/{path} — serve raw file with label containing special characters."""
    test_name = "GET /{app}/{profile}/{label}/{path} (raw file with special label)"
    # Label with parentheses and hyphens: feature(_)beta-testing
    special_label = "feature(_)beta-testing"
    resp = requests.get(f"{BASE_URL}/{PROJECT}/default/{special_label}/dev.yaml", auth=AUTH,
                       headers={"Accept": "application/octet-stream"})

    if resp.status_code == 200 and "localhost" in resp.text:
        add_result(test_name, True)
    else:
        add_result(test_name, False, f"status={resp.status_code}, body={resp.text[:300]}")

# ═══════════════════════════════════════════════════════════════════════════════
# TEST: POST /encrypt — Encrypt endpoint
# ═══════════════════════════════════════════════════════════════════════════════

def test_encrypt_basic():
    """POST /encrypt — encrypt a plaintext string."""
    test_name = "POST /encrypt (basic)"
    plaintext = "Hello, World!"
    resp = requests.post(f"{BASE_URL}/encrypt", auth=AUTH, data=plaintext)

    if resp.status_code == 200 and len(resp.text) > 0:
        encrypted = resp.text
        # The encrypted value should not be the same as plaintext
        if encrypted != plaintext:
            add_result(test_name, True)
        else:
            add_result(test_name, False, "Encrypted value equals plaintext")
    else:
        add_result(test_name, False, f"status={resp.status_code}, body={resp.text[:300]}")

def test_encrypt_empty():
    """POST /encrypt — encrypt an empty string."""
    test_name = "POST /encrypt (empty)"
    resp = requests.post(f"{BASE_URL}/encrypt", auth=AUTH, data="")

    if resp.status_code == 200:
        add_result(test_name, True)
    else:
        add_result(test_name, False, f"status={resp.status_code}, body={resp.text[:300]}")

def test_encrypt_unauthorized():
    """POST /encrypt — unauthorized request."""
    test_name = "POST /encrypt (unauthorized)"
    resp = requests.post(f"{BASE_URL}/encrypt", data="test", auth=("wronguser", "wrongpass"))

    if resp.status_code == 401:
        add_result(test_name, True)
    else:
        add_result(test_name, False, f"Expected 401, got {resp.status_code}")

# ═══════════════════════════════════════════════════════════════════════════════
# TEST: POST /decrypt — Decrypt endpoint
# ═══════════════════════════════════════════════════════════════════════════════

def test_decrypt_basic():
    """POST /decrypt — decrypt an encrypted string."""
    test_name = "POST /decrypt (basic)"
    plaintext = "Hello, World!"

    # First encrypt
    enc_resp = requests.post(f"{BASE_URL}/encrypt", auth=AUTH, data=plaintext)
    if enc_resp.status_code != 200:
        add_result(test_name, False, "Failed to encrypt for decrypt test")
        return

    encrypted = enc_resp.text

    # Then decrypt
    dec_resp = requests.post(f"{BASE_URL}/decrypt", auth=AUTH, data=encrypted)

    if dec_resp.status_code == 200 and dec_resp.text == plaintext:
        add_result(test_name, True)
    else:
        add_result(test_name, False, f"status={dec_resp.status_code}, body={dec_resp.text[:300]}")

def test_decrypt_wrong_key():
    """POST /decrypt — decrypt with a key that doesn't match (should fail)."""
    test_name = "POST /decrypt (wrong key)"
    # Try to decrypt with a different user's encryption key
    # We'll use a random string that can't be decrypted by user2
    resp = requests.post(f"{BASE_URL}/decrypt", auth=AUTH, data="invalidcipher123")

    # This should return 400 because decryption fails with wrong key
    if resp.status_code == 400:
        add_result(test_name, True)
    else:
        add_result(test_name, False, f"Expected 400, got {resp.status_code}, body={resp.text[:300]}")

def test_decrypt_unauthorized():
    """POST /decrypt — unauthorized request."""
    test_name = "POST /decrypt (unauthorized)"
    resp = requests.post(f"{BASE_URL}/decrypt", data="test", auth=("wronguser", "wrongpass"))

    if resp.status_code == 401:
        add_result(test_name, True)
    else:
        add_result(test_name, False, f"Expected 401, got {resp.status_code}")

# ═══════════════════════════════════════════════════════════════════════════════
# TEST: GET /list — List endpoint
# ═══════════════════════════════════════════════════════════════════════════════

def test_list_basic():
    """GET /list — list all configuration files."""
    test_name = "GET /list (basic)"
    resp = requests.get(f"{BASE_URL}/list", auth=AUTH)

    if resp.status_code == 200 and isinstance(resp.json(), list):
        files = resp.json()
        if len(files) > 0:
            add_result(test_name, True, f"Found {len(files)} files")
        else:
            add_result(test_name, False, "No files found")
    else:
        add_result(test_name, False, f"status={resp.status_code}, body={resp.text[:300]}")

def test_list_unauthorized():
    """GET /list — unauthorized request."""
    test_name = "GET /list (unauthorized)"
    resp = requests.get(f"{BASE_URL}/list", auth=("wronguser", "wrongpass"))

    if resp.status_code == 401:
        add_result(test_name, True)
    else:
        add_result(test_name, False, f"Expected 401, got {resp.status_code}")

# ═══════════════════════════════════════════════════════════════════════════════
# TEST: POST /delete — Delete endpoint
# ═══════════════════════════════════════════════════════════════════════════════

def test_delete_basic():
    """POST /delete — delete a configuration file."""
    test_name = "POST /delete (basic)"
    # First upload, then delete
    # Upload a test file
    fpath = os.path.join(TEST_DATA_DIR, "list.yaml")
    with open(fpath, "r") as f:
        content = f.read()

    params = {"app": PROJECT, "profile": PROFILE, "ext": ".yaml", "path": "list.yaml"}
    requests.post(f"{BASE_URL}/upload", auth=AUTH, params=params, data=content)

    # Then delete
    del_params = {"app": PROJECT, "profile": PROFILE, "ext": ".yaml"}
    del_resp = requests.delete(f"{BASE_URL}/delete", auth=AUTH, params=del_params)

    if del_resp.status_code == 200 and "deleted" in del_resp.json().get("description", "").lower():
        add_result(test_name, True)
    else:
        add_result(test_name, False, f"status={del_resp.status_code}, body={del_resp.text[:300]}")

def test_delete_not_found():
    """POST /delete — delete a file that doesn't exist."""
    test_name = "POST /delete (not found)"
    del_params = {"app": "nonexistent", "profile": "nonexistent", "ext": ".yaml"}
    del_resp = requests.delete(f"{BASE_URL}/delete", auth=AUTH, params=del_params)

    if del_resp.status_code == 404:
        add_result(test_name, True)
    else:
        add_result(test_name, False, f"Expected 404, got {del_resp.status_code}")

def test_delete_missing_params():
    """POST /delete — delete with missing required params."""
    test_name = "POST /delete (missing params)"
    del_params = {"app": PROJECT}  # missing profile and ext
    del_resp = requests.delete(f"{BASE_URL}/delete", auth=AUTH, params=del_params)

    if del_resp.status_code == 400:
        add_result(test_name, True)
    else:
        add_result(test_name, False, f"Expected 400, got {del_resp.status_code}")

def test_delete_invalid_ext():
    """POST /delete — delete with unsupported extension."""
    test_name = "POST /delete (invalid ext)"
    del_params = {"app": PROJECT, "profile": PROFILE, "ext": ".txt"}
    del_resp = requests.delete(f"{BASE_URL}/delete", auth=AUTH, params=del_params)

    if del_resp.status_code == 400:
        add_result(test_name, True)
    else:
        add_result(test_name, False, f"Expected 400, got {del_resp.status_code}")

# ═══════════════════════════════════════════════════════════════════════════════
# Additional edge-case tests based on the spec
# ═══════════════════════════════════════════════════════════════════════════════

def test_get_env_with_special_chars_in_app():
    """GET /{app}/{profile} — app name with special characters (should be rejected)."""
    test_name = "GET /{app}/{profile} (invalid app name)"
    resp = requests.get(f"{BASE_URL}/app/invalid/default", auth=AUTH)

    # Should return 400 for invalid path segment
    if resp.status_code == 400:
        add_result(test_name, True)
    else:
        # Also accept 404 as valid (the path segment validation might not apply to GET)
        if resp.status_code == 404:
            add_result(test_name, True)
        else:
            add_result(test_name, False, f"Expected 400 or 404, got {resp.status_code}")

def test_get_env_with_spaces_in_profile():
    """GET /{app}/{profile} — profile name with spaces."""
    test_name = "GET /{app}/{profile} (profile with spaces)"
    resp = requests.get(f"{BASE_URL}/{PROJECT}/profile with spaces", auth=AUTH)

    # Should return 400 for invalid path segment
    if resp.status_code == 400:
        add_result(test_name, True)
    else:
        # Also accept 404 as valid
        if resp.status_code == 404:
            add_result(test_name, True)
        else:
            add_result(test_name, False, f"Expected 400 or 404, got {resp.status_code}")

# ═══════════════════════════════════════════════════════════════════════════════
# RUN ALL TESTS
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 80)
    print("CONFIG-SERVER-GO ENDPOINT TEST SUITE")
    print(f"Base URL: {BASE_URL}")
    print(f"User: {USERNAME}")
    print("=" * 80)

    # Reset the app before running tests
    print("\n>>> Resetting app...")
    os.system("docker compose down -v; docker compose up -d --build")
    print(">>> Waiting for server to be ready...")
    time.sleep(5)

    # Verify server is up
    try:
        health = requests.get(f"{BASE_URL}/health")
        if health.status_code == 200:
            print(">>> Server is healthy!")
        else:
            print(f">>> WARNING: Server health check failed: {health.status_code}")
    except Exception as e:
        print(f">>> ERROR: Cannot reach server: {e}")
        sys.exit(1)

    # Upload test data first
    print("\n>>> Uploading test data...")
    upload_test_data()
    time.sleep(1)

    # Run all tests
    print("\n" + "=" * 80)
    print("RUNNING TESTS")
    print("=" * 80)

    # Upload tests
    test_upload_without_label()
    test_upload_with_label()
    test_upload_with_special_char_label()
    test_upload_invalid_ext()
    test_upload_invalid_app()
    test_upload_missing_app()

    # JSON Environment endpoint tests
    test_get_env_basic()
    test_get_env_with_label()
    test_get_env_with_special_char_label()
    test_get_env_file_ext()
    test_get_env_not_found()
    test_get_env_multiple_profiles()

    # Plain Text / Raw File endpoint tests
    test_get_raw_file_by_path()
    test_get_raw_file_default_label()
    test_get_raw_file_with_special_char_label()
    test_get_raw_file_not_found()

    # Encrypt tests
    test_encrypt_basic()
    test_encrypt_empty()
    test_encrypt_unauthorized()

    # Decrypt tests
    test_decrypt_basic()
    test_decrypt_wrong_key()
    test_decrypt_unauthorized()

    # List tests
    test_list_basic()
    test_list_unauthorized()

    # Delete tests
    test_delete_basic()
    test_delete_not_found()
    test_delete_missing_params()
    test_delete_invalid_ext()

    # Edge case tests
    test_get_env_with_special_chars_in_app()
    test_get_env_with_spaces_in_profile()

    # Summary
    print("\n" + "=" * 80)
    print("TEST RESULTS")
    print("=" * 80)

    passed = sum(1 for r in results if r["passed"])
    failed = sum(1 for r in results if not r["passed"])

    for r in results:
        status = "✓ PASS" if r["passed"] else "✗ FAIL"
        print(f"  {status}: {r['test']}")
        if not r["passed"]:
            print(f"         Detail: {r['detail']}")

    print(f"\nTotal: {len(results)} tests — {passed} passed, {failed} failed")

    # Print failed tests summary for docs
    if failed > 0:
        print("\nFAILED TESTS (for documentation):")
        print("-" * 40)
        for r in results:
            if not r["passed"]:
                print(f"  - {r['test']}: {r['detail']}")

    # Exit with non-zero if any tests failed
    sys.exit(1 if failed > 0 else 0)
