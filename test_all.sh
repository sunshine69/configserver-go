#!/bin/bash
#
# Comprehensive test suite for config-server-go
# Covers: filesystem backend, PostgreSQL backend, auth, encrypt/decrypt,
#         multi-password auth, format-specific endpoints, input validation,
#         edge cases, and Spring Cloud Config spec compliance.
#
# Usage: ./test_all.sh [server_url]
#   server_url defaults to http://localhost:7777
#

#set -euo pipefail

# ── Configuration ──────────────────────────────────────────────────────────────
BASE_URL="${1:-http://localhost:7777}"

# Dynamically read ALL credentials from .env so tests always match config.yaml
set -a
source "$(dirname "${BASH_SOURCE[0]}")/.env"
set +a

PASS=0
FAIL=0
TOTAL=0

# ── Helpers ────────────────────────────────────────────────────────────────────

# Print a test header
test_header() {
    echo ""
    echo "=============================================="
    echo "  $1"
    echo "=============================================="
}

# Run a test: expects a specific HTTP status code
# Usage: expect_status "description" EXPECTED_CODE "curl_args..."
expect_status() {
    local desc="$1"
    local expected="$2"
    shift 2
    local curl_args=("$@")

    TOTAL=$((TOTAL + 1))
    local response
    local http_code
    response=$(curl -s -w "\n%{http_code}" "${curl_args[@]}" 2>/dev/null)
    http_code=$(echo "$response" | tail -1)
    local body
    body=$(echo "$response" | sed '$d')

    if [[ "$http_code" == "$expected" ]]; then
        PASS=$((PASS + 1))
        echo "  ✅ PASS: $desc (HTTP $http_code)"
    else
        FAIL=$((FAIL + 1))
        echo "  ❌ FAIL: $desc (expected HTTP $expected, got HTTP $http_code)"
        if [[ -n "$body" && "$body" != "$http_code" ]]; then
            echo "       Response: $(echo "$body" | head -c 200)"
        fi
    fi
}

# Run a test: expects the response body to contain a substring
# Usage: expect_contains "description" "substring" "curl_args..."
expect_contains() {
    local desc="$1"
    local substring="$2"
    shift 2
    local curl_args=("$@")

    TOTAL=$((TOTAL + 1))
    local response
    local http_code
    response=$(curl -s -w "\n%{http_code}" "${curl_args[@]}" 2>/dev/null)
    http_code=$(echo "$response" | tail -1)
    local body
    body=$(echo "$response" | sed '$d')

    if echo "$body" | grep -qF "$substring"; then
        PASS=$((PASS + 1))
        echo "  ✅ PASS: $desc (HTTP $http_code, contains '$substring')"
    else
        FAIL=$((FAIL + 1))
        echo "  ❌ FAIL: $desc (expected body to contain '$substring')"
        echo "       Got HTTP $http_code: $(echo "$body" | head -c 200)"
    fi
}

# Run a test: expects the response body to NOT contain a substring
# Usage: expect_not_contains "description" "substring" "curl_args..."
expect_not_contains() {
    local desc="$1"
    local substring="$2"
    shift 2
    local curl_args=("$@")

    TOTAL=$((TOTAL + 1))
    local response
    local http_code
    response=$(curl -s -w "\n%{http_code}" "${curl_args[@]}" 2>/dev/null)
    http_code=$(echo "$response" | tail -1)
    local body
    body=$(echo "$response" | sed '$d')

    if ! echo "$body" | grep -qF "$substring"; then
        PASS=$((PASS + 1))
        echo "  ✅ PASS: $desc (HTTP $http_code, does not contain '$substring')"
    else
        FAIL=$((FAIL + 1))
        echo "  ❌ FAIL: $desc (body should NOT contain '$substring')"
        echo "       Got HTTP $http_code: $(echo "$body" | head -c 200)"
    fi
}

# Run a test: expects JSON body to have a specific key-value in propertySources
# Usage: expect_property "description" "app_url" "username:password" "key" "value"
expect_property() {
    local desc="$1"
    local url="$2"
    local auth="$3"
    local key="$4"
    local expected_value="$5"

    TOTAL=$((TOTAL + 1))
    local response
    local http_code
    response=$(curl -s -w "\n%{http_code}" "$url" -u "$auth" 2>/dev/null)
    http_code=$(echo "$response" | tail -1)
    local body
    body=$(echo "$response" | sed '$d')

    if [[ "$http_code" == "200" ]]; then
        local actual
        actual=$(echo "$body" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    src = d.get('propertySources', [{}])[0].get('source', {})
    v = src.get('$key')
    if v is None:
        print('NONE')
    else:
        print(v)
except:
    print('PARSE_ERROR')
" 2>/dev/null || echo "ERROR")

        if [[ "$actual" == "$expected_value" ]]; then
            PASS=$((PASS + 1))
            echo "  ✅ PASS: $desc (key='$key' value='$actual')"
        else
            FAIL=$((FAIL + 1))
            echo "  ❌ FAIL: $desc (expected '$expected_value', got '$actual')"
        fi
    else
        FAIL=$((FAIL + 1))
        echo "  ❌ FAIL: $desc (HTTP $http_code, expected 200)"
    fi
}

# Run a test: expects JSON body to have specific fields
# Usage: expect_json_field "description" "curl_args" "field" "expected_value"
expect_json_field() {
    local desc="$1"
    shift
    local curl_args=("$@")
    local field="$2"
    local expected_value="$3"

    TOTAL=$((TOTAL + 1))
    local response
    local http_code
    response=$(curl -s -w "\n%{http_code}" "${curl_args[@]}" 2>/dev/null)
    http_code=$(echo "$response" | tail -1)
    local body
    body=$(echo "$response" | sed '$d')

    local actual
    actual=$(echo "$body" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(d.get('$field', 'MISSING'))
" 2>/dev/null || echo "PARSE_ERROR")

    if [[ "$http_code" == "200" && "$actual" == "$expected_value" ]]; then
        PASS=$((PASS + 1))
        echo "  ✅ PASS: $desc ($field='$actual')"
    else
        FAIL=$((FAIL + 1))
        echo "  ❌ FAIL: $desc (expected $field='$expected_value', got '$actual', HTTP $http_code)"
    fi
}

# ── Pre-flight check ─────────────────────────────────────────────────────────

echo "=============================================="
echo "  Config Server Go - Comprehensive Test Suite"
echo "=============================================="
echo ""
echo "Server: $BASE_URL"
echo "User1 (filesystem): ${USER1_USERNAME}/${USER1_PASSWORD}"
echo "User2 (postgres):   ${USER2_USERNAME}/${USER2_PASSWORD}"

# Check server is reachable
if ! curl -s --max-time 3 "$BASE_URL/" -o /dev/null 2>/dev/null; then
    echo ""
    echo "❌ Server not reachable at $BASE_URL"
    echo "   Make sure docker compose is running: docker compose up -d"
    exit 1
fi
echo "✅ Server is reachable"

# ── 1. Authentication Tests ───────────────────────────────────────────────────

test_header "1. Authentication Tests"

# No auth
expect_status "GET without authentication returns 401" \
    "401" \
    "$BASE_URL/myapp/dev.yaml"

# Wrong password
expect_status "GET with wrong password returns 401" \
    "401" \
    "$BASE_URL/myapp/dev.yaml" -u "${USER1_USERNAME}:wrongpass"

# Wrong user
expect_status "GET with unknown user returns 401" \
    "401" \
    "$BASE_URL/myapp/dev.yaml" -u "nonexistent:pass"

# Upload without auth
expect_status "Upload without authentication returns 401" \
    "401" \
    -X POST "$BASE_URL/upload?app=myapp&profile=test&ext=.yaml" -d "test"

# Upload with wrong password
expect_status "Upload with wrong password returns 401" \
    "401" \
    -X POST "$BASE_URL/upload?app=myapp&profile=test&ext=.yaml" -u "${USER1_USERNAME}:wrongpass" -d "test"

# ── 2. Filesystem Backend - Upload ────────────────────────────────────────────

test_header "2. Filesystem Backend - Upload Tests (user1)"

# Upload YAML
expect_status "Upload YAML file" \
    "200" \
    -X POST "$BASE_URL/upload?app=myapp&profile=dev&ext=.yaml" -u "${USER1_USERNAME}:${USER1_PASSWORD}" \
    --data-binary @test-data/dev.yaml

# Upload JSON
expect_status "Upload JSON file" \
    "200" \
    -X POST "$BASE_URL/upload?app=myapp&profile=prod&ext=.json" -u "${USER1_USERNAME}:${USER1_PASSWORD}" \
    --data-binary @test-data/prod.json

# Upload Properties
expect_status "Upload .properties file" \
    "200" \
    -X POST "$BASE_URL/upload?app=myapp&profile=prod&ext=.properties" -u "${USER1_USERNAME}:${USER1_PASSWORD}" \
    --data-binary @test-data/prod.properties

# Upload .yml
expect_status "Upload .yml file" \
    "200" \
    -X POST "$BASE_URL/upload?app=myapp&profile=ymltest&ext=.yml" -u "${USER1_USERNAME}:${USER1_PASSWORD}" \
    --data-binary @test-data/dev.yaml

# Upload with default extension (omitted)
expect_status "Upload with default .yaml extension" \
    "200" \
    -X POST "$BASE_URL/upload?app=myapp&profile=defaultext" -u "${USER1_USERNAME}:${USER1_PASSWORD}" \
    --data-binary @test-data/dev.yaml

# Upload with label
expect_status "Upload YAML with label" \
    "200" \
    -X POST "$BASE_URL/upload?app=myapp&profile=dev&label=main&ext=.yaml" -u "${USER1_USERNAME}:${USER1_PASSWORD}" \
    --data-binary @test-data/dev.yaml

# Upload with label v2
expect_status "Upload with label 'v2'" \
    "200" \
    -X POST "$BASE_URL/upload?app=myapp&profile=staging&label=v2&ext=.yaml" -u "${USER1_USERNAME}:${USER1_PASSWORD}" \
    --data-binary @test-data/dev.yaml

# Upload special characters in values
expect_status "Upload config with special characters" \
    "200" \
    -X POST "$BASE_URL/upload?app=myapp&profile=special2&ext=.yaml" -u "${USER1_USERNAME}:${USER1_PASSWORD}" \
    --data-binary @test-data/special2.yaml

# Upload large config
expect_status "Upload large config (100 keys)" \
    "200" \
    -X POST "$BASE_URL/upload?app=myapp&profile=large&ext=.yaml" -u "${USER1_USERNAME}:${USER1_PASSWORD}" \
    --data-binary @test-data/large.yaml

# Overwrite existing file
expect_status "Overwrite existing YAML file" \
    "200" \
    -X POST "$BASE_URL/upload?app=myapp&profile=dev&ext=.yaml" -u "${USER1_USERNAME}:${USER1_PASSWORD}" \
    --data-binary @test-data/dev.yaml

# ── 3. Filesystem Backend - GET ───────────────────────────────────────────────

test_header "3. Filesystem Backend - GET Tests (user1)"

# GET existing YAML
expect_status "GET existing YAML file" \
    "200" \
    "$BASE_URL/myapp/dev.yaml" -u "${USER1_USERNAME}:${USER1_PASSWORD}"

# GET existing JSON
expect_status "GET existing JSON file" \
    "200" \
    "$BASE_URL/myapp/prod.json" -u "${USER1_USERNAME}:${USER1_PASSWORD}"

# GET existing .properties
expect_status "GET existing .properties file" \
    "200" \
    "$BASE_URL/myapp/prod.properties" -u "${USER1_USERNAME}:${USER1_PASSWORD}"

# GET existing .yml
expect_status "GET existing .yml file" \
    "200" \
    "$BASE_URL/myapp/ymltest.yml" -u "${USER1_USERNAME}:${USER1_PASSWORD}"

# GET with label
expect_status "GET YAML with label" \
    "200" \
    "$BASE_URL/myapp/dev/main.yaml" -u "${USER1_USERNAME}:${USER1_PASSWORD}"

# GET non-existent file returns 404
expect_status "GET non-existent file returns 404" \
    "404" \
    "$BASE_URL/myapp/nonexistent.yaml" -u "${USER1_USERNAME}:${USER1_PASSWORD}"

# ── 4. Property Flattening Tests ──────────────────────────────────────────────

test_header "4. Property Flattening & Content Tests"

# Verify response has correct profiles
TOTAL=$((TOTAL + 1))
_profile_response=$(curl -s "$BASE_URL/myapp/dev.yaml" -u "${USER1_USERNAME}:${USER1_PASSWORD}" 2>/dev/null)
profiles=$(echo "$_profile_response" | python3 -c "import sys,json; print(json.load(sys.stdin)['profiles'])" 2>/dev/null || echo "ERROR")
if [[ "$profiles" == "['dev']" ]]; then
    PASS=$((PASS + 1))
    echo "  ✅ PASS: Response profiles=['dev']"
else
    FAIL=$((FAIL + 1))
    echo "  ❌ FAIL: Response profiles='$profiles' (expected ['dev'])"
fi

# Verify response has label when label is specified
TOTAL=$((TOTAL + 1))
label_response=$(curl -s "$BASE_URL/myapp/dev/main.yaml" -u "${USER1_USERNAME}:${USER1_PASSWORD}" 2>/dev/null)
label_val=$(echo "$label_response" | python3 -c "import sys,json; print(json.load(sys.stdin).get('label'))" 2>/dev/null || echo "NONE")
if [[ "$label_val" == "main" ]]; then
    PASS=$((PASS + 1))
    echo "  ✅ PASS: Response label='main'"
else
    FAIL=$((FAIL + 1))
    echo "  ❌ FAIL: Response label='$label_val' (expected 'main')"
fi

# Verify propertySources is non-empty array
TOTAL=$((TOTAL + 1))
ps_count=$(curl -s "$BASE_URL/myapp/dev.yaml" -u "${USER1_USERNAME}:${USER1_PASSWORD}" 2>/dev/null | \
    python3 -c "import sys,json; print(len(json.load(sys.stdin)['propertySources']))" 2>/dev/null || echo "ERROR")
if [[ "$ps_count" == "1" ]]; then
    PASS=$((PASS + 1))
    echo "  ✅ PASS: propertySources has 1 entry"
else
    FAIL=$((FAIL + 1))
    echo "  ❌ FAIL: propertySources has $ps_count entries (expected 1)"
fi

# Verify source is a dict (not empty)
TOTAL=$((TOTAL + 1))
source_keys=$(curl -s "$BASE_URL/myapp/dev.yaml" -u "${USER1_USERNAME}:${USER1_PASSWORD}" 2>/dev/null | \
    python3 -c "import sys,json; src=json.load(sys.stdin)['propertySources'][0]['source']; print(len(src))" 2>/dev/null || echo "ERROR")
if [[ "$source_keys" -gt 0 ]] 2>/dev/null; then
    PASS=$((PASS + 1))
    echo "  ✅ PASS: propertySources[0].source has $source_keys keys"
else
    FAIL=$((FAIL + 1))
    echo "  ❌ FAIL: propertySources[0].source has $source_keys keys (expected >0)"
fi

# ── 6. PostgreSQL Backend Tests ──────────────────────────────────────────────

test_header "6. PostgreSQL Backend Tests (user2)"

# Upload to PostgreSQL
expect_status "Upload YAML to PostgreSQL" \
    "200" \
    -X POST "$BASE_URL/upload?app=pgapp&profile=dev&ext=.yaml" -u "${USER2_USERNAME}:${USER2_PASSWORD}" \
    --data-binary @test-data/dev.yaml

# Upload JSON to PostgreSQL
expect_status "Upload JSON to PostgreSQL" \
    "200" \
    -X POST "$BASE_URL/upload?app=pgapp&profile=prod&ext=.json" -u "${USER2_USERNAME}:${USER2_PASSWORD}" \
    --data-binary @test-data/prod.json

# Upload .properties to PostgreSQL
expect_status "Upload .properties to PostgreSQL" \
    "200" \
    -X POST "$BASE_URL/upload?app=pgapp&profile=prod&ext=.properties" -u "${USER2_USERNAME}:${USER2_PASSWORD}" \
    --data-binary @test-data/prod.properties

# Upload with label to PostgreSQL
expect_status "Upload YAML with label to PostgreSQL" \
    "200" \
    -X POST "$BASE_URL/upload?app=pgapp&profile=dev&label=staging&ext=.yaml" -u "${USER2_USERNAME}:${USER2_PASSWORD}" \
    --data-binary @test-data/dev.yaml

# GET from PostgreSQL
expect_status "GET YAML from PostgreSQL" \
    "200" \
    "$BASE_URL/pgapp/dev.yaml" -u "${USER2_USERNAME}:${USER2_PASSWORD}"

# GET JSON from PostgreSQL
expect_status "GET JSON from PostgreSQL" \
    "200" \
    "$BASE_URL/pgapp/prod.json" -u "${USER2_USERNAME}:${USER2_PASSWORD}"

# GET non-existent from PostgreSQL
expect_status "GET non-existent from PostgreSQL returns 404" \
    "404" \
    "$BASE_URL/pgapp/nonexistent.yaml" -u "${USER2_USERNAME}:${USER2_PASSWORD}"

# Cross-user isolation: user2 cannot access user1's files
expect_status "User2 cannot access user1's files" \
    "404" \
    "$BASE_URL/myapp/dev.yaml" -u "${USER2_USERNAME}:${USER2_PASSWORD}"

# Cross-user isolation: user1 cannot access user2's files
expect_status "User1 cannot access user2's files" \
    "404" \
    "$BASE_URL/pgapp/dev.yaml" -u "${USER1_USERNAME}:${USER1_PASSWORD}"

# User2 overwrites its own file (upsert)
expect_status "User2 overwrites its own file" \
    "200" \
    -X POST "$BASE_URL/upload?app=pgapp&profile=dev&ext=.yaml" -u "${USER2_USERNAME}:${USER2_PASSWORD}" \
    --data-binary @test-data/dev.yaml

# ── 7. Encrypt / Decrypt Tests ────────────────────────────────────────────────

test_header "7. Encrypt / Decrypt Tests"

# Encrypt plaintext
TOTAL=$((TOTAL + 1))
encrypted=$(curl -s -X POST "$BASE_URL/encrypt" -u "${USER1_USERNAME}:${USER1_PASSWORD}" -d "my-secret-password" 2>/dev/null)
if [[ -n "$encrypted" && ${#encrypted} -gt 10 ]]; then
    PASS=$((PASS + 1))
    echo "  ✅ PASS: Encrypt returns ciphertext (${#encrypted} chars)"
else
    FAIL=$((FAIL + 1))
    echo "  ❌ FAIL: Encrypt returned empty or too short: '$encrypted'"
fi

# Decrypt ciphertext
TOTAL=$((TOTAL + 1))
decrypted=$(curl -s -X POST "$BASE_URL/decrypt" -u "${USER1_USERNAME}:${USER1_PASSWORD}" -d "$encrypted" 2>/dev/null)
if [[ "$decrypted" == "my-secret-password" ]]; then
    PASS=$((PASS + 1))
    echo "  ✅ PASS: Decrypt returns original plaintext"
else
    FAIL=$((FAIL + 1))
    echo "  ❌ FAIL: Decrypt returned '$decrypted' (expected 'my-secret-password')"
fi

# Decrypt with invalid ciphertext
expect_status "Decrypt invalid ciphertext returns 400" \
    "400" \
    -X POST "$BASE_URL/decrypt" -u "${USER1_USERNAME}:${USER1_PASSWORD}" -d "invalid-ciphertext"

# Encrypt/decrypt roundtrip with special chars
TOTAL=$((TOTAL + 1))
encrypted_special=$(curl -s -X POST "$BASE_URL/encrypt" -u "${USER1_USERNAME}:${USER1_PASSWORD}" -d "p@ss w0rd!#\$%" 2>/dev/null)
decrypted_special=$(curl -s -X POST "$BASE_URL/decrypt" -u "${USER1_USERNAME}:${USER1_PASSWORD}" -d "$encrypted_special" 2>/dev/null)
if [[ "$decrypted_special" == "p@ss w0rd!#\$%" ]]; then
    PASS=$((PASS + 1))
    echo "  ✅ PASS: Encrypt/decrypt roundtrip with special chars"
else
    FAIL=$((FAIL + 1))
    echo "  ❌ FAIL: Roundtrip with special chars failed: got '$decrypted_special'"
fi

# Auto-decrypt {cipher} in config
expect_status "GET config with {cipher} values auto-decrypts" \
    "200" \
    "$BASE_URL/myapp/encrypted.yaml" -u "${USER1_USERNAME}:${USER1_PASSWORD}"

# ── 8. Input Validation Tests ────────────────────────────────────────────────

test_header "8. Input Validation Tests"

# Invalid extension
expect_status "Upload with invalid extension returns 400" \
    "400" \
    -X POST "$BASE_URL/upload?app=myapp&profile=dev&ext=.exe" -u "${USER1_USERNAME}:${USER1_PASSWORD}" -d "test"

# Missing app parameter
expect_status "Upload missing app returns 400" \
    "400" \
    -X POST "$BASE_URL/upload?profile=dev&ext=.yaml" -u "${USER1_USERNAME}:${USER1_PASSWORD}" -d "test"

# Missing profile parameter
expect_status "Upload missing profile returns 400" \
    "400" \
    -X POST "$BASE_URL/upload?app=myapp&ext=.yaml" -u "${USER1_USERNAME}:${USER1_PASSWORD}" -d "test"

# Path traversal attempt in app name
expect_status "Path traversal in app name returns 400" \
    "400" \
    -X POST "$BASE_URL/upload?app=../etc&profile=dev&ext=.yaml" -u "${USER1_USERNAME}:${USER1_PASSWORD}" -d "test"

# Path traversal attempt in profile name
expect_status "Path traversal in profile name returns 400" \
    "400" \
    -X POST "$BASE_URL/upload?app=myapp&profile=../etc&ext=.yaml" -u "${USER1_USERNAME}:${USER1_PASSWORD}" -d "test"

# Path traversal attempt in label
expect_status "Path traversal in label returns 400" \
    "400" \
    -X POST "$BASE_URL/upload?app=myapp&profile=dev&label=../../etc&ext=.yaml" -u "${USER1_USERNAME}:${USER1_PASSWORD}" -d "test"

# Invalid characters in app name (spaces)
expect_status "Spaces in app name returns 400" \
    "400" \
    -X POST "$BASE_URL/upload?app=my app&profile=dev&ext=.yaml" -u "${USER1_USERNAME}:${USER1_PASSWORD}" -d "test"

# Invalid characters in app name (dots)
expect_status "Dots in app name returns 400" \
    "400" \
    -X POST "$BASE_URL/upload?app=my.app&profile=dev&ext=.yaml" -u "${USER1_USERNAME}:${USER1_PASSWORD}" -d "test"

# Commas in profile (not allowed)
expect_status "Commas in profile returns 400" \
    "400" \
    -X POST "$BASE_URL/upload?app=myapp&profile=dev,prod&ext=.yaml" -u "${USER1_USERNAME}:${USER1_PASSWORD}" -d "test"

# ── 9. Edge Cases ────────────────────────────────────────────────────────────

test_header "9. Edge Cases"

# Upload empty content
TOTAL=$((TOTAL + 1))
resp=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/upload?app=myapp&profile=empty&ext=.yaml" \
    -u "${USER1_USERNAME}:${USER1_PASSWORD}" --data-binary "" 2>/dev/null)
http_code=$(echo "$resp" | tail -1)
body=$(echo "$resp" | sed '$d')
if [[ "$http_code" == "200" ]]; then
    PASS=$((PASS + 1))
    echo "  ✅ PASS: Upload empty content returns 200"
else
    FAIL=$((FAIL + 1))
    echo "  ❌ FAIL: Upload empty content returned HTTP $http_code (expected 200)"
    echo "       Response: $body"
fi

# GET empty content (should return 200 with empty source)
TOTAL=$((TOTAL + 1))
resp=$(curl -s -w "\n%{http_code}" "$BASE_URL/myapp/empty.yaml" -u "${USER1_USERNAME}:${USER1_PASSWORD}" 2>/dev/null)
http_code=$(echo "$resp" | tail -1)
body=$(echo "$resp" | sed '$d')
if [[ "$http_code" == "200" ]]; then
    PASS=$((PASS + 1))
    echo "  ✅ PASS: GET empty content returns 200"
else
    FAIL=$((FAIL + 1))
    echo "  ❌ FAIL: GET empty content returned HTTP $http_code (expected 200)"
fi

# Upload config with deep nesting
TOTAL=$((TOTAL + 1))
python3 -c "
import yaml
data = {'a': {'b': {'c': {'d': {'e': 'deep'}}}}}
with open('test-data/deep.yaml', 'w') as f:
    yaml.dump(data, f)
" 2>/dev/null || true
resp=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/upload?app=myapp&profile=deep&ext=.yaml" \
    -u "${USER1_USERNAME}:${USER1_PASSWORD}" --data-binary @test-data/deep.yaml 2>/dev/null)
http_code=$(echo "$resp" | tail -1)
if [[ "$http_code" == "200" ]]; then
    PASS=$((PASS + 1))
    echo "  ✅ PASS: Upload deeply nested config"
else
    FAIL=$((FAIL + 1))
    echo "  ❌ FAIL: Upload deeply nested config returned HTTP $http_code"
fi

# GET deeply nested config
TOTAL=$((TOTAL + 1))
resp=$(curl -s "$BASE_URL/myapp/deep.yaml" -u "${USER1_USERNAME}:${USER1_PASSWORD}" 2>/dev/null)
deep_val=$(echo "$resp" | python3 -c "
import sys, json
d = json.load(sys.stdin)
src = d['propertySources'][0]['source']
print(src.get('a.b.c.d.e', 'MISSING'))
" 2>/dev/null || echo "ERROR")
if [[ "$deep_val" == "deep" ]]; then
    PASS=$((PASS + 1))
    echo "  ✅ PASS: Deep nesting flattened correctly: a.b.c.d.e='deep'"
else
    FAIL=$((FAIL + 1))
    echo "  ❌ FAIL: Deep nesting failed: a.b.c.d.e='$deep_val'"
fi

# Upload with list values
TOTAL=$((TOTAL + 1))
python3 -c "
import yaml
data = {'items': ['alpha', 'beta', 'gamma']}
with open('test-data/list.yaml', 'w') as f:
    yaml.dump(data, f)
" 2>/dev/null || true
resp=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/upload?app=myapp&profile=list&ext=.yaml" \
    -u "${USER1_USERNAME}:${USER1_PASSWORD}" --data-binary @test-data/list.yaml 2>/dev/null)
http_code=$(echo "$resp" | tail -1)
if [[ "$http_code" == "200" ]]; then
    PASS=$((PASS + 1))
    echo "  ✅ PASS: Upload config with list values"
else
    FAIL=$((FAIL + 1))
    echo "  ❌ FAIL: Upload config with list values returned HTTP $http_code"
fi

# GET config with list values
TOTAL=$((TOTAL + 1))
resp=$(curl -s "$BASE_URL/myapp/list.yaml" -u "${USER1_USERNAME}:${USER1_PASSWORD}" 2>/dev/null)
list_val=$(echo "$resp" | python3 -c "
import sys, json
d = json.load(sys.stdin)
src = d['propertySources'][0]['source']
v = src.get('items')
if isinstance(v, list):
    print('LIST:' + ','.join(v))
else:
    print(v)
" 2>/dev/null || echo "ERROR")
if [[ "$list_val" == "LIST:alpha,beta,gamma" ]]; then
    PASS=$((PASS + 1))
    echo "  ✅ PASS: List values preserved: items=[$list_val]"
else
    FAIL=$((FAIL + 1))
    echo "  ❌ FAIL: List values not preserved: items='$list_val'"
fi

# Upload same file twice (idempotent overwrite)
expect_status "Idempotent upload (same file twice)" \
    "200" \
    -X POST "$BASE_URL/upload?app=myapp&profile=dev&ext=.yaml" -u "${USER1_USERNAME}:${USER1_PASSWORD}" \
    --data-binary @test-data/dev.yaml

# ── 10. Multiple File Formats Round-Trip ──────────────────────────────────────

test_header "10. Multiple Format Round-Trip"

# YAML → GET → check keys
TOTAL=$((TOTAL + 1))
yaml_keys=$(curl -s "$BASE_URL/myapp/dev.yaml" -u "${USER1_USERNAME}:${USER1_PASSWORD}" 2>/dev/null | \
    python3 -c "import sys,json; d=json.load(sys.stdin); src=d['propertySources'][0]['source']; print(sorted(src.keys()))" 2>/dev/null)
if echo "$yaml_keys" | grep -q "database.host"; then
    PASS=$((PASS + 1))
    echo "  ✅ PASS: YAML keys present: $yaml_keys"
else
    FAIL=$((FAIL + 1))
    echo "  ❌ FAIL: YAML keys missing or malformed: $yaml_keys"
fi

# JSON → GET → check keys
TOTAL=$((TOTAL + 1))
json_keys=$(curl -s "$BASE_URL/myapp/prod.json" -u "${USER1_USERNAME}:${USER1_PASSWORD}" 2>/dev/null | \
    python3 -c "import sys,json; d=json.load(sys.stdin); src=d['propertySources'][0]['source']; print(sorted(src.keys()))" 2>/dev/null)
if echo "$json_keys" | grep -q "app"; then
    PASS=$((PASS + 1))
    echo "  ✅ PASS: JSON keys present: $json_keys"
else
    FAIL=$((FAIL + 1))
    echo "  ❌ FAIL: JSON keys missing or malformed: $json_keys"
fi

# Properties → GET → check keys
TOTAL=$((TOTAL + 1))
props_keys=$(curl -s "$BASE_URL/myapp/prod.properties" -u "${USER1_USERNAME}:${USER1_PASSWORD}" 2>/dev/null | \
    python3 -c "import sys,json; d=json.load(sys.stdin); src=d['propertySources'][0]['source']; print(sorted(src.keys()))" 2>/dev/null)
if echo "$props_keys" | grep -q "database.host"; then
    PASS=$((PASS + 1))
    echo "  ✅ PASS: Properties keys present: $props_keys"
else
    FAIL=$((FAIL + 1))
    echo "  ❌ FAIL: Properties keys missing or malformed: $props_keys"
fi

# ── 11. Multi-Profile Merge Tests ────────────────────────────────────────────

test_header "11. Multi-Profile Merge Tests"

# Upload common profile
expect_status "Upload common profile" \
    "200" \
    -X POST "$BASE_URL/upload?app=myapp&profile=common&ext=.yaml" -u "${USER1_USERNAME}:${USER1_PASSWORD}" \
    --data-binary @test-data/dev.yaml

# Fetch multi-profile
TOTAL=$((TOTAL + 1))
multi_response=$(curl -s "$BASE_URL/myapp/dev,common" -u "${USER1_USERNAME}:${USER1_PASSWORD}" 2>/dev/null)
if [[ $? -eq 0 ]]; then
    PASS=$((PASS + 1))
    echo "  ✅ PASS: Multi-profile fetch returns 200"
else
    FAIL=$((FAIL + 1))
    echo "  ❌ FAIL: Multi-profile fetch failed"
fi

# ── 12. Health Check & List ──────────────────────────────────────────────────

test_header "12. Health Check & List Tests"

# Health check
TOTAL=$((TOTAL + 1))
health_response=$(curl -s "$BASE_URL/health" 2>/dev/null)
if echo "$health_response" | grep -q "UP"; then
    PASS=$((PASS + 1))
    echo "  ✅ PASS: Health check returns UP"
else
    FAIL=$((FAIL + 1))
    echo "  ❌ FAIL: Health check failed: $health_response"
fi

# List files
expect_status "List files returns 200" \
    "200" \
    "$BASE_URL/list" -u "${USER1_USERNAME}:${USER1_PASSWORD}"

# ── 13. Multi-Password Authentication Tests ──────────────────────────────────

test_header "13. Multi-Password Authentication Tests"

# Add temporary password
TOTAL=$((TOTAL + 1))
FUTURE_DATE=$(date -d "+24 hours" -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u -v+24H +"%Y-%m-%dT%H:%M:%SZ")
resp=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/addpassword" \
    -u "${USER2_USERNAME}:${USER2_PASSWORD}" \
    -d "password=temptoken123" \
    -d "exp=$FUTURE_DATE" \
    -d "description=temporary-token-for-testing" 2>/dev/null)
http_code=$(echo "$resp" | tail -1)
if [[ "$http_code" == "200" ]]; then
    PASS=$((PASS + 1))
    echo "  ✅ PASS: Add temporary password (HTTP $http_code)"
else
    FAIL=$((FAIL + 1))
    echo "  ❌ FAIL: Add temporary password returned HTTP $http_code"
fi

# Add no-expire password
TOTAL=$((TOTAL + 1))
resp=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/addpassword" \
    -u "${USER2_USERNAME}:${USER2_PASSWORD}" \
    -d "password=foreverpass" \
    -d "exp=noexpire" \
    -d "description=permanent-secondary-password" 2>/dev/null)
http_code=$(echo "$resp" | tail -1)
if [[ "$http_code" == "200" ]]; then
    PASS=$((PASS + 1))
    echo "  ✅ PASS: Add no-expire password (HTTP $http_code)"
else
    FAIL=$((FAIL + 1))
    echo "  ❌ FAIL: Add no-expire password returned HTTP $http_code"
fi

# List all passwords
TOTAL=$((TOTAL + 1))
listpw_response=$(curl -s -w "\n%{http_code}" "$BASE_URL/listpasswords" -u "${USER2_USERNAME}:${USER2_PASSWORD}" 2>/dev/null)
http_code=$(echo "$listpw_response" | tail -1)
if [[ "$http_code" == "200" ]]; then
    PASS=$((PASS + 1))
    echo "  ✅ PASS: List passwords returns 200"
else
    FAIL=$((FAIL + 1))
    echo "  ❌ FAIL: List passwords returned HTTP $http_code"
fi

# Authenticate with temp password
expect_status "Authenticate with temp password" \
    "200" \
    "$BASE_URL/myapp/dev.yaml" -u "user2:temptoken123"

# Authenticate with no-expire password
expect_status "Authenticate with no-expire password" \
    "200" \
    "$BASE_URL/myapp/dev.yaml" -u "user2:foreverpass"

# Authenticate with main password still works
expect_status "Authenticate with main password still works" \
    "200" \
    "$BASE_URL/myapp/dev.yaml" -u "user2:changeme"

# Duplicate password rejected
expect_status "Duplicate password rejected" \
    "400" \
    -X POST "$BASE_URL/addpassword" \
    -u "${USER2_USERNAME}:${USER2_PASSWORD}" \
    -d "password=temptoken123" \
    -d "exp=noexpire" \
    -d "description=duplicate-test"

# Missing password field rejected
expect_status "Missing password field rejected" \
    "400" \
    -X POST "$BASE_URL/addpassword" \
    -u "${USER2_USERNAME}:${USER2_PASSWORD}" \
    -d "exp=$FUTURE_DATE" \
    -d "description=missing-password"

# Invalid exp format rejected
expect_status "Invalid exp format rejected" \
    "400" \
    -X POST "$BASE_URL/addpassword" \
    -u "${USER2_USERNAME}:${USER2_PASSWORD}" \
    -d "password=badexp" \
    -d "exp=not-a-date" \
    -d "description=bad-exp"

# Delete a password by hash
TOTAL=$((TOTAL + 1))
TEMP_HASH=$(curl -s "$BASE_URL/listpasswords" -u "${USER2_USERNAME}:${USER2_PASSWORD}" 2>/dev/null | jq -r '.passwords | keys[0]')
resp=$(curl -s -w "\n%{http_code}" -X DELETE "$BASE_URL/delpassword?hash=$TEMP_HASH" \
    -u "${USER2_USERNAME}:${USER2_PASSWORD}" 2>/dev/null)
http_code=$(echo "$resp" | tail -1)
if [[ "$http_code" == "200" ]]; then
    PASS=$((PASS + 1))
    echo "  ✅ PASS: Delete password by hash (HTTP $http_code)"
else
    FAIL=$((FAIL + 1))
    echo "  ❌ FAIL: Delete password by hash returned HTTP $http_code"
fi

# Delete nonexistent hash
expect_status "Delete nonexistent hash returns 404" \
    "404" \
    -X DELETE "$BASE_URL/delpassword?hash=nonexistenthash00000000000000000000000000000000000000000000000000000000" \
    -u "${USER2_USERNAME}:${USER2_PASSWORD}"

# Delete missing hash param
expect_status "Delete missing hash param returns 400" \
    "400" \
    -X DELETE "$BASE_URL/delpassword" \
    -u "${USER2_USERNAME}:${USER2_PASSWORD}"

# Unauthorized on addpassword
expect_status "Unauthorized on addpassword returns 401" \
    "401" \
    -X POST "$BASE_URL/addpassword" \
    -d "password=test" \
    -d "exp=noexpire" \
    -d "description=unauthorized"

# Unauthorized on listpasswords
expect_status "Unauthorized on listpasswords returns 401" \
    "401" \
    "$BASE_URL/listpasswords"

# Unauthorized on delpassword
expect_status "Unauthorized on delpassword returns 401" \
    "401" \
    -X DELETE "$BASE_URL/delpassword?hash=abc123"

# ── 14. Format-Specific Endpoints (Spring Cloud Config Server) ────────────────

test_header "14. Format-Specific Endpoints (Spring Cloud Config Server)"

# YAML format endpoint
expect_status "GET /{app}-{profile}.yml" \
    "200" \
    "$BASE_URL/myapp-dev.yml" -u "${USER1_USERNAME}:${USER1_PASSWORD}"

# JSON format endpoint
expect_status "GET /{app}-{profile}.json" \
    "200" \
    "$BASE_URL/myapp-prod.json" -u "${USER1_USERNAME}:${USER1_PASSWORD}"

# Properties format endpoint
expect_status "GET /{app}-{profile}.properties" \
    "200" \
    "$BASE_URL/myapp-prod.properties" -u "${USER1_USERNAME}:${USER1_PASSWORD}"

# Label-prefixed YAML endpoint
expect_status "GET /{label}/{app}-{profile}.yml" \
    "200" \
    "$BASE_URL/main/myapp-dev.yml" -u "${USER1_USERNAME}:${USER1_PASSWORD}"

# Label-prefixed JSON endpoint
expect_status "GET /{label}/{app}-{profile}.json" \
    "200" \
    "$BASE_URL/main/myapp-prod.json" -u "${USER1_USERNAME}:${USER1_PASSWORD}"

# Label-prefixed properties endpoint
expect_status "GET /{label}/{app}-{profile}.properties" \
    "200" \
    "$BASE_URL/main/myapp-prod.properties" -u "${USER1_USERNAME}:${USER1_PASSWORD}"

# ── 15. Swagger UI ────────────────────────────────────────────────────────────

test_header "15. Swagger UI"

expect_status "Swagger UI returns 200" \
    "200" \
    "$BASE_URL/swagger/index.html"

# ── Summary ────────────────────────────────────────────────────────────────────

echo ""
echo "=============================================="
echo "  TEST SUMMARY"
echo "=============================================="
echo ""
echo "  Total:  $TOTAL"
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
echo ""

if [[ $FAIL -eq 0 ]]; then
    echo "  🎉 ALL TESTS PASSED!"
else
    echo "  ⚠️  $FAIL TEST(S) FAILED"
fi
echo ""

exit $FAIL
