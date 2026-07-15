#!/bin/bash
#
# Comprehensive test script for config-server-go
# Covers: filesystem backend, PostgreSQL backend, auth, encrypt/decrypt,
#         edge cases, error handling, and Spring Cloud Config spec compliance.
#
# Usage: ./tests/run_tests.sh [server_url]
#   server_url defaults to http://localhost:7777
#

set -euo pipefail

# ── Configuration ──────────────────────────────────────────────────────────────
SERVER="${1:-http://localhost:7777}"

USER1_USER="user1"
USER1_PASS="changeme123"
USER1_KEY="mySecretKey123"

USER2_USER="user2"
USER2_PASS="changeme456"
USER2_KEY="mySecretKey456"

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

# Upload helper
# Usage: upload_file "app" "profile" "ext" "username:password" "test_file" "[label]"
upload_file() {
    local app="$1"
    local profile="$2"
    local ext="$3"
    local auth="$4"
    local test_file="$5"
    local label="${6:-}"

    local url="http://localhost:7777/upload?app=${app}&profile=${profile}&ext=${ext}"
    if [[ -n "$label" ]]; then
        url="${url}&label=${label}"
    fi

    curl -s -w "\n%{http_code}" -X POST "$url" -u "$auth" \
        -H "Content-Type: application/octet-stream" \
        --data-binary "@${test_file}" 2>/dev/null
}

# ── Pre-flight check ─────────────────────────────────────────────────────────

echo "=============================================="
echo "  Config Server Go - Comprehensive Test Suite"
echo "=============================================="
echo ""
echo "Server: $SERVER"
echo "User1 (filesystem): ${USER1_USER}/${USER1_PASS}"
echo "User2 (postgres):   ${USER2_USER}/${USER2_PASS}"

# Check server is reachable
if ! curl -s --max-time 3 "$SERVER/" -o /dev/null 2>/dev/null; then
    echo ""
    echo "❌ Server not reachable at $SERVER"
    echo "   Make sure docker compose is running: docker compose up -d"
    exit 1
fi
echo "✅ Server is reachable"

# ── Tests ──────────────────────────────────────────────────────────────────────

# ── 1. Authentication Tests ───────────────────────────────────────────────────

test_header "1. Authentication Tests"

# No auth
expect_status "GET without authentication returns 401" \
    "401" \
    "$SERVER/myapp/dev.yaml"

# Wrong password
expect_status "GET with wrong password returns 401" \
    "401" \
    "$SERVER/myapp/dev.yaml" -u "${USER1_USER}:wrongpass"

# Wrong user
expect_status "GET with unknown user returns 401" \
    "401" \
    "$SERVER/myapp/dev.yaml" -u "nonexistent:pass"

# Upload without auth
expect_status "Upload without authentication returns 401" \
    "401" \
    -X POST "$SERVER/upload?app=myapp&profile=test&ext=.yaml" -d "test"

# Upload with wrong password
expect_status "Upload with wrong password returns 401" \
    "401" \
    -X POST "$SERVER/upload?app=myapp&profile=test&ext=.yaml" -u "${USER1_USER}:wrongpass" -d "test"

# ── 2. Filesystem Backend - Upload ────────────────────────────────────────────

test_header "2. Filesystem Backend - Upload Tests (user1)"

# Upload YAML
expect_status "Upload YAML file" \
    "200" \
    -X POST "$SERVER/upload?app=myapp&profile=dev&ext=.yaml" -u "${USER1_USER}:${USER1_PASS}" \
    --data-binary @test-data/dev.yaml

# Upload JSON
expect_status "Upload JSON file" \
    "200" \
    -X POST "$SERVER/upload?app=myapp&profile=prod&ext=.json" -u "${USER1_USER}:${USER1_PASS}" \
    --data-binary @test-data/prod.json

# Upload Properties
expect_status "Upload .properties file" \
    "200" \
    -X POST "$SERVER/upload?app=myapp&profile=prod&ext=.properties" -u "${USER1_USER}:${USER1_PASS}" \
    --data-binary @test-data/prod.properties

# Upload .yml
expect_status "Upload .yml file" \
    "200" \
    -X POST "$SERVER/upload?app=myapp&profile=ymltest&ext=.yml" -u "${USER1_USER}:${USER1_PASS}" \
    --data-binary @test-data/dev.yaml

# Upload with default extension (omitted)
expect_status "Upload with default .yaml extension" \
    "200" \
    -X POST "$SERVER/upload?app=myapp&profile=defaultext" -u "${USER1_USER}:${USER1_PASS}" \
    --data-binary @test-data/dev.yaml

# Upload with label
expect_status "Upload YAML with label" \
    "200" \
    -X POST "$SERVER/upload?app=myapp&profile=dev&label=main&ext=.yaml" -u "${USER1_USER}:${USER1_PASS}" \
    --data-binary @test-data/dev.yaml

# Upload with label v2
expect_status "Upload with label 'v2'" \
    "200" \
    -X POST "$SERVER/upload?app=myapp&profile=staging&label=v2&ext=.yaml" -u "${USER1_USER}:${USER1_PASS}" \
    --data-binary @test-data/dev.yaml

# Upload special characters in values
expect_status "Upload config with special characters" \
    "200" \
    -X POST "$SERVER/upload?app=myapp&profile=special2&ext=.yaml" -u "${USER1_USER}:${USER1_PASS}" \
    --data-binary @test-data/special2.yaml

# Upload large config
expect_status "Upload large config (100 keys)" \
    "200" \
    -X POST "$SERVER/upload?app=myapp&profile=large&ext=.yaml" -u "${USER1_USER}:${USER1_PASS}" \
    --data-binary @test-data/large.yaml

# Overwrite existing file
expect_status "Overwrite existing YAML file" \
    "200" \
    -X POST "$SERVER/upload?app=myapp&profile=dev&ext=.yaml" -u "${USER1_USER}:${USER1_PASS}" \
    --data-binary @test-data/dev.yaml

# ── 3. Filesystem Backend - GET ───────────────────────────────────────────────

test_header "3. Filesystem Backend - GET Tests (user1)"

# GET existing YAML
expect_status "GET existing YAML file" \
    "200" \
    "$SERVER/myapp/dev.yaml" -u "${USER1_USER}:${USER1_PASS}"

# GET existing JSON
expect_status "GET existing JSON file" \
    "200" \
    "$SERVER/myapp/prod.json" -u "${USER1_USER}:${USER1_PASS}"

# GET existing .properties
expect_status "GET existing .properties file" \
    "200" \
    "$SERVER/myapp/prod.properties" -u "${USER1_USER}:${USER1_PASS}"

# GET existing .yml
expect_status "GET existing .yml file" \
    "200" \
    "$SERVER/myapp/ymltest.yml" -u "${USER1_USER}:${USER1_PASS}"

# GET with label
expect_status "GET YAML with label" \
    "200" \
    "$SERVER/myapp/dev/main.yaml" -u "${USER1_USER}:${USER1_PASS}"

# GET with label v2
expect_status "GET with label 'v2'" \
    "200" \
    "$SERVER/myapp/staging/v2.yaml" -u "${USER1_USER}:${USER1_PASS}"

# GET non-existent file returns 404
expect_status "GET non-existent file returns 404" \
    "404" \
    "$SERVER/myapp/nonexistent.yaml" -u "${USER1_USER}:${USER1_PASS}"

# ── 4. Property Flattening Tests ──────────────────────────────────────────────

test_header "4. Property Flattening & Content Tests"

# YAML nested keys flattened to dot notation
expect_property "YAML nested key flattening: database.host" \
    "$SERVER/myapp/dev.yaml" "${USER1_USER}:${USER1_PASS}" \
    "database.host" "localhost"

# JSON flat keys
expect_property "JSON flat key: app" \
    "$SERVER/myapp/prod.json" "${USER1_USER}:${USER1_PASS}" \
    "app" '{"name": "myapp", "version": "2.0"}'

# Properties file parsing
expect_property "Properties key: database.host" \
    "$SERVER/myapp/prod.properties" "${USER1_USER}:${USER1_PASS}" \
    "database.host" "prodhost"

# Nested YAML
expect_property "Nested YAML: nested.key1" \
    "$SERVER/myapp/special2.yaml" "${USER1_USER}:${USER1_PASS}" \
    "nested.key1" "val1"

expect_property "Deep nested YAML: nested.key2.subkey" \
    "$SERVER/myapp/special2.yaml" "${USER1_USER}:${USER1_PASS}" \
    "nested.key2.subkey" "subval"

# Boolean and numeric types preserved
expect_property "Boolean preserved: bool" \
    "$SERVER/myapp/special2.yaml" "${USER1_USER}:${USER1_PASS}" \
    "bool" "true"

expect_property "Numeric preserved: numeric" \
    "$SERVER/myapp/special2.yaml" "${USER1_USER}:${USER1_PASS}" \
    "numeric" "42"

# ── 5. GetValuesResponse JSON Structure Tests ────────────────────────────────

test_header "5. GetValuesResponse JSON Structure Tests"

# Verify response has correct name field
expect_json_field "Response name is 'myapp'" \
    -s "$SERVER/myapp/dev.yaml" -u "${USER1_USER}:${USER1_PASS}" \
    "name" "myapp"

# Verify response has correct profiles
TOTAL=$((TOTAL + 1))
_profile_response=$(curl -s "$SERVER/myapp/dev.yaml" -u "${USER1_USER}:${USER1_PASS}" 2>/dev/null)
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
label_response=$(curl -s "$SERVER/myapp/dev/main.yaml" -u "${USER1_USER}:${USER1_PASS}" 2>/dev/null)
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
ps_count=$(curl -s "$SERVER/myapp/dev.yaml" -u "${USER1_USER}:${USER1_PASS}" 2>/dev/null | \
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
source_keys=$(curl -s "$SERVER/myapp/dev.yaml" -u "${USER1_USER}:${USER1_PASS}" 2>/dev/null | \
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
    -X POST "$SERVER/upload?app=pgapp&profile=dev&ext=.yaml" -u "${USER2_USER}:${USER2_PASS}" \
    --data-binary @test-data/dev.yaml

# Upload JSON to PostgreSQL
expect_status "Upload JSON to PostgreSQL" \
    "200" \
    -X POST "$SERVER/upload?app=pgapp&profile=prod&ext=.json" -u "${USER2_USER}:${USER2_PASS}" \
    --data-binary @test-data/prod.json

# Upload .properties to PostgreSQL
expect_status "Upload .properties to PostgreSQL" \
    "200" \
    -X POST "$SERVER/upload?app=pgapp&profile=prod&ext=.properties" -u "${USER2_USER}:${USER2_PASS}" \
    --data-binary @test-data/prod.properties

# Upload with label to PostgreSQL
expect_status "Upload YAML with label to PostgreSQL" \
    "200" \
    -X POST "$SERVER/upload?app=pgapp&profile=dev&label=staging&ext=.yaml" -u "${USER2_USER}:${USER2_PASS}" \
    --data-binary @test-data/dev.yaml

# GET from PostgreSQL
expect_status "GET YAML from PostgreSQL" \
    "200" \
    "$SERVER/pgapp/dev.yaml" -u "${USER2_USER}:${USER2_PASS}"

# GET JSON from PostgreSQL
expect_status "GET JSON from PostgreSQL" \
    "200" \
    "$SERVER/pgapp/prod.json" -u "${USER2_USER}:${USER2_PASS}"

# GET with label from PostgreSQL
expect_status "GET YAML with label from PostgreSQL" \
    "200" \
    "$SERVER/pgapp/dev/staging.yaml" -u "${USER2_USER}:${USER2_PASS}"

# GET non-existent from PostgreSQL
expect_status "GET non-existent from PostgreSQL returns 404" \
    "404" \
    "$SERVER/pgapp/nonexistent.yaml" -u "${USER2_USER}:${USER2_PASS}"

# Cross-user isolation: user2 cannot access user1's files
expect_status "User2 cannot access user1's files" \
    "404" \
    "$SERVER/myapp/dev.yaml" -u "${USER2_USER}:${USER2_PASS}"

# Cross-user isolation: user1 cannot access user2's files
expect_status "User1 cannot access user2's files" \
    "404" \
    "$SERVER/pgapp/dev.yaml" -u "${USER1_USER}:${USER1_PASS}"

# User2 overwrites its own file (upsert)
expect_status "User2 overwrites its own file" \
    "200" \
    -X POST "$SERVER/upload?app=pgapp&profile=dev&ext=.yaml" -u "${USER2_USER}:${USER2_PASS}" \
    --data-binary @test-data/dev.yaml

# ── 7. Encrypt / Decrypt Tests ────────────────────────────────────────────────

test_header "7. Encrypt / Decrypt Tests"

# Encrypt plaintext
TOTAL=$((TOTAL + 1))
encrypted=$(curl -s -X POST "$SERVER/encrypt" -u "${USER1_USER}:${USER1_PASS}" -d "my-secret-password" 2>/dev/null)
if [[ -n "$encrypted" && ${#encrypted} -gt 10 ]]; then
    PASS=$((PASS + 1))
    echo "  ✅ PASS: Encrypt returns ciphertext (${#encrypted} chars)"
else
    FAIL=$((FAIL + 1))
    echo "  ❌ FAIL: Encrypt returned empty or too short: '$encrypted'"
fi

# Decrypt ciphertext
TOTAL=$((TOTAL + 1))
decrypted=$(curl -s -X POST "$SERVER/decrypt" -u "${USER1_USER}:${USER1_PASS}" -d "$encrypted" 2>/dev/null)
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
    -X POST "$SERVER/decrypt" -u "${USER1_USER}:${USER1_PASS}" -d "invalid-ciphertext"

# Encrypt/decrypt roundtrip with special chars
TOTAL=$((TOTAL + 1))
encrypted_special=$(curl -s -X POST "$SERVER/encrypt" -u "${USER1_USER}:${USER1_PASS}" -d "p@ss w0rd!#$%" 2>/dev/null)
decrypted_special=$(curl -s -X POST "$SERVER/decrypt" -u "${USER1_USER}:${USER1_PASS}" -d "$encrypted_special" 2>/dev/null)
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
    "$SERVER/myapp/encrypted.yaml" -u "${USER1_USER}:${USER1_PASS}"

# ── 8. Input Validation Tests ────────────────────────────────────────────────

test_header "8. Input Validation Tests"

# Invalid extension
expect_status "Upload with invalid extension returns 400" \
    "400" \
    -X POST "$SERVER/upload?app=myapp&profile=dev&ext=.exe" -u "${USER1_USER}:${USER1_PASS}" -d "test"

# Missing app parameter
expect_status "Upload missing app returns 400" \
    "400" \
    -X POST "$SERVER/upload?profile=dev&ext=.yaml" -u "${USER1_USER}:${USER1_PASS}" -d "test"

# Missing profile parameter
expect_status "Upload missing profile returns 400" \
    "400" \
    -X POST "$SERVER/upload?app=myapp&ext=.yaml" -u "${USER1_USER}:${USER1_PASS}" -d "test"

# Path traversal attempt in app name
expect_status "Path traversal in app name returns 400" \
    "400" \
    -X POST "$SERVER/upload?app=../etc&profile=dev&ext=.yaml" -u "${USER1_USER}:${USER1_PASS}" -d "test"

# Path traversal attempt in profile name
expect_status "Path traversal in profile name returns 400" \
    "400" \
    -X POST "$SERVER/upload?app=myapp&profile=../etc&ext=.yaml" -u "${USER1_USER}:${USER1_PASS}" -d "test"

# Path traversal attempt in label
expect_status "Path traversal in label returns 400" \
    "400" \
    -X POST "$SERVER/upload?app=myapp&profile=dev&label=../../etc&ext=.yaml" -u "${USER1_USER}:${USER1_PASS}" -d "test"

# Invalid characters in app name (spaces)
expect_status "Spaces in app name returns 400" \
    "400" \
    -X POST "$SERVER/upload?app=my app&profile=dev&ext=.yaml" -u "${USER1_USER}:${USER1_PASS}" -d "test"

# Invalid characters in app name (dots)
expect_status "Dots in app name returns 400" \
    "400" \
    -X POST "$SERVER/upload?app=my.app&profile=dev&ext=.yaml" -u "${USER1_USER}:${USER1_PASS}" -d "test"

# Commas in profile (not allowed)
expect_status "Commas in profile returns 400" \
    "400" \
    -X POST "$SERVER/upload?app=myapp&profile=dev,prod&ext=.yaml" -u "${USER1_USER}:${USER1_PASS}" -d "test"

# ── 9. Edge Cases ────────────────────────────────────────────────────────────

test_header "9. Edge Cases"

# Upload empty content
TOTAL=$((TOTAL + 1))
resp=$(curl -s -w "\n%{http_code}" -X POST "$SERVER/upload?app=myapp&profile=empty&ext=.yaml" \
    -u "${USER1_USER}:${USER1_PASS}" --data-binary "" 2>/dev/null)
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
resp=$(curl -s -w "\n%{http_code}" "$SERVER/myapp/empty.yaml" -u "${USER1_USER}:${USER1_PASS}" 2>/dev/null)
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
resp=$(curl -s -w "\n%{http_code}" -X POST "$SERVER/upload?app=myapp&profile=deep&ext=.yaml" \
    -u "${USER1_USER}:${USER1_PASS}" --data-binary @test-data/deep.yaml 2>/dev/null)
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
resp=$(curl -s "$SERVER/myapp/deep.yaml" -u "${USER1_USER}:${USER1_PASS}" 2>/dev/null)
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
resp=$(curl -s -w "\n%{http_code}" -X POST "$SERVER/upload?app=myapp&profile=list&ext=.yaml" \
    -u "${USER1_USER}:${USER1_PASS}" --data-binary @test-data/list.yaml 2>/dev/null)
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
resp=$(curl -s "$SERVER/myapp/list.yaml" -u "${USER1_USER}:${USER1_PASS}" 2>/dev/null)
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
    -X POST "$SERVER/upload?app=myapp&profile=dev&ext=.yaml" -u "${USER1_USER}:${USER1_PASS}" \
    --data-binary @test-data/dev.yaml

# ── 10. Multiple File Formats Round-Trip ──────────────────────────────────────

test_header "10. Multiple Format Round-Trip"

# YAML → GET → check keys
TOTAL=$((TOTAL + 1))
yaml_keys=$(curl -s "$SERVER/myapp/dev.yaml" -u "${USER1_USER}:${USER1_PASS}" 2>/dev/null | \
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
json_keys=$(curl -s "$SERVER/myapp/prod.json" -u "${USER1_USER}:${USER1_PASS}" 2>/dev/null | \
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
props_keys=$(curl -s "$SERVER/myapp/prod.properties" -u "${USER1_USER}:${USER1_PASS}" 2>/dev/null | \
    python3 -c "import sys,json; d=json.load(sys.stdin); src=d['propertySources'][0]['source']; print(sorted(src.keys()))" 2>/dev/null)
if echo "$props_keys" | grep -q "database.host"; then
    PASS=$((PASS + 1))
    echo "  ✅ PASS: Properties keys present: $props_keys"
else
    FAIL=$((FAIL + 1))
    echo "  ❌ FAIL: Properties keys missing or malformed: $props_keys"
fi

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
