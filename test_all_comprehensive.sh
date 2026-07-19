#!/bin/bash
# Comprehensive test suite for config-server-go
# Tests all Spring Cloud Config Server features

BASE_URL="${BASE_URL:-http://localhost:7777}"
AUTH="-u ${CONFIG_USER:-user2}:${CONFIG_PASSWORD:-changeme}"

echo "AUTH: '$AUTH' $BASE_URL"
read junk

echo "=========================================="
echo "=== COMPREHENSIVE TEST SUITE: config-server-go ==="
echo "=========================================="
echo ""

# Clean up any existing test data
echo "--- CLEANUP ---"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=test&profile=dev&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=test&profile=common&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=altformat&profile=prod&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=placeholder&profile=default&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=labelapp&profile=dev&label=main&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=cipherapp&profile=default&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=pathapp&profile=prod&ext=.yaml"
echo ""

# TEST 1: Upload single profile
echo "=========================================="
echo "=== TEST 1: Upload single profile ==="
echo "=========================================="
curl -s $AUTH -X POST "$BASE_URL/upload?app=test&profile=dev&ext=.yaml" -H "Content-Type: text/plain" -d "database_url: postgres://localhost/mydb
app_name: test-app
feature_flag: true"
echo ""

# TEST 2: Fetch single profile - JSON format
echo "=========================================="
echo "=== TEST 2: Fetch /test/dev (JSON) ==="
echo "=========================================="
curl -s $AUTH "$BASE_URL/test/dev" | jq .
echo ""

# TEST 3: Fetch single segment format
echo "=========================================="
echo "=== TEST 3: Fetch /test-dev ==="
echo "=========================================="
curl -s $AUTH "$BASE_URL/test-dev" | jq .
echo ""

# TEST 4: Upload second profile for multi-profile merge
echo "=========================================="
echo "=== TEST 4: Upload common profile ==="
echo "=========================================="
curl -s $AUTH -X POST "$BASE_URL/upload?app=test&profile=common&ext=.yaml" -H "Content-Type: text/plain" -d "log_level: info
max_retries: 3
database_url: override-from-common"
echo ""

# TEST 5: Multi-profile merge
echo "=========================================="
echo "=== TEST 5: Multi-profile /test/dev,common ==="
echo "=========================================="
curl -s $AUTH "$BASE_URL/test/dev,common" | jq .
echo ""

# TEST 6: Health check
echo "=========================================="
echo "=== TEST 6: Health check ==="
echo "=========================================="
curl -s "$BASE_URL/health" | jq .
echo ""

# TEST 7: List files
echo "=========================================="
echo "=== TEST 7: List files ==="
echo "=========================================="
curl -s $AUTH "$BASE_URL/list" | jq .
echo ""

# TEST 8: Upload JSON file
echo "=========================================="
echo "=== TEST 8: Upload JSON file ==="
echo "=========================================="
curl -s $AUTH -X POST "$BASE_URL/upload?app=myapp&profile=prod&ext=.json" -H "Content-Type: text/plain" -d '{"server":{"host":"localhost","port":8080}}'
echo ""

# TEST 9: Fetch JSON file
echo "=========================================="
echo "=== TEST 9: Fetch JSON /myapp/prod ==="
echo "=========================================="
curl -s $AUTH "$BASE_URL/myapp/prod" | jq .
echo ""

# TEST 10: Upload properties file
echo "=========================================="
echo "=== TEST 10: Upload properties file ==="
echo "=========================================="
curl -s $AUTH -X POST "$BASE_URL/upload?app=propsapp&profile=default&ext=.properties" -H "Content-Type: text/plain" -d "spring.datasource.url=jdbc:mysql://localhost/test
spring.datasource.username=root"
echo ""

# TEST 11: Fetch properties file
echo "=========================================="
echo "=== TEST 11: Fetch properties /propsapp/default ==="
echo "=========================================="
curl -s $AUTH "$BASE_URL/propsapp/default" | jq .
echo ""

# TEST 12: Upload with label
echo "=========================================="
echo "=== TEST 12: Upload with label ==="
echo "=========================================="
curl -s $AUTH -X POST "$BASE_URL/upload?app=labelapp&profile=dev&label=main&ext=.yaml" -H "Content-Type: text/plain" -d "label_config: enabled"
echo ""

# TEST 13: Fetch with label
echo "=========================================="
echo "=== TEST 13: Fetch with label /labelapp/dev/main ==="
echo "=========================================="
curl -s $AUTH "$BASE_URL/labelapp/dev/main" | jq .
echo ""

# TEST 14: Upload properties file for extension priority test
echo "=========================================="
echo "=== TEST 14: Upload .properties (should win over .yaml) ==="
echo "=========================================="
curl -s $AUTH -X POST "$BASE_URL/upload?app=prioapp&profile=test&ext=.properties" -H "Content-Type: text/plain" -d "source=from-properties
key1=properties-value"
curl -s $AUTH -X POST "$BASE_URL/upload?app=prioapp&profile=test&ext=.yaml" -H "Content-Type: text/plain" -d "source: from-yaml
key2: yaml-value"
echo ""

# TEST 15: Extension priority test (properties should win)
echo "=========================================="
echo "=== TEST 15: Extension priority /prioapp/test ==="
echo "=========================================="
curl -s $AUTH "$BASE_URL/prioapp/test" | jq .
echo ""

# TEST 16: Upload encrypted content
echo "=========================================="
echo "=== TEST 16: Encrypt value ==="
echo "=========================================="
ENCRYPTED=$(curl -s $AUTH -X POST "$BASE_URL/encrypt" -H "Content-Type: text/plain" -d "my-secret-password" | tr -d '\n')
echo "Encrypted: $ENCRYPTED"
echo ""

# Upload file with cipher pattern
curl -s $AUTH -X POST "$BASE_URL/upload?app=cipherapp&profile=default&ext=.yaml" -H "Content-Type: text/plain" -d "password: '$ENCRYPTED'
normal_key: normal_value"
echo ""

# TEST 17: Fetch with cipher decryption
echo "=========================================="
echo "=== TEST 17: Fetch with cipher decryption ==="
echo "=========================================="
curl -s $AUTH "$BASE_URL/cipherapp/default" | jq .
echo ""

# TEST 18: Decrypt test
echo "=========================================="
echo "=== TEST 18: Decrypt value ==="
echo "=========================================="
curl -s $AUTH -X POST "$BASE_URL/decrypt" -H "Content-Type: text/plain" -d "$ENCRYPTED"
echo ""

# TEST 19: 401 - wrong password
echo "=========================================="
echo "=== TEST 19: Wrong password (401) ==="
echo "=========================================="
curl -s -o /dev/null -w "HTTP Status: %{http_code}" -u "user2:wrongpass" "$BASE_URL/test/dev"
echo ""

# TEST 20: 401 - unknown user
echo "=========================================="
echo "=== TEST 20: Unknown user (401) ==="
echo "=========================================="
curl -s -o /dev/null -w "HTTP Status: %{http_code}" -u "unknown:password" "$BASE_URL/test/dev"
echo ""

# TEST 21: 404 - nonexistent config
echo "=========================================="
echo "=== TEST 21: Nonexistent config (404) ==="
echo "=========================================="
curl -s -o /dev/null -w "HTTP Status: %{http_code}" $AUTH "$BASE_URL/nonexistent/dev"
echo ""

# TEST 22: Delete file
echo "=========================================="
echo "=== TEST 22: Delete file ==="
echo "=========================================="
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=cipherapp&profile=default&ext=.yaml"
echo ""

# Verify deletion
echo "=========================================="
echo "=== VERIFY: File should be gone ==="
echo "=========================================="
curl -s -o /dev/null -w "HTTP Status: %{http_code}" $AUTH "$BASE_URL/cipherapp/default"
echo ""

# TEST 23: Swagger UI
echo "=========================================="
echo "=== TEST 23: Swagger UI ==="
echo "=========================================="
curl -s -o /dev/null -w "HTTP Status: %{http_code}" "$BASE_URL/swagger/index.html"
echo ""

# TEST 24: Upload with path parameter (raw file at custom path)
echo "=========================================="
echo "=== TEST 24: Upload with path parameter ==="
echo "=========================================="
curl -s $AUTH -X POST "$BASE_URL/upload?app=myapp&profile=prod&ext=.yaml&path=configs/myapp/prod.yaml" -H "Content-Type: text/plain" -d "path_config: enabled
custom_path: true"
echo ""

# TEST 25: Fetch uploaded file via path (raw content)
echo "=========================================="
echo "=== TEST 25: Fetch raw file via path ==="
echo "=========================================="
curl -s $AUTH "$BASE_URL/configs/myapp/prod.yaml"
echo ""

# TEST 26: Upload with nested path
echo "=========================================="
echo "=== TEST 26: Upload with nested path ==="
echo "=========================================="
curl -s $AUTH -X POST "$BASE_URL/upload?app=nestedapp&profile=dev&ext=.json&path=depth/level1/level2/nested.json" -H "Content-Type: text/plain" -d '{"nested": true}'
echo ""

# TEST 27: Fetch nested file via path
echo "=========================================="
echo "=== TEST 27: Fetch nested raw file via path ==="
echo "=========================================="
curl -s $AUTH "$BASE_URL/depth/level1/level2/nested.json"
echo ""

# TEST 28: Alternative Format - Fetch as .yaml
echo "=========================================="
echo "=== TEST 28: Alternative Format - Fetch as .yaml ==="
echo "=========================================="
curl -s $AUTH "$BASE_URL/myapp/prod.yaml"
echo ""

# TEST 29: Alternative Format - Fetch as .properties
echo "=========================================="
echo "=== TEST 29: Alternative Format - Fetch as .properties ==="
echo "=========================================="
curl -s $AUTH "$BASE_URL/myapp/prod.properties"
echo ""

# TEST 30: Accept Header - application/octet-stream (comprehensive)
echo "=========================================="
echo "=== TEST 30: Accept Header - application/octet-stream ==="
echo "=========================================="

# 30a: GET /{app}/{profile} + Accept → raw file
echo "--- 30a: GET /test/dev + Accept: application/octet-stream ---"
RESPONSE_30A=$(curl -s -H "Accept: application/octet-stream" $AUTH "$BASE_URL/test/dev")
echo "Response: $RESPONSE_30A"
if echo "$RESPONSE_30A" | grep -q "database_url"; then
  echo "✓ PASS: Raw content returned (contains 'database_url')"
else
  echo "✗ FAIL: Expected raw file content, got: $RESPONSE_30A"
fi
echo ""

# 30b: GET /{app} + Accept → raw file (no profile)
echo "--- 30b: GET /test + Accept: application/octet-stream ---"
# First upload a base config for /test
curl -s $AUTH -X POST "$BASE_URL/upload?app=test&profile=&ext=.yaml" -H "Content-Type: text/plain" -d "base_key: base_value
base_env: production"
RESPONSE_30B=$(curl -s -H "Accept: application/octet-stream" $AUTH "$BASE_URL/test")
echo "Response: $RESPONSE_30B"
if echo "$RESPONSE_30B" | grep -q "base_key"; then
  echo "✓ PASS: Raw content returned for /test (contains 'base_key')"
else
  echo "✗ FAIL: Expected raw file content, got: $RESPONSE_30B"
fi
echo ""

# 30c: GET /{app}-{profile} + Accept → raw file
echo "--- 30c: GET /test-dev + Accept: application/octet-stream ---"
RESPONSE_30C=$(curl -s -H "Accept: application/octet-stream" $AUTH "$BASE_URL/test-dev")
echo "Response: $RESPONSE_30C"
if echo "$RESPONSE_30C" | grep -q "database_url"; then
  echo "✓ PASS: Raw content returned for /test-dev (contains 'database_url')"
else
  echo "✗ FAIL: Expected raw file content, got: $RESPONSE_30C"
fi
echo ""

# 30d: GET /{app}/{profile}/{label} + Accept → raw file with label
echo "--- 30d: GET /labelapp/dev/main + Accept: application/octet-stream ---"
RESPONSE_30D=$(curl -s -H "Accept: application/octet-stream" $AUTH "$BASE_URL/labelapp/dev/main")
echo "Response: $RESPONSE_30D"
if echo "$RESPONSE_30D" | grep -q "label_config"; then
  echo "✓ PASS: Raw content returned for /labelapp/dev/main (contains 'label_config')"
else
  echo "✗ FAIL: Expected raw file content, got: $RESPONSE_30D"
fi
echo ""

# 30e: Without Accept header → should still return JSON (not raw)
echo "--- 30e: GET /test/dev WITHOUT Accept header → JSON ---"
RESPONSE_30E=$(curl -s $AUTH "$BASE_URL/test/dev")
echo "Response (first 200 chars): $(echo "$RESPONSE_30E" | head -c 200)"
if echo "$RESPONSE_30E" | grep -q '"name"'; then
  echo "✓ PASS: JSON response returned (contains '\"name\"')"
else
  echo "✗ FAIL: Expected JSON, got raw content"
fi
echo ""

# 30f: GET /{app}/{profile}/{label}/{path} + Accept → raw config file
echo "--- 30f: GET /test/dev/main + Accept: application/octet-stream ---"
# Upload a file with label "main" for app=test
curl -s $AUTH -X POST "$BASE_URL/upload?app=test&profile=dev&label=main&ext=.yaml" -H "Content-Type: text/plain" -d "label_main_key: main_value
label_main_env: staging"
RESPONSE_30F=$(curl -s -H "Accept: application/octet-stream" $AUTH "$BASE_URL/test/dev/main")
echo "Response: $RESPONSE_30F"
if echo "$RESPONSE_30F" | grep -q "label_main_key"; then
  echo "✓ PASS: Raw content returned for /test/dev/main (contains 'label_main_key')"
else
  echo "✗ FAIL: Expected raw file content, got: $RESPONSE_30F"
fi
echo ""

# 30g: Accept header with .ext URL → still raw (no change in behavior)
echo "--- 30g: GET /test/dev.yaml + Accept: application/octet-stream → raw ---"
# Re-upload since earlier cleanup may have deleted it
curl -s $AUTH -X POST "$BASE_URL/upload?app=test&profile=dev&ext=.yaml" -H "Content-Type: text/plain" -d "database_url: postgres://localhost/mydb
app_name: test-app
feature_flag: true"
RESPONSE_30G=$(curl -s -H "Accept: application/octet-stream" $AUTH "$BASE_URL/test/dev.yaml")
echo "Response: $RESPONSE_30G"
if echo "$RESPONSE_30G" | grep -q "database_url"; then
  echo "✓ PASS: Raw content returned for /test/dev.yaml"
else
  echo "✗ FAIL: Expected raw file content, got: $RESPONSE_30G"
fi
echo ""

# Cleanup test 30 files
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=test&profile=&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=test&profile=dev&label=main&ext=.yaml"
echo ""

# TEST 31: resolvePlaceholders query parameter
echo "=========================================="
echo "=== TEST 31: resolvePlaceholders=true ==="
echo "=========================================="
curl -s "$BASE_URL/myapp/prod.yaml?resolvePlaceholders=true"
echo ""

# TEST 32: Default label behavior (fetch without label)
echo "=========================================="
echo "=== TEST 32: Default label - fetch without label ==="
echo "=========================================="
curl -s $AUTH "$BASE_URL/labelapp/dev" | jq .
echo ""

# TEST 47: Default Label Fallback - main → master
echo "=========================================="
echo "=== TEST 47: Default Label Fallback (main → master) ==="
echo "=========================================="

# Cleanup
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=fallbacktest&profile=default&label=main&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=fallbacktest&profile=default&label=master&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=fallbacktest&profile=default&ext=.yaml"
echo ""

# Scenario A: Upload "main" label only, fetch without label → should find "main"
echo "--- Scenario A: Upload 'main' label, fetch without label → should find 'main' ---"
curl -s $AUTH -X POST "$BASE_URL/upload?app=fallbacktest&profile=default&label=main&ext=.yaml" -H "Content-Type: text/plain" -d "source: main-branch
config: v1"
echo ""

echo "Fetching /fallbacktest/default (no label) → should use 'main':"
RESPONSE_A=$(curl -s $AUTH "$BASE_URL/fallbacktest/default")
echo "$RESPONSE_A" | jq .

SOURCE_A=$(echo "$RESPONSE_A" | jq -r '.propertySources[0].source.source')
if [ "$SOURCE_A" = "main-branch" ]; then
  echo "✓ PASS: Found config from 'main' branch"
else
  echo "✗ FAIL: Expected 'main-branch', got '$SOURCE_A'"
fi

RESPONSE_LABEL_A=$(echo "$RESPONSE_A" | jq -r '.label')
if [ "$RESPONSE_LABEL_A" = "main" ]; then
  echo "✓ PASS: Response label is 'main'"
else
  echo "✗ FAIL: Expected label 'main', got '$RESPONSE_LABEL_A'"
fi
echo ""

# Scenario B: Also upload "master" label, then delete "main" → should fall back to "master"
echo "--- Scenario B: Upload 'master' then delete 'main' → should fall back to 'master' ---"
curl -s $AUTH -X POST "$BASE_URL/upload?app=fallbacktest&profile=default&label=master&ext=.yaml" -H "Content-Type: text/plain" -d "source: master-branch
config: v2"
echo ""

# Delete only the "main" label
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=fallbacktest&profile=default&label=main&ext=.yaml"
echo ""

echo "Fetching /fallbacktest/default (no label) → should fall back to 'master':"
RESPONSE_B=$(curl -s $AUTH "$BASE_URL/fallbacktest/default")
echo "$RESPONSE_B" | jq .

SOURCE_B=$(echo "$RESPONSE_B" | jq -r '.propertySources[0].source.source')
if [ "$SOURCE_B" = "master-branch" ]; then
  echo "✓ PASS: Found config from 'master' branch via fallback"
else
  echo "✗ FAIL: Expected 'master-branch', got '$SOURCE_B'"
fi

RESPONSE_LABEL_B=$(echo "$RESPONSE_B" | jq -r '.label')
if [ "$RESPONSE_LABEL_B" = "master" ]; then
  echo "✓ PASS: Response label is 'master'"
else
  echo "✗ FAIL: Expected label 'master', got '$RESPONSE_LABEL_B'"
fi
echo ""

# Scenario C: Fetch with explicit label "main" → should NOT fall back
echo "--- Scenario C: Explicit label 'main' (no fallback) ---"
curl -s $AUTH "$BASE_URL/fallbacktest/default/main" | jq '{
  config: .propertySources[0].source.config
}'
echo ""

# Scenario D: Fetch with explicit label "master" → should NOT fall back
echo "--- Scenario D: Explicit label 'master' (no fallback) ---"
curl -s $AUTH "$BASE_URL/fallbacktest/default/master" | jq '{
  config: .propertySources[0].source.config
}'
echo ""

# Scenario E: No files with main or master → should return 404
echo "--- Scenario E: No main/master files → 404 ---"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=fallbacktest&profile=default&label=main&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=fallbacktest&profile=default&label=master&ext=.yaml"
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" $AUTH "$BASE_URL/fallbacktest/default")
if [ "$HTTP_STATUS" = "404" ]; then
  echo "✓ PASS: Returns 404 when no main/master files exist"
else
  echo "✗ FAIL: Expected 404, got $HTTP_STATUS"
fi
echo ""

# Scenario F: Verify fallback picks ONLY "main" when it exists
echo "--- Scenario F: Only main sources returned when main exists ---"
curl -s $AUTH -X POST "$BASE_URL/upload?app=fallbacktest&profile=default&label=main&ext=.yaml" -H "Content-Type: text/plain" -d "shared_key: from-main
unique_main: true"
curl -s $AUTH -X POST "$BASE_URL/upload?app=fallbacktest&profile=default&label=master&ext=.yaml" -H "Content-Type: text/plain" -d "shared_key: from-master
unique_master: true"
echo ""

# Fetch without label → should ONLY get "main" sources
RESPONSE_F=$(curl -s $AUTH "$BASE_URL/fallbacktest/default")
echo "Property sources count (should be 1, only from main):"
SOURCE_COUNT_F=$(echo "$RESPONSE_F" | jq '.propertySources | length')
echo "Count: $SOURCE_COUNT_F"
if [ "$SOURCE_COUNT_F" -eq 1 ]; then
  echo "✓ PASS: Only main sources returned"
else
  echo "✗ FAIL: Expected 1 source, got $SOURCE_COUNT_F"
fi
echo ""

# Verify unique_main exists (from main) and unique_master does NOT exist (not from master)
UNIQUE_MAIN=$(echo "$RESPONSE_F" | jq -r '.propertySources[0].source.unique_main')
UNIQUE_MASTER=$(echo "$RESPONSE_F" | jq -r '.propertySources[0].source.unique_master')
if [ "$UNIQUE_MAIN" = "true" ] && [ "$UNIQUE_MASTER" = "null" ]; then
  echo "✓ PASS: Only main source content present (unique_master is null)"
else
  echo "✗ FAIL: Expected unique_main=true, unique_master=null, got main=$UNIQUE_MAIN master=$UNIQUE_MASTER"
fi
echo ""

# Cleanup fallback test files
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=fallbacktest&profile=default&label=main&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=fallbacktest&profile=default&label=master&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=fallbacktest&profile=default&ext=.yaml"
echo ""

# TEST 33: Profile-specific file names
echo "=========================================="
echo "=== TEST 33: Profile-specific file names ==="
echo "=========================================="
curl -s $AUTH -X POST "$BASE_URL/upload?app=altformat&profile=prod&ext=.yaml" -H "Content-Type: text/plain" -d "app_name: altformat-prod
env: production"
curl -s $AUTH -X POST "$BASE_URL/upload?app=altformat&profile=default&ext=.yaml" -H "Content-Type: text/plain" -d "app_name: altformat-default
env: default"
echo "Fetching /altformat/prod:"
curl -s $AUTH "$BASE_URL/altformat/prod" | jq .
echo ""
echo "Fetching /altformat/default:"
curl -s $AUTH "$BASE_URL/altformat/default" | jq .
echo ""

# TEST 34: Per-application encryption
echo "=========================================="
echo "=== TEST 34: Per-application encryption ==="
echo "=========================================="
# Upload config with cipher for pathapp
ENCRYPTED_PATHAPP=$(curl -s $AUTH -X POST "$BASE_URL/encrypt" -H "Content-Type: text/plain" -d "pathapp-secret" | tr -d '\n')
curl -s $AUTH -X POST "$BASE_URL/upload?app=pathapp&profile=prod&ext=.yaml" -H "Content-Type: text/plain" -d "db_password: '$ENCRYPTED_PATHAPP'
api_key: test-key-123"
echo "Fetching /pathapp/prod (should decrypt cipher):"
curl -s $AUTH "$BASE_URL/pathapp/prod" | jq .
echo ""

# TEST 35: Nested file path in URL
echo "=========================================="
echo "=== TEST 35: Nested file path in URL ==="
echo "=========================================="
curl -s $AUTH -X POST "$BASE_URL/upload?app=nested&profile=dev&ext=.json&path=app/nested/config.json" -H "Content-Type: text/plain" -d '{"nested": "deep config"}'
echo "Fetching /app/nested/config.json:"
curl -s $AUTH "$BASE_URL/app/nested/config.json"
echo ""

# TEST 36: Multiple labels for same app/profile
echo "=========================================="
echo "=== TEST 36: Multiple labels ==="
echo "=========================================="
curl -s $AUTH -X POST "$BASE_URL/upload?app=labeltest&profile=dev&label=main&ext=.yaml" -H "Content-Type: text/plain" -d "label: main
version: 1.0"
curl -s $AUTH -X POST "$BASE_URL/upload?app=labeltest&profile=dev&label=feature&ext=.yaml" -H "Content-Type: text/plain" -d "label: feature
version: 2.0"
echo "Fetching /labeltest/dev/main:"
curl -s $AUTH "$BASE_URL/labeltest/dev/main" | jq .
echo ""
echo "Fetching /labeltest/dev/feature:"
curl -s $AUTH "$BASE_URL/labeltest/dev/feature" | jq .
echo ""

# TEST 37: Empty body upload (should fail)
echo "=========================================="
echo "=== TEST 37: Empty body upload (error handling) ==="
echo "=========================================="
curl -s -o /dev/null -w "HTTP Status: %{http_code}" $AUTH -X POST "$BASE_URL/upload?app=emptytest&profile=dev&ext=.yaml" -H "Content-Type: text/plain" -d ""
echo ""

# TEST 38: Invalid file extension
echo "=========================================="
echo "=== TEST 38: Invalid file extension ==="
echo "=========================================="
curl -s $AUTH -X POST "$BASE_URL/upload?app=invalid&profile=dev&ext=.xml" -H "Content-Type: text/plain" -d "invalid extension test"
echo ""

# TEST 39: Path traversal attempt (security)
echo "=========================================="
echo "=== TEST 39: Path traversal attempt (security) ==="
echo "=========================================="
curl -s -o /dev/null -w "HTTP Status: %{http_code}" $AUTH -X POST "$BASE_URL/upload?app=security&profile=dev&ext=.yaml&path=../../etc/passwd" -H "Content-Type: text/plain" -d "malicious content"
echo ""

# TEST 40: Fetch non-existent label
echo "=========================================="
echo "=== TEST 40: Fetch non-existent label ==="
echo "=========================================="
curl -s -o /dev/null -w "HTTP Status: %{http_code}" $AUTH "$BASE_URL/labelapp/dev/nonexistent"
echo ""

# TEST 41: Decrypt invalid ciphertext
echo "=========================================="
echo "=== TEST 41: Decrypt invalid ciphertext ==="
echo "=========================================="
curl -s -o /dev/null -w "HTTP Status: %{http_code}" $AUTH -X POST "$BASE_URL/decrypt" -H "Content-Type: text/plain" -d "invalid-ciphertext-123"
echo ""

# TEST 42: Upload to same app/profile with different label
echo "=========================================="
echo "=== TEST 42: Same app/profile, different labels ==="
echo "=========================================="
curl -s $AUTH -X POST "$BASE_URL/upload?app=sametest&profile=prod&label=branch1&ext=.yaml" -H "Content-Type: text/plain" -d "branch: branch1
config: v1"
curl -s $AUTH -X POST "$BASE_URL/upload?app=sametest&profile=prod&label=branch2&ext=.yaml" -H "Content-Type: text/plain" -d "branch: branch2
config: v2"
echo "Fetching branch1:"
curl -s $AUTH "$BASE_URL/sametest/prod/branch1" | jq .
echo ""
echo "Fetching branch2:"
curl -s $AUTH "$BASE_URL/sametest/prod/branch2" | jq .
echo ""

# TEST 43: Verify response structure (GetValuesResponse)
echo "=========================================="
echo "=== TEST 43: Verify response structure ==="
echo "=========================================="
curl -s $AUTH "$BASE_URL/test/dev" | jq '{
  has_name: (.name != null),
  has_profiles: (.profiles != null),
  has_propertySources: (.propertySources != null),
  propertySources_count: (.propertySources | length)
}'
echo ""


# TEST 44: Hierarchical property source resolution - application.yml
echo "=========================================="
echo "=== TEST 44: Hierarchical resolution (application.yml) ==="
echo "=========================================="

# Upload application.yaml (lowest priority, level 1) - empty profile
curl -s $AUTH -X POST "$BASE_URL/upload?app=application&profile=&ext=.yaml" -H "Content-Type: text/plain" -d "level: 1
database_url: global-postgres://localhost/global
log_level: warn
shared: from-application"
echo "Uploaded application.yaml (app=application, profile=)"

# Upload application-hier.yaml (level 2)
curl -s $AUTH -X POST "$BASE_URL/upload?app=application&profile=hier&ext=.yaml" -H "Content-Type: text/plain" -d "level: 2
database_url: profile-specific-postgres://localhost/profile
log_level: info
shared: from-application-hier"
echo "Uploaded application-hier.yaml (app=application, profile=hier)"

# Upload myapp.yaml (level 3) - empty profile
curl -s $AUTH -X POST "$BASE_URL/upload?app=myapp&profile=&ext=.yaml" -H "Content-Type: text/plain" -d "level: 3
database_url: app-specific-postgres://localhost/app
log_level: debug
shared: from-myapp"
echo "Uploaded myapp.yaml (app=myapp, profile=)"

# Upload myapp-hier.yaml (highest priority, level 4)
curl -s $AUTH -X POST "$BASE_URL/upload?app=myapp&profile=hier&ext=.yaml" -H "Content-Type: text/plain" -d "level: 4
database_url: app-profile-specific-postgres://localhost/app-profile
log_level: trace
shared: from-myapp-hier"
echo "Uploaded myapp-hier.yaml (app=myapp, profile=hier)"

echo ""
echo "Fetching /myapp/hier - should merge all 4 files in precedence order:"
RESPONSE=$(curl -s $AUTH "$BASE_URL/myapp/hier")
echo "$RESPONSE" | jq .
echo ""

# Verify the merge
SOURCE_COUNT=$(echo "$RESPONSE" | jq '.propertySources | length')
echo "Property sources count: $SOURCE_COUNT (expected: 4)"
if [ "$SOURCE_COUNT" -eq 4 ]; then
  echo "✓ PASS: Got 4 property sources"
else
  echo "✗ FAIL: Expected 4 property sources, got $SOURCE_COUNT"
fi
echo ""

# Verify highest precedence source is myapp-hier
FIRST_SOURCE=$(echo "$RESPONSE" | jq -r '.propertySources[0].name')
echo "Highest precedence source: $FIRST_SOURCE"
if echo "$FIRST_SOURCE" | grep -q "app=myapp profile=hier"; then
  echo "✓ PASS: Highest precedence is myapp-hier"
else
  echo "✗ FAIL: Expected myapp-hier as highest precedence, got $FIRST_SOURCE"
fi
echo ""

# Verify database_url comes from highest precedence
DATABASE_URL=$(echo "$RESPONSE" | jq -r '.propertySources[0].source.database_url')
echo "database_url value: $DATABASE_URL"
if echo "$DATABASE_URL" | grep -q "app-profile-specific"; then
  echo "✓ PASS: database_url from myapp-hier (highest precedence)"
else
  echo "✗ FAIL: Expected app-profile-specific, got $DATABASE_URL"
fi
echo ""

# TEST 45: Verify lower-level sources are also present
echo "=========================================="
echo "=== TEST 45: Verify all levels present ==="
echo "=========================================="
SOURCE_NAMES=$(echo "$RESPONSE" | jq -r '.propertySources[].name')
echo "All property sources:"
echo "$SOURCE_NAMES"
echo ""

# Check all 4 levels are present
if echo "$SOURCE_NAMES" | grep -q "app=application profile="; then
  echo "✓ PASS: application.yaml (base) present"
else
  echo "✗ FAIL: application.yaml (base) missing"
fi

if echo "$SOURCE_NAMES" | grep -q "app=application profile=hier"; then
  echo "✓ PASS: application-hier.yaml present"
else
  echo "✗ FAIL: application-hier.yaml missing"
fi

if echo "$SOURCE_NAMES" | grep -q "app=myapp profile="; then
  echo "✓ PASS: myapp.yaml (base) present"
else
  echo "✗ FAIL: myapp.yaml (base) missing"
fi

if echo "$SOURCE_NAMES" | grep -q "app=myapp profile=hier"; then
  echo "✓ PASS: myapp-hier.yaml present"
else
  echo "✗ FAIL: myapp-hier.yaml missing"
fi
echo ""

# TEST 46: Override test - verify lower levels don't override higher levels
echo "=========================================="
echo "=== TEST 46: Verify override behavior ==="
echo "=========================================="

# Check log_level - should be from highest precedence (trace from myapp-hier)
LOG_LEVEL=$(echo "$RESPONSE" | jq -r '.propertySources[0].source.log_level')
echo "log_level from highest precedence: $LOG_LEVEL"
if [ "$LOG_LEVEL" = "trace" ]; then
  echo "✓ PASS: log_level correctly overridden by myapp-hier"
else
  echo "✗ FAIL: Expected trace, got $LOG_LEVEL"
fi
echo ""

# Check 'shared' field - should be from highest precedence
SHARED=$(echo "$RESPONSE" | jq -r '.propertySources[0].source.shared')
echo "shared from highest precedence: $SHARED"
if echo "$SHARED" | grep -q "myapp-hier"; then
  echo "✓ PASS: shared correctly overridden by myapp-hier"
else
  echo "✗ FAIL: Expected myapp-hier, got $SHARED"
fi
echo ""

# Clean up hierarchical test files
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=application&profile=&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=application&profile=hier&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=myapp&profile=&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=myapp&profile=hier&ext=.yaml"
echo ""
# Clean up
echo "--- FINAL CLEANUP ---"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=test&profile=dev&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=test&profile=common&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=altformat&profile=prod&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=placeholder&profile=default&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=labelapp&profile=dev&label=main&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=pathapp&profile=prod&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=myapp&profile=prod&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=propsapp&profile=default&ext=.properties"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=prioapp&profile=test&ext=.properties"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=prioapp&profile=test&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=labeltest&profile=dev&label=main&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=labeltest&profile=dev&label=feature&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=sametest&profile=prod&label=branch1&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=sametest&profile=prod&label=branch2&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=nested&profile=dev&ext=.json"
echo ""

echo "=========================================="
echo "=== COMPREHENSIVE TEST SUITE COMPLETE ==="
echo "=== Total Tests: 47 (TEST 30 expanded to 7 sub-tests) ==="
echo "=========================================="
echo ""
echo "Features Tested:"
echo "  ✓ Single profile upload/fetch"
echo "  ✓ Multi-profile merge"
echo "  ✓ JSON format"
echo "  ✓ YAML format"
echo "  ✓ Properties format"
echo "  ✓ Label support"
echo "  ✓ Extension priority"
echo "  ✓ Encryption/Decryption"
echo "  ✓ Cipher pattern decryption"
echo "  ✓ Authentication (401 errors)"
echo "  ✓ File not found (404)"
echo "  ✓ File deletion"
echo "  ✓ Path serving"
echo "  ✓ Nested paths"
echo "  ✓ Alternative format serving (.yaml, .properties)"
echo "  ✓ Accept header (application/octet-stream) — all URL patterns: /{app}, /{app}-{profile}, /{app}/{profile}, /{app}/{profile}/{label}, /{app}/{profile}/{label}/{path}"
echo "  ✓ resolvePlaceholders parameter"
echo "  ✓ Default label behavior"
echo "  ✓ Profile-specific files"
echo "  ✓ Per-application encryption"
echo "  ✓ Multiple labels"
echo "  ✓ Error handling"
echo "  ✓ Security (path traversal prevention)"
echo "  ✓ Response structure validation"
echo "  ✓ Hierarchical property source resolution (application.yml, application-{profile}.yml, {app}.yml, {app}-{profile}.yml)"
echo ""