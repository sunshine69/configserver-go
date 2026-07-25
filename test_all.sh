#!/bin/bash
# Comprehensive test suite for config-server-go

BASE_URL="${BASE_URL:-http://localhost:7777}"
AUTH="-u ${CONFIG_USER:-user2}:${CONFIG_PASSWORD:-changeme}"

echo "AUTH: '$AUTH' $BASE_URL"
read junk

echo "=========================================="
echo "=== TEST SUITE: config-server-go ==="
echo "=========================================="
echo ""

# Clean up any existing test data
echo "--- CLEANUP ---"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=test&profile=dev&ext=.yaml"
echo ""
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=test&profile=common&ext=.yaml"
echo ""
echo ""

# TEST 1: Upload single profile
echo "=========================================="
echo "=== TEST 1: Upload single profile ==="
echo "=========================================="
curl -s $AUTH -X POST "$BASE_URL/upload?app=test&profile=dev&ext=.yaml" -H "Content-Type: text/plain" -d "database_url: postgres://localhost/mydb
app_name: test-app
feature_flag: true"
echo ""
echo ""

# TEST 2: Fetch single profile
echo "=========================================="
echo "=== TEST 2: Fetch /test/dev ==="
echo "=========================================="
curl -s $AUTH "$BASE_URL/test/dev" | jq .
echo ""
echo ""

# TEST 3: Fetch single segment format
echo "=========================================="
echo "=== TEST 3: Fetch /test-dev ==="
echo "=========================================="
curl -s $AUTH "$BASE_URL/test-dev" | jq .
echo ""
echo ""

# TEST 4: Upload second profile for multi-profile merge
echo "=========================================="
echo "=== TEST 4: Upload common profile ==="
echo "=========================================="
curl -s $AUTH -X POST "$BASE_URL/upload?app=test&profile=common&ext=.yaml" -H "Content-Type: text/plain" -d "log_level: info
max_retries: 3
database_url: override-from-common"
echo ""
echo ""

# TEST 5: Multi-profile merge
echo "=========================================="
echo "=== TEST 5: Multi-profile /test/dev,common ==="
echo "=========================================="
curl -s $AUTH "$BASE_URL/test/dev,common" | jq .
echo ""
echo ""

# TEST 6: Health check
echo "=========================================="
echo "=== TEST 6: Health check ==="
echo "=========================================="
curl -s "$BASE_URL/health" | jq .
echo ""
echo ""

# TEST 7: List files
echo "=========================================="
echo "=== TEST 7: List files ==="
echo "=========================================="
curl -s $AUTH "$BASE_URL/list" | jq .
echo ""
echo ""

# TEST 8: Upload JSON file
echo "=========================================="
echo "=== TEST 8: Upload JSON file ==="
echo "=========================================="
curl -s $AUTH -X POST "$BASE_URL/upload?app=myapp&profile=prod&ext=.json" -H "Content-Type: text/plain" -d '{"server":{"host":"localhost","port":8080}}'
echo ""
echo ""

# TEST 9: Fetch JSON file
echo "=========================================="
echo "=== TEST 9: Fetch JSON /myapp/prod ==="
echo "=========================================="
curl -s $AUTH "$BASE_URL/myapp/prod" | jq .
echo ""
echo ""

# TEST 10: Upload properties file
echo "=========================================="
echo "=== TEST 10: Upload properties file ==="
echo "=========================================="
curl -s $AUTH -X POST "$BASE_URL/upload?app=propsapp&profile=default&ext=.properties" -H "Content-Type: text/plain" -d "spring.datasource.url=jdbc:mysql://localhost/test
spring.datasource.username=root"
echo ""
echo ""

# TEST 11: Fetch properties file
echo "=========================================="
echo "=== TEST 11: Fetch properties /propsapp/default ==="
echo "=========================================="
curl -s $AUTH "$BASE_URL/propsapp/default" | jq .
echo ""
echo ""

# TEST 12: Upload with label
echo "=========================================="
echo "=== TEST 12: Upload with label ==="
echo "=========================================="
curl -s $AUTH -X POST "$BASE_URL/upload?app=labelapp&profile=dev&label=main&ext=.yaml" -H "Content-Type: text/plain" -d "label_config: enabled"
echo ""
echo ""

# TEST 13: Fetch with label
echo "=========================================="
echo "=== TEST 13: Fetch with label /labelapp/dev/main ==="
echo "=========================================="
curl -s $AUTH "$BASE_URL/labelapp/dev/main" | jq .
echo ""
echo ""

# TEST 14: Upload properties file for extension priority test
echo "=========================================="
echo "=== TEST 14: Upload .properties (should win over .yaml) ==="
echo "=========================================="
curl -s $AUTH -X POST "$BASE_URL/upload?app=prioapp&profile=test&ext=.properties" -H "Content-Type: text/plain" -d "source=from-properties
key1=properties-value"
echo ""
echo ""

# Upload yaml too for priority test
curl -s $AUTH -X POST "$BASE_URL/upload?app=prioapp&profile=test&ext=.yaml" -H "Content-Type: text/plain" -d "source: from-yaml
key2: yaml-value"
echo ""
echo ""

# TEST 15: Extension priority test (properties should win)
echo "=========================================="
echo "=== TEST 15: Extension priority /prioapp/test ==="
echo "=========================================="
curl -s $AUTH "$BASE_URL/prioapp/test" | jq .
echo ""
echo ""

# TEST 16: Upload encrypted content
echo "=========================================="
echo "=== TEST 16: Encrypt value ==="
echo "=========================================="
ENCRYPTED=$(curl -s $AUTH -X POST "$BASE_URL/encrypt" -H "Content-Type: text/plain" -d "my-secret-password" | tr -d '\n')
echo "Encrypted: $ENCRYPTED"
echo ""
echo ""

# Upload file with cipher pattern
curl -s $AUTH -X POST "$BASE_URL/upload?app=cipherapp&profile=default&ext=.yaml" -H "Content-Type: text/plain" -d "password: '$ENCRYPTED'
normal_key: normal_value"
echo ""
echo ""

# TEST 17: Fetch with cipher decryption
echo "=========================================="
echo "=== TEST 17: Fetch with cipher decryption ==="
echo "=========================================="
curl -s $AUTH "$BASE_URL/cipherapp/default" | jq .
echo ""
echo ""

# TEST 18: Decrypt test
echo "=========================================="
echo "=== TEST 18: Decrypt value ==="
echo "=========================================="
curl -s $AUTH -X POST "$BASE_URL/decrypt" -H "Content-Type: text/plain" -d "$ENCRYPTED"
echo ""
echo ""

# TEST 19: 401 - wrong password
echo "=========================================="
echo "=== TEST 19: Wrong password (401) ==="
echo "=========================================="
curl -s -o /dev/null -w "HTTP Status: %{http_code}" -u "user2:wrongpass" "$BASE_URL/test/dev"
echo ""
echo ""

# TEST 20: 401 - unknown user
echo "=========================================="
echo "=== TEST 20: Unknown user (401) ==="
echo "=========================================="
curl -s -o /dev/null -w "HTTP Status: %{http_code}" -u "unknown:password" "$BASE_URL/test/dev"
echo ""
echo ""

# TEST 21: 404 - nonexistent config
echo "=========================================="
echo "=== TEST 21: Nonexistent config (404) ==="
echo "=========================================="
curl -s -o /dev/null -w "HTTP Status: %{http_code}" $AUTH "$BASE_URL/nonexistent/dev"
echo ""
echo ""

# TEST 22: Delete file
echo "=========================================="
echo "=== TEST 22: Delete file ==="
echo "=========================================="
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=cipherapp&profile=default&ext=.yaml"
echo ""
echo ""

# Verify deletion
echo "=========================================="
echo "=== VERIFY: File should be gone ==="
echo "=========================================="
curl -s -o /dev/null -w "HTTP Status: %{http_code}" $AUTH "$BASE_URL/cipherapp/default"
echo ""
echo ""

# TEST 23: Swagger UI
echo "=========================================="
echo "=== TEST 23: Swagger UI ==="
echo "=========================================="
curl -s -o /dev/null -w "HTTP Status: %{http_code}" "$BASE_URL/swagger/index.html"
echo ""
echo ""

# TEST 24: Upload with path parameter (raw file at custom path)
echo "=========================================="
echo "=== TEST 24: Upload with path parameter ==="
echo "=========================================="
curl -s $AUTH -X POST "$BASE_URL/upload?app=myapp&profile=prod&ext=.yaml&path=configs/myapp/prod.yaml" -H "Content-Type: text/plain" -d "path_config: enabled
custom_path: true"
echo ""
echo ""

# TEST 25: Fetch uploaded file via path (raw content)
echo "=========================================="
echo "=== TEST 25: Fetch raw file via path ==="
echo "=========================================="
curl -s $AUTH "$BASE_URL/configs/myapp/prod.yaml"
echo ""
echo ""

# TEST 26: Upload with nested path
echo "=========================================="
echo "=== TEST 26: Upload with nested path ==="
echo "=========================================="
curl -s $AUTH -X POST "$BASE_URL/upload?app=nestedapp&profile=dev&ext=.json&path=depth/level1/level2/nested.json" -H "Content-Type: text/plain" -d '{"nested": true}'
echo ""
echo ""

# TEST 27: Fetch nested file via path
echo "=========================================="
echo "=== TEST 27: Fetch nested raw file via path ==="
echo "=========================================="
curl -s $AUTH "$BASE_URL/depth/level1/level2/nested.json"
echo ""
echo ""

# Clean up path-based files
echo "--- CLEANUP (path files) ---"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=myapp&profile=prod&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=nestedapp&profile=dev&ext=.json"
echo ""
echo ""

echo "=========================================="
echo "=== TEST SUITE COMPLETE ==="
echo "=========================================="

# ============================================================
# === MULTI-PASSWORD AUTHENTICATION TESTS ===
# ============================================================

echo ""
echo "=========================================="
echo "=== TEST 28: Add a temporary password ==="
echo "=========================================="
FUTURE_DATE=$(date -d "+24 hours" -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u -v+24H +"%Y-%m-%dT%H:%M:%SZ")
echo "Expiry: $FUTURE_DATE"
curl -s $AUTH -X POST "$BASE_URL/addpassword" \
  -d "password=temptoken123" \
  -d "exp=$FUTURE_DATE" \
  -d "description=temporary-token-for-testing"
echo ""
echo ""

echo "=========================================="
echo "=== TEST 29: Add a no-expire password ==="
echo "=========================================="
curl -s $AUTH -X POST "$BASE_URL/addpassword" \
  -d "password=foreverpass" \
  -d "exp=noexpire" \
  -d "description=permanent-secondary-password"
echo ""
echo ""

echo "=========================================="
echo "=== TEST 30: List all passwords ==="
echo "=========================================="
curl -s $AUTH "$BASE_URL/listpasswords" | jq .
echo ""
echo ""

echo "=========================================="
echo "=== TEST 31: Authenticate with temp password ==="
echo "=========================================="
curl -s -o /dev/null -w "HTTP Status: %{http_code}" -u "user2:temptoken123" "$BASE_URL/test/dev"
echo ""
echo ""

echo "=========================================="
echo "=== TEST 32: Authenticate with no-expire password ==="
echo "=========================================="
curl -s -o /dev/null -w "HTTP Status: %{http_code}" -u "user2:foreverpass" "$BASE_URL/test/dev"
echo ""
echo ""

echo "=========================================="
echo "=== TEST 33: Authenticate with main password still works ==="
echo "=========================================="
curl -s -o /dev/null -w "HTTP Status: %{http_code}" -u "user2:changeme" "$BASE_URL/test/dev"
echo ""
echo ""

echo "=========================================="
echo "=== TEST 34: Duplicate password rejected ==="
echo "=========================================="
curl -s -o /dev/null -w "HTTP Status: %{http_code}" $AUTH -X POST "$BASE_URL/addpassword" \
  -d "password=temptoken123" \
  -d "exp=noexpire" \
  -d "description=duplicate-test"
echo ""
echo ""

echo "=========================================="
echo "=== TEST 35: Missing password field rejected ==="
echo "=========================================="
curl -s -o /dev/null -w "HTTP Status: %{http_code}" $AUTH -X POST "$BASE_URL/addpassword" \
  -d "exp=$FUTURE_DATE" \
  -d "description=missing-password"
echo ""
echo ""

echo "=========================================="
echo "=== TEST 36: Invalid exp format rejected ==="
echo "=========================================="
curl -s -o /dev/null -w "HTTP Status: %{http_code}" $AUTH -X POST "$BASE_URL/addpassword" \
  -d "password=badexp" \
  -d "exp=not-a-date" \
  -d "description=bad-exp"
echo ""
echo ""

echo "=========================================="
echo "=== TEST 37: Delete a password by hash ==="
echo "=========================================="
# First get the hash from list
TEMP_HASH=$(curl -s $AUTH "$BASE_URL/listpasswords" | jq -r '.passwords | keys[0]')
echo "Deleting hash: $TEMP_HASH"
curl -s $AUTH -X DELETE "$BASE_URL/delpassword?hash=$TEMP_HASH"
echo ""
echo ""

echo "=========================================="
echo "=== TEST 38: Delete nonexistent hash ==="
echo "=========================================="
curl -s -o /dev/null -w "HTTP Status: %{http_code}" $AUTH -X DELETE "$BASE_URL/delpassword?hash=nonexistenthash00000000000000000000000000000000000000000000000000000000"
echo ""
echo ""

echo "=========================================="
echo "=== TEST 39: Delete missing hash param ==="
echo "=========================================="
curl -s -o /dev/null -w "HTTP Status: %{http_code}" $AUTH -X DELETE "$BASE_URL/delpassword"
echo ""
echo ""

echo "=========================================="
echo "=== TEST 40: Unauthorized on addpassword ==="
echo "=========================================="
curl -s -o /dev/null -w "HTTP Status: %{http_code}" -X POST "$BASE_URL/addpassword" \
  -d "password=test" \
  -d "exp=noexpire" \
  -d "description=unauthorized"
echo ""
echo ""

echo "=========================================="
echo "=== TEST 41: Unauthorized on listpasswords ==="
echo "=========================================="
curl -s -o /dev/null -w "HTTP Status: %{http_code}" "$BASE_URL/listpasswords"
echo ""
echo ""

echo "=========================================="
echo "=== TEST 42: Unauthorized on delpassword ==="
echo "=========================================="
curl -s -o /dev/null -w "HTTP Status: %{http_code}" -X DELETE "$BASE_URL/delpassword?hash=abc123"
echo ""
echo ""

# ============================================================
# === FORMAT-SPECIFIC ENDPOINTS (Spring Cloud Config Server) ===
# ============================================================

echo ""
echo "=========================================="
echo "=== TEST 43: YAML format endpoint ==="
echo "=========================================="
echo "Spring spec: /{application}-{profile}.yml"
curl -s $AUTH "$BASE_URL/test-dev.yml" | jq .
echo ""
echo ""

echo "=========================================="
echo "=== TEST 44: JSON format endpoint ==="
echo "=========================================="
echo "Spring spec: /{application}-{profile}.json"
curl -s $AUTH "$BASE_URL/test-dev.json" | jq .
echo ""
echo ""

echo "=========================================="
echo "=== TEST 45: Properties format endpoint ==="
echo "=========================================="
echo "Spring spec: /{application}-{profile}.properties"
curl -s $AUTH "$BASE_URL/test-dev.properties" | jq .
echo ""
echo ""

echo "=========================================="
echo "=== TEST 46: Label-prefixed YAML endpoint ==="
echo "=========================================="
echo "Spring spec: /{label}/{application}-{profile}.yml"
curl -s $AUTH "$BASE_URL/main/test-dev.yml" | jq .
echo ""
echo ""

echo "=========================================="
echo "=== TEST 47: Label-prefixed JSON endpoint ==="
echo "=========================================="
echo "Spring spec: /{label}/{application}-{profile}.json"
curl -s $AUTH "$BASE_URL/main/test-dev.json" | jq .
echo ""
echo ""

echo "=========================================="
echo "=== TEST 48: Label-prefixed properties endpoint ==="
echo "=========================================="
echo "Spring spec: /{label}/{application}-{profile}.properties"
curl -s $AUTH "$BASE_URL/main/test-dev.properties" | jq .
echo ""
echo ""

# ============================================================
# === RAW FILE ENDPOINTS (Spring Cloud Config Server) ===
# ============================================================

echo ""
echo "=========================================="
echo "=== TEST 49: List files endpoint ==="
echo "=========================================="
echo "Spring spec: /{application}/{profile}/{label}/{path}/listFiles"
curl -s $AUTH "$BASE_URL/test/dev/main/listFiles" | jq .
echo ""
echo ""

echo "=========================================="
echo "=== TEST 50: List files for default label ==="
echo "=========================================="
echo "Spring spec: /{application}/{profile}/{path}/listFiles"
curl -s $AUTH "$BASE_URL/test/dev/listFiles" | jq .
echo ""
echo ""

echo "=========================================="
echo "=== ALL TESTS COMPLETE ==="
echo "=========================================="
