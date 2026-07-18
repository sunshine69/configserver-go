#!/bin/bash
# Test profile-specific file resolution (application.yml, application-{profile}.yml)
# Verifies Spring Cloud Config Server hierarchical property source resolution

BASE_URL="http://localhost:7777"
AUTH="-u user2:changeme"

# Clean up
echo "=== CLEANUP ==="
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=testapp&profile=dev&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=testapp&profile=dev&label=main&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=testapp&profile=hier&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=testapp&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=testapp&profile=dev&ext=.json"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=testapp&profile=dev&ext=.yml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=testapp&profile=dev&ext=.properties"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=testapp&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=testapp&profile=dev&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=testapp&profile=dev&label=main&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=testapp&ext=.json"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=testapp&profile=dev&ext=.yml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=testapp&profile=dev&ext=.properties"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=application&profile=dev&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=application&profile=hier&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=application&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=altformat&profile=prod&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=altformat&profile=default&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=myapp&profile=hier&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=propsapp&profile=default&ext=.properties"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=prioapp&profile=test&ext=.properties"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=prioapp&profile=test&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=labeltest&profile=dev&label=main&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=labeltest&profile=dev&label=feature&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=sametest&profile=prod&label=branch1&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=sametest&profile=prod&label=branch2&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=nested&profile=dev&ext=.json"
echo ""

# TEST 1: Upload all 4 file types for hierarchical resolution
echo "=== TEST 1: Upload all 4 file types ==="
echo ""

# Level 1 (highest): {app}-{profile}.{ext}
echo "1. Uploading testapp-dev.yaml..."
curl -s $AUTH -X POST "$BASE_URL/upload?app=testapp&profile=dev&ext=.yaml" \
  -H "Content-Type: text/plain" \
  -d "level1: testapp-dev-specific
database_url: testapp-dev-postgres://localhost/dev
app_name: testapp-dev
feature_flag: true
shared_dev: dev-from-app-profile"

echo ""

# Level 2: {app}.{ext} - upload with empty profile (using path parameter)
echo "2. Uploading testapp.yaml (base app file)..."
curl -s $AUTH -X POST "$BASE_URL/upload?app=testapp&profile=dev&ext=.yaml&path=testapp.yaml" \
  -H "Content-Type: text/plain" \
  -d "level2: testapp-base
database_url: testapp-base-postgres://localhost/base
app_name: testapp-base
feature_flag: false
shared_app: app-level"

echo ""

# Level 3: application-{profile}.{ext}
echo "3. Uploading application-dev.yaml..."
curl -s $AUTH -X POST "$BASE_URL/upload?app=application&profile=dev&ext=.yaml" \
  -H "Content-Type: text/plain" \
  -d "level3: application-dev-shared
database_url: shared-dev-postgres://localhost/shared
log_level: debug
shared_dev: shared-dev-level
global_debug: true"

echo ""

# Level 4 (lowest): application.{ext}
echo "4. Uploading application.yaml (base application file)..."
curl -s $AUTH -X POST "$BASE_URL/upload?app=application&profile=dev&ext=.yaml&path=application.yaml" \
  -H "Content-Type: text/plain" \
  -d "level4: application-global
database_url: global-postgres://localhost/global
log_level: info
shared_app: global-level
global_config: base-config"

echo ""
echo ""

# TEST 2: Fetch and verify hierarchical merge
echo "=== TEST 2: Fetch /testapp/dev - should merge all 4 files ==="
echo ""
RESPONSE=$(curl -s $AUTH "$BASE_URL/testapp/dev")
echo "$RESPONSE" | jq .
echo ""

# Verify the merge
echo "=== VERIFICATION ==="
echo ""

# Check that we have 4 property sources
SOURCE_COUNT=$(echo "$RESPONSE" | jq '.propertySources | length')
echo "Property sources count: $SOURCE_COUNT (expected: 4)"
if [ "$SOURCE_COUNT" -eq 4 ]; then
  echo "✓ PASS: Got 4 property sources"
else
  echo "✗ FAIL: Expected 4 property sources, got $SOURCE_COUNT"
fi
echo ""

# Check precedence order (first should be highest precedence)
FIRST_SOURCE=$(echo "$RESPONSE" | jq -r '.propertySources[0].name')
echo "First (highest precedence) source: $FIRST_SOURCE"
if echo "$FIRST_SOURCE" | grep -q "testapp-dev"; then
  echo "✓ PASS: Highest precedence is testapp-dev"
else
  echo "✗ FAIL: Expected testapp-dev as highest precedence, got $FIRST_SOURCE"
fi
echo ""

# Verify key overrides work (higher precedence wins)
DATABASE_URL=$(echo "$RESPONSE" | jq -r '.propertySources[0].source.database_url')
echo "database_url value: $DATABASE_URL"
if echo "$DATABASE_URL" | grep -q "testapp-dev"; then
  echo "✓ PASS: database_url from highest precedence (testapp-dev)"
else
  echo "✗ FAIL: Expected testapp-dev database_url, got $DATABASE_URL"
fi
echo ""

LOG_LEVEL=$(echo "$RESPONSE" | jq -r '.propertySources[2].source.log_level')
echo "log_level in application-dev: $LOG_LEVEL"
if [ "$LOG_LEVEL" = "debug" ]; then
  echo "✓ PASS: log_level correctly set in application-dev"
else
  echo "✗ FAIL: Expected debug, got $LOG_LEVEL"
fi
echo ""

GLOBAL_CONFIG=$(echo "$RESPONSE" | jq -r '.propertySources[3].source.global_config')
echo "global_config in application: $GLOBAL_CONFIG"
if [ "$GLOBAL_CONFIG" = "base-config" ]; then
  echo "✓ PASS: global_config correctly set in application"
else
  echo "✗ FAIL: Expected base-config, got $GLOBAL_CONFIG"
fi
echo ""

echo ""
echo "=== TEST 3: Verify shared_dev override (testapp-dev should win) ==="
SHARED_DEV=$(echo "$RESPONSE" | jq -r '.propertySources[0].source.shared_dev')
echo "shared_dev value: $SHARED_DEV"
if echo "$SHARED_DEV" | grep -q "testapp-dev"; then
  echo "✓ PASS: shared_dev from testapp-dev (highest precedence)"
else
  echo "✗ FAIL: Expected testapp-dev shared_dev, got $SHARED_DEV"
fi
echo ""

echo "=== TEST 4: Verify all levels present ==="
SOURCE_NAMES=$(echo "$RESPONSE" | jq -r '.propertySources[].name')
echo "All property sources:"
echo "$SOURCE_NAMES"
echo ""

# Check all 4 levels are present
if echo "$SOURCE_NAMES" | grep -q "testapp-dev"; then
  echo "✓ PASS: testapp-dev.yaml present"
else
  echo "✗ FAIL: testapp-dev.yaml missing"
fi

if echo "$SOURCE_NAMES" | grep -q "testapp"; then
  echo "✓ PASS: testapp.yaml present"
else
  echo "✗ FAIL: testapp.yaml missing"
fi

if echo "$SOURCE_NAMES" | grep -q "application-dev"; then
  echo "✓ PASS: application-dev.yaml present"
else
  echo "✗ FAIL: application-dev.yaml missing"
fi

if echo "$SOURCE_NAMES" | grep -q "application"; then
  echo "✓ PASS: application.yaml present"
else
  echo "✗ FAIL: application.yaml missing"
fi
echo ""

echo "=== TEST 5: Verify override behavior ==="

# Check log_level - should be from highest precedence (debug from application-dev)
LOG_LEVEL=$(echo "$RESPONSE" | jq -r '.propertySources[2].source.log_level')
echo "log_level from application-dev: $LOG_LEVEL"
if [ "$LOG_LEVEL" = "debug" ]; then
  echo "✓ PASS: log_level correctly set in application-dev"
else
  echo "✗ FAIL: Expected debug, got $LOG_LEVEL"
fi
echo ""

# Check 'shared_app' field - should be from highest precedence that has it
SHARED_APP=$(echo "$RESPONSE" | jq -r '.propertySources[1].source.shared_app')
echo "shared_app from testapp.yaml: $SHARED_APP"
if echo "$SHARED_APP" | grep -q "app-level"; then
  echo "✓ PASS: shared_app correctly set in testapp.yaml"
else
  echo "✗ FAIL: Expected app-level, got $SHARED_APP"
fi
echo ""

# Clean up hierarchical test files
echo "=== CLEANUP ==="
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=testapp&profile=dev&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=application&profile=dev&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=testapp&profile=dev&ext=.yaml&path=testapp.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=application&profile=dev&ext=.yaml&path=application.yaml"
echo ""
