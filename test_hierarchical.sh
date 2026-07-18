#!/bin/bash
# Test hierarchical property source resolution
# Verifies that multiple config files are fetched and merged in correct precedence order

BASE_URL="http://localhost:7777"
AUTH="-u user2:changeme"

echo "=== HIERARCHICAL PROPERTY SOURCE RESOLUTION TEST ==="
echo ""

# Clean up any existing test data
echo "--- CLEANUP ---"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=testapp&profile=dev&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=application&profile=dev&ext=.yaml"
echo ""

# Upload config files at different hierarchy levels
echo "=== UPLOADING CONFIG FILES ==="
echo ""

# Level 1: App-specific file (highest precedence)
echo "1. Uploading testapp-dev.yaml (app-specific, highest precedence)..."
curl -s $AUTH -X POST "$BASE_URL/upload?app=testapp&profile=dev&ext=.yaml" \
  -H "Content-Type: text/plain" \
  -d "level: 1
database_url: testapp-dev-postgres://localhost/dev
app_name: testapp-dev
feature_flag: true
shared_key: from-app-specific"
echo ""

# Level 2: Application-level file (lowest precedence)
echo "2. Uploading application-dev.yaml (application-level, lowest precedence)..."
curl -s $AUTH -X POST "$BASE_URL/upload?app=application&profile=dev&ext=.yaml" \
  -H "Content-Type: text/plain" \
  -d "level: 2
database_url: application-dev-postgres://localhost/application
log_level: debug
shared_key: from-application"
echo ""

echo ""
echo "=== FETCHING CONFIG ==="
echo ""

# Fetch the config and examine the response
echo "Fetching /testapp/dev..."
RESPONSE=$(curl -s $AUTH "$BASE_URL/testapp/dev")
echo "$RESPONSE" | jq .
echo ""

# Verify the response
echo "=== VERIFICATION ==="
echo ""

# Check property sources count (should be 2)
SOURCE_COUNT=$(echo "$RESPONSE" | jq '.propertySources | length')
echo "Property sources count: $SOURCE_COUNT (expected: 2)"
if [ "$SOURCE_COUNT" -eq 2 ]; then
  echo "✓ PASS: Got 2 property sources"
else
  echo "✗ FAIL: Expected 2 property sources, got $SOURCE_COUNT"
fi
echo ""

# Check first source (should be app-specific)
FIRST_SOURCE=$(echo "$RESPONSE" | jq -r '.propertySources[0].name')
echo "First source name: $FIRST_SOURCE"
if echo "$FIRST_SOURCE" | grep -q "app=testapp profile=dev"; then
  echo "✓ PASS: First source is app-specific (testapp-dev)"
else
  echo "✗ FAIL: Expected testapp-dev, got $FIRST_SOURCE"
fi
echo ""

# Check second source (should be application-level)
SECOND_SOURCE=$(echo "$RESPONSE" | jq -r '.propertySources[1].name')
echo "Second source name: $SECOND_SOURCE"
if echo "$SECOND_SOURCE" | grep -q "app=application profile=dev"; then
  echo "✓ PASS: Second source is application-level (application-dev)"
else
  echo "✗ FAIL: Expected application-dev, got $SECOND_SOURCE"
fi
echo ""

# Verify value precedence (shared_key should come from first source)
SHARED_KEY=$(echo "$RESPONSE" | jq -r '.propertySources[0].source.shared_key')
echo "shared_key value: $SHARED_KEY"
if echo "$SHARED_KEY" | grep -q "from-app-specific"; then
  echo "✓ PASS: shared_key from app-specific (highest precedence)"
else
  echo "✗ FAIL: Expected 'from-app-specific', got $SHARED_KEY"
fi
echo ""

# Verify database_url comes from first source
DB_URL=$(echo "$RESPONSE" | jq -r '.propertySources[0].source.database_url')
echo "database_url value: $DB_URL"
if echo "$DB_URL" | grep -q "testapp-dev"; then
  echo "✓ PASS: database_url from app-specific (highest precedence)"
else
  echo "✗ FAIL: Expected testapp-dev, got $DB_URL"
fi
echo ""

# Clean up
echo "--- CLEANUP ---"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=testapp&profile=dev&ext=.yaml"
curl -s $AUTH -X DELETE "$BASE_URL/delete?app=application&profile=dev&ext=.yaml"
echo ""

echo "=== TEST COMPLETE ==="
