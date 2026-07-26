==============================================
  Config Server Go - Comprehensive Test Suite
==============================================

Server: http://localhost:7777
User1 (filesystem): user1/changeme
User2 (postgres):   user2/changeme
✅ Server is reachable

==============================================
  1. Authentication Tests
==============================================
  ✅ PASS: GET without authentication returns 401 (HTTP 401)
  ✅ PASS: GET with wrong password returns 401 (HTTP 401)
  ✅ PASS: GET with unknown user returns 401 (HTTP 401)
  ✅ PASS: Upload without authentication returns 401 (HTTP 401)
  ✅ PASS: Upload with wrong password returns 401 (HTTP 401)

==============================================
  2. Filesystem Backend - Upload Tests (user1)
==============================================
  ✅ PASS: Upload YAML file (HTTP 200)
  ✅ PASS: Upload JSON file (HTTP 200)
  ✅ PASS: Upload .properties file (HTTP 200)
  ✅ PASS: Upload .yml file (HTTP 200)
  ✅ PASS: Upload with default .yaml extension (HTTP 200)
  ✅ PASS: Upload YAML with label (HTTP 200)
  ✅ PASS: Upload with label 'v2' (HTTP 200)
  ✅ PASS: Upload config with special characters (HTTP 200)
  ✅ PASS: Upload large config (100 keys) (HTTP 200)
  ✅ PASS: Overwrite existing YAML file (HTTP 200)

==============================================
  3. Filesystem Backend - GET Tests (user1)
==============================================
  ✅ PASS: GET existing YAML file (HTTP 200)
  ✅ PASS: GET existing JSON file (HTTP 200)
  ✅ PASS: GET existing .properties file (HTTP 200)
  ✅ PASS: GET existing .yml file (HTTP 200)
  ❌ FAIL: GET YAML with label (expected HTTP 200, got HTTP 404)
       Response: File not found
  ❌ FAIL: GET non-existent file returns 404 (expected HTTP 404, got HTTP 200)
       Response: {"name":"myapp","profiles":["nonexistent.yaml"],"label":"","version":null,"state":null,"propertySources":[{"name":"FileSystemBackend app=myapp profile= label= ext=.yaml","source":{"":"test"}}]}

==============================================
  4. Property Flattening & Content Tests
==============================================
  ❌ FAIL: Response profiles='['dev.yaml']' (expected ['dev'])
  ❌ FAIL: Response label='NONE' (expected 'main')
  ❌ FAIL: propertySources has 2 entries (expected 1)
  ✅ PASS: propertySources[0].source has 5 keys

==============================================
  6. PostgreSQL Backend Tests (user2)
==============================================
  ✅ PASS: Upload YAML to PostgreSQL (HTTP 200)
  ✅ PASS: Upload JSON to PostgreSQL (HTTP 200)
  ✅ PASS: Upload .properties to PostgreSQL (HTTP 200)
  ✅ PASS: Upload YAML with label to PostgreSQL (HTTP 200)
  ✅ PASS: GET YAML from PostgreSQL (HTTP 200)
  ✅ PASS: GET JSON from PostgreSQL (HTTP 200)
  ✅ PASS: GET non-existent from PostgreSQL returns 404 (HTTP 404)
  ✅ PASS: User2 cannot access user1's files (HTTP 404)
  ✅ PASS: User1 cannot access user2's files (HTTP 404)
  ✅ PASS: User2 overwrites its own file (HTTP 200)

==============================================
  7. Encrypt / Decrypt Tests
==============================================
  ✅ PASS: Encrypt returns ciphertext (84 chars)
  ✅ PASS: Decrypt returns original plaintext
  ✅ PASS: Decrypt invalid ciphertext returns 400 (HTTP 400)
  ✅ PASS: Encrypt/decrypt roundtrip with special chars
  ✅ PASS: GET config with {cipher} values auto-decrypts (HTTP 200)

==============================================
  8. Input Validation Tests
==============================================
  ✅ PASS: Upload with invalid extension returns 400 (HTTP 400)
  ✅ PASS: Upload missing app returns 400 (HTTP 400)
  ❌ FAIL: Upload missing profile returns 400 (expected HTTP 400, got HTTP 200)
       Response: {"app":"myapp","description":"File uploaded successfully","ext":".yaml","label":"","profile":"","status":"OK"}
  ✅ PASS: Path traversal in app name returns 400 (HTTP 400)
  ✅ PASS: Path traversal in profile name returns 400 (HTTP 400)
  ✅ PASS: Path traversal in label returns 400 (HTTP 400)
  ❌ FAIL: Spaces in app name returns 400 (expected HTTP 400, got HTTP 000)
  ✅ PASS: Dots in app name returns 400 (HTTP 400)
  ✅ PASS: Commas in profile returns 400 (HTTP 400)

==============================================
  9. Edge Cases
==============================================
  ✅ PASS: Upload empty content returns 200
  ✅ PASS: GET empty content returns 200
  ✅ PASS: Upload deeply nested config
  ✅ PASS: Deep nesting flattened correctly: a.b.c.d.e='deep'
  ✅ PASS: Upload config with list values
  ❌ FAIL: List values not preserved: items='None'
  ✅ PASS: Idempotent upload (same file twice) (HTTP 200)

==============================================
  10. Multiple Format Round-Trip
==============================================
  ✅ PASS: YAML keys present: ['app.debug', 'app.name', 'database.host', 'database.name', 'database.port']
  ✅ PASS: JSON keys present: ['app.debug', 'app.name', 'database.host', 'database.name', 'database.port']
  ✅ PASS: Properties keys present: ['app.debug', 'app.name', 'database.host', 'database.name', 'database.port']

==============================================
  11. Multi-Profile Merge Tests
==============================================
  ✅ PASS: Upload common profile (HTTP 200)
  ✅ PASS: Multi-profile fetch returns 200

==============================================
  12. Health Check & List Tests
==============================================
  ✅ PASS: Health check returns UP
  ✅ PASS: List files returns 200 (HTTP 200)

==============================================
  13. Multi-Password Authentication Tests
==============================================
  ✅ PASS: Add temporary password (HTTP 200)
  ✅ PASS: Add no-expire password (HTTP 200)
  ✅ PASS: List passwords returns 200
  ❌ FAIL: Authenticate with temp password (expected HTTP 200, got HTTP 401)
       Response: Unauthorized
  ❌ FAIL: Authenticate with no-expire password (expected HTTP 200, got HTTP 404)
       Response: Config not found
  ❌ FAIL: Authenticate with main password still works (expected HTTP 200, got HTTP 404)
       Response: Config not found
  ✅ PASS: Duplicate password rejected (HTTP 400)
  ✅ PASS: Missing password field rejected (HTTP 400)
  ✅ PASS: Invalid exp format rejected (HTTP 400)
  ✅ PASS: Delete password by hash (HTTP 200)
  ✅ PASS: Delete nonexistent hash returns 404 (HTTP 404)
  ✅ PASS: Delete missing hash param returns 400 (HTTP 400)
  ✅ PASS: Unauthorized on addpassword returns 401 (HTTP 401)
  ✅ PASS: Unauthorized on listpasswords returns 401 (HTTP 401)
  ✅ PASS: Unauthorized on delpassword returns 401 (HTTP 401)

==============================================
  14. Format-Specific Endpoints (Spring Cloud Config Server)
==============================================
  ❌ FAIL: GET /{app}-{profile}.yml (expected HTTP 200, got HTTP 404)
       Response: File not found
  ✅ PASS: GET /{app}-{profile}.json (HTTP 200)
  ✅ PASS: GET /{app}-{profile}.properties (HTTP 200)
  ❌ FAIL: GET /{label}/{app}-{profile}.yml (expected HTTP 200, got HTTP 404)
       Response: Config not found
  ❌ FAIL: GET /{label}/{app}-{profile}.json (expected HTTP 200, got HTTP 404)
       Response: Config not found
  ❌ FAIL: GET /{label}/{app}-{profile}.properties (expected HTTP 200, got HTTP 404)
       Response: Config not found

==============================================
  15. Swagger UI
==============================================
  ✅ PASS: Swagger UI returns 200 (HTTP 200)

==============================================
  TEST SUMMARY
==============================================

  Total:  85
  Passed: 70
  Failed: 15

  ⚠️  15 TEST(S) FAILED

