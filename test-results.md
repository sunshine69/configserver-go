# config-server-go — Test Results

## Environment

- **Server**: Docker container on `http://localhost:7777`
- **Backend**: PostgreSQL (`user2` configured with `connection_string`)
- **Auth**: Basic Auth (`user2:changeme`, `user1:changeme`)
- **Date**: 2026-07-15

---

## Test Summary

| # | Feature | Expected | Result | Status |
|---|---------|----------|--------|--------|
| 1 | Upload YAML single profile | 200 OK + JSON response | 200 OK | ✅ PASS |
| 2 | Fetch `/test/dev` | GetValuesResponse with YAML data | Correct JSON with flat keys | ✅ PASS |
| 3 | Fetch `/test-dev` (single segment) | Same as /test/dev | Identical response | ✅ PASS |
| 4 | Upload second profile (common) | 200 OK | 200 OK | ✅ PASS |
| 5 | Multi-profile merge `/test/dev,common` | Merged JSON, common overrides dev | `database_url` overridden correctly | ✅ PASS |
| 6 | Health check `/health` | Returns checks array | Backend UP | ✅ PASS |
| 7 | List files `/list` | Array of file metadata | All files listed | ✅ PASS |
| 8 | Upload JSON file | 200 OK | 200 OK | ✅ PASS |
| 9 | Fetch JSON `/myapp/prod` | Flattened nested JSON | `server.host`, `server.port` | ✅ PASS |
| 10 | Upload properties file | 200 OK | 200 OK | ✅ PASS |
| 11 | Fetch properties `/propsapp/default` | Key=value pairs | `spring.datasource.url` | ✅ PASS |
| 12 | Upload with label | 200 OK with label | Label "main" stored | ✅ PASS |
| 13 | Fetch with label `/labelapp/dev/main` | GetValuesResponse with label | Label "main" in response | ✅ PASS |
| 14–15 | Extension priority | `.properties` wins over `.yaml` | `source=from-properties` | ✅ PASS |
| 16 | Encrypt value | Ciphertext returned | Base64 ciphertext | ✅ PASS |
| 17 | Cipher decryption at fetch time | `{cipher}` value decrypted | Decrypted correctly | ✅ PASS |
| 18 | Decrypt value | Plaintext returned | `my-secret-password` | ✅ PASS |
| 19 | Wrong password (401) | HTTP 401 | 401 Unauthorized | ✅ PASS |
| 20 | Unknown user (401) | HTTP 401 | 401 Unauthorized | ✅ PASS |
| 21 | Nonexistent config (404) | HTTP 404 | 404 Not Found | ✅ PASS |
| 22 | Delete file | 200 OK confirmation | File deleted | ✅ PASS |
| 23 | Verify deleted file | HTTP 404 on fetch | 404 Not Found | ✅ PASS |
| 24 | Swagger UI | HTTP 200 | 200 OK | ✅ PASS |
| 25 | Raw file upload + retrieval | `GET /{app}-{profile}.{ext}` returns raw content | Raw YAML returned | ✅ PASS |
| 26 | Placeholder resolution | `${VAR}` resolved to env value | Environment variable substituted | ✅ PASS |
| 27 | Binary file serving | `Accept: application/octet-stream` returns raw bytes | Content-Type: application/octet-stream | ✅ PASS |
| 28 | Multi-segment path | `GET /{app}/{profile}/{label}/{path}` returns raw file | Raw file content | ✅ PASS |
| 29 | Alternative format .yaml | Fetch as .yaml | Raw YAML returned | ✅ PASS |
| 30 | Alternative format .properties | Fetch as .properties | Raw properties returned | ✅ PASS |
| 31 | Accept Header | application/octet-stream | Raw content served | ✅ PASS |
| 32 | resolvePlaceholders parameter | Query parameter support | Placeholder resolved | ✅ PASS |
| 33 | Default label behavior | Fetch without label | Default label used | ✅ PASS |
| 34 | Profile-specific file names | Fetch /altformat/prod | Profile-specific config | ✅ PASS |
| 35 | Per-application encryption | Fetch /pathapp/prod | Cipher decrypted | ✅ PASS |
| 36 | Nested file path in URL | GET /app/nested/config.json | Raw JSON returned | ✅ PASS |
| 37 | Multiple labels | /labeltest/dev/main vs /labeltest/dev/feature | Different content per label | ✅ PASS |
| 38 | Empty body upload | Error handling | HTTP 400 | ✅ PASS |
| 39 | Invalid file extension | Error handling | HTTP 400 | ✅ PASS |
| 40 | Path traversal attempt | Security | HTTP 400 (blocked) | ✅ PASS |
| 41 | Fetch non-existent label | HTTP 404 | 404 Not Found | ✅ PASS |
| 42 | Decrypt invalid ciphertext | HTTP 400 | Error returned | ✅ PASS |
| 43 | Same app/profile, different labels | branch1 vs branch2 | Different content per label | ✅ PASS |
| 44 | Verify response structure | GetValuesResponse format | All required fields present | ✅ PASS |
| 45 | **Hierarchical resolution (application.yml)** | 4 property sources merged | All levels present | ✅ PASS |
| 46 | **Verify override behavior** | Highest precedence wins | myapp-hier overrides all | ✅ PASS |

**Total: 46 tests — 46 PASS**

---

## Hierarchical Property Source Resolution (TEST 44-46)

### Test 44: Upload 4 hierarchy levels

```bash
# Upload application.yaml (lowest priority, base config)
POST /upload?app=application&profile=&ext=.yaml
Body: level: 1
      database_url: global-postgres://localhost/global
      log_level: warn
      shared: from-application

# Upload application-hier.yaml (profile-specific base)
POST /upload?app=application&profile=hier&ext=.yaml
Body: level: 2
      database_url: profile-specific-postgres://localhost/profile
      log_level: info
      shared: from-application-hier

# Upload myapp.yaml (app-specific)
POST /upload?app=myapp&profile=&ext=.yaml
Body: level: 3
      database_url: app-specific-postgres://localhost/app
      log_level: debug
      shared: from-myapp

# Upload myapp-hier.yaml (highest priority, app + profile)
POST /upload?app=myapp&profile=hier&ext=.yaml
Body: level: 4
      database_url: app-profile-specific-postgres://localhost/app-profile
      log_level: trace
      shared: from-myapp-hier
```

### Test 45: Verify 4 property sources

```bash
GET /myapp/hier

Response:
{
  "name": "myapp",
  "profiles": ["hier"],
  "propertySources": [
    {
      "name": "postgres:config_server_files app=myapp profile=hier label= ext=.yaml",
      "source": {
        "database_url": "app-profile-specific-postgres://localhost/app-profile",
        "log_level": "trace",
        "shared": "from-myapp-hier",
        "level": "4"
      }
    },
    {
      "name": "postgres:config_server_files app=myapp profile= label= ext=.yaml",
      "source": {
        "database_url": "app-specific-postgres://localhost/app",
        "log_level": "debug",
        "shared": "from-myapp",
        "level": "3"
      }
    },
    {
      "name": "postgres:config_server_files app=application profile=hier label= ext=.yaml",
      "source": {
        "database_url": "profile-specific-postgres://localhost/profile",
        "log_level": "info",
        "shared": "from-application-hier",
        "level": "2"
      }
    },
    {
      "name": "postgres:config_server_files app=application profile= label= ext=.yaml",
      "source": {
        "database_url": "global-postgres://localhost/global",
        "log_level": "warn",
        "shared": "from-application",
        "level": "1"
      }
    }
  ]
}
```

### Test 46: Verify override behavior

✅ **Highest precedence source (myapp-hier) wins for all overridden keys:**
- `database_url` = "app-profile-specific-postgres://localhost/app-profile" (from myapp-hier)
- `log_level` = "trace" (from myapp-hier)
- `shared` = "from-myapp-hier" (from myapp-hier)

✅ **All 4 property sources present in correct order:**
1. `app=myapp profile=hier` (highest priority)
2. `app=myapp profile=`
3. `app=application profile=hier`
4. `app=application profile=` (lowest priority)

---

## Detailed Test Output

### TEST 1-24: Standard Features
*(See previous test results for detailed output)*

### TEST 44-46: Hierarchical Resolution (NEW)

#### TEST 44: Upload hierarchy files
```
Uploaded application.yaml (app=application, profile=)
Uploaded application-hier.yaml (app=application, profile=hier)
Uploaded myapp.yaml (app=myapp, profile=)
Uploaded myapp-hier.yaml (app=myapp, profile=hier)

Fetching /myapp/hier - should merge all 4 files in precedence order:
{
  "name": "myapp",
  "profiles": ["hier"],
  "label": null,
  "version": null,
  "state": null,
  "propertySources": [
    {
      "name": "postgres:config_server_files app=myapp profile=hier label= ext=.yaml",
      "source": {
        "database_url": "app-profile-specific-postgres://localhost/app-profile",
        "log_level": "trace",
        "level": "4",
        "shared": "from-myapp-hier"
      }
    },
    {
      "name": "postgres:config_server_files app=myapp profile= label= ext=.yaml",
      "source": {
        "database_url": "app-specific-postgres://localhost/app",
        "log_level": "debug",
        "level": "3",
        "shared": "from-myapp"
      }
    },
    {
      "name": "postgres:config_server_files app=application profile=hier label= ext=.yaml",
      "source": {
        "database_url": "profile-specific-postgres://localhost/profile",
        "log_level": "info",
        "level": "2",
        "shared": "from-application-hier"
      }
    },
    {
      "name": "postgres:config_server_files app=application profile= label= ext=.yaml",
      "source": {
        "database_url": "global-postgres://localhost/global",
        "log_level": "warn",
        "level": "1",
        "shared": "from-application"
      }
    }
  ]
}
```

#### TEST 45: Verify all levels present
```
Property sources count: 4 (expected: 4)
✓ PASS: Got 4 property sources

Highest precedence source: postgres:config_server_files app=myapp profile=hier label= ext=.yaml
✓ PASS: Highest precedence is myapp-hier

database_url value: app-profile-specific-postgres://localhost/app-profile
✓ PASS: database_url from myapp-hier (highest precedence)

All property sources:
postgres:config_server_files app=myapp profile=hier label= ext=.yaml
postgres:config_server_files app=myapp profile= label= ext=.yaml
postgres:config_server_files app=application profile=hier label= ext=.yaml
postgres:config_server_files app=application profile= label= ext=.yaml

✓ PASS: application.yaml (base) present
✓ PASS: application-hier.yaml present
✓ PASS: myapp.yaml (base) present
✓ PASS: myapp-hier.yaml present
```

#### TEST 46: Verify override behavior
```
log_level from highest precedence: trace
✓ PASS: log_level correctly overridden by myapp-hier

shared from highest precedence: from-myapp-hier
✓ PASS: shared correctly overridden by myapp-hier
```

---

## Known Behaviors

| Behavior | Details |
|----------|---------|
| Health DB check | Skipped when no user has a DSN configured |
| Property source name | Returns individual sources per profile with backend-specific naming |
| Version/State | Always `null` — Git version and state not tracked in filesystem backend |
| Raw file retrieval | `GET /{app}-{profile}.{ext}` returns raw file content |
| Placeholder resolution | `${VAR}` resolved using environment variables |
| Binary serving | `Accept: application/octet-stream` header triggers raw content serving |
| **Hierarchical resolution** | **application.yml < application-{profile}.yml < {app}.yml < {app}-{profile}.yml** |
| **Empty profile support** | **Upload handler accepts empty profile for base-level files** |

---

## Code Changes Applied During Testing

1. **Extension priority fixed**: `supportedConfigFileType` reordered from `json, yaml, yml, properties` → `properties, yml, yaml, json`
2. **Health handler registered**: Added `mux.HandleFunc("GET /health", a.healthHandler)` to HTTP mux
3. **Upload Swagger docs fixed**: Changed from path parameters to query parameters in annotations
4. **Property source naming**: Returns individual sources per profile with backend-specific naming
5. **Extension priority in fetch**: Only first matching extension is used (not all extensions merged)
6. **Raw file retrieval fixed**: `GET /{app}-{profile}.{ext}` now returns raw content instead of always returning JSON
7. **Placeholder resolution added**: `lib.ResolvePlaceholders()` function resolves `${VAR}` syntax using environment variables
8. **Accept header support added**: Checks `Accept: application/octet-stream` to serve raw content for binary files
9. **Multi-segment path support added**: `pathsLen > 3` case handles `/{app}/{profile}/{label}/{path}` format
10. **Hierarchical resolution implemented**: `serveValues` now fetches all 4 hierarchy levels in correct precedence order
11. **Upload handler fixed**: Allows empty profile parameter for base-level files (`application.yml`, `{app}.yml`)
12. **Delete handler fixed**: Allows deletion of files with empty profiles

---

## Spec Compliance Summary

| Spec | Feature | Status |
|------|---------|--------|
| **1** | Structured REST endpoint (`/{app}/{profile}` → JSON) | ✅ FULLY SUPPORTED |
| **2** | Backend processing (placeholders, decryption, JSON response) | ✅ FULLY SUPPORTED |
| **3** | Raw file endpoints (plain-text, binary) | ✅ FULLY SUPPORTED |
| **4** | **Hierarchical property source resolution** | ✅ FULLY SUPPORTED |
| **5** | **Multi-profile merge** | ✅ FULLY SUPPORTED |
| **6** | **Extension priority** | ✅ FULLY SUPPORTED |
| **7** | **Label support** | ✅ FULLY SUPPORTED |

**All 7 specs fully implemented and tested.**

---

## Features Tested

- ✓ Single profile upload/fetch
- ✓ Multi-profile merge
- ✓ JSON format
- ✓ YAML format
- ✓ Properties format
- ✓ Label support
- ✓ Extension priority
- ✓ Encryption/Decryption
- ✓ Cipher pattern decryption
- ✓ Authentication (401 errors)
- ✓ File not found (404)
- ✓ File deletion
- ✓ Path serving
- ✓ Nested paths
- ✓ Alternative format serving (.yaml, .properties)
- ✓ Accept header (application/octet-stream)
- ✓ resolvePlaceholders parameter
- ✓ Default label behavior
- ✓ Profile-specific files
- ✓ Per-application encryption
- ✓ Multiple labels
- ✓ Error handling
- ✓ Security (path traversal prevention)
- ✓ Response structure validation
- ✓ **Hierarchical property source resolution (application.yml, application-{profile}.yml, {app}.yml, {app}-{profile}.yml)**
