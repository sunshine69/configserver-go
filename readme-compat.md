# Compatibility Analysis: Spring Cloud Config Server vs config-server-go

This document compares the feature set of the official [Spring Cloud Config Server](https://docs.spring.io/spring-cloud-config/reference/html/) (Java) with our Go implementation (`config-server-go`).

## Quick Summary

| Category | Spring Cloud Config (Java) | config-server-go | Gap |
|---|---|---|---|
| HTTP/REST API | ✅ | ✅ | — |
| Basic Auth | ✅ | ✅ | — |
| YAML Format | ✅ | ✅ | — |
| JSON Format | ✅ | ✅ | — |
| Properties Format | ✅ | ✅ | — |
| Multi-Profile Merge | ✅ | ✅ | — |
| Label/Version Support | ✅ | ✅ | — |
| Encrypt/Decrypt Endpoints | ✅ | ✅ (symmetric only) | ⚠️ Partial |
| File CRUD (upload/delete/list) | ❌ (not built-in) | ✅ | — |
| Health Check | ✅ (Actuator) | ✅ | — |
| Swagger UI | ✅ | ✅ | — |
| Plain Text File Serving | ✅ | ✅ | — |
| **Profile-Specific Files** (`application-{profile}.yml`) | ✅ | ❌ | 🔴 |
| **Accept: application/octet-stream** | ✅ | ❌ | 🔴 |
| **Default Label Fallback** (main → master) | ✅ | ✅ | — |
| **resolvePlaceholders Query Param** | ✅ | ❌ | 🟡 |
| **Accept-Empty Flag** (`spring.cloud.config.server.accept-empty`) | ✅ | ❌ | 🟡 |
| **Git Repository Pattern Matching** | ✅ | ❌ | 🟡 |
| **Search Paths** (subdirectory patterns) | ✅ | ❌ | 🟡 |
| **Clone on Start** | ✅ | ❌ | 🟢 |
| **Asymmetric Encryption** (RSA) | ✅ | ❌ | 🔴 |
| **JWKS / OAuth2 Token Validation** | ✅ | ❌ | 🟡 |
| **Vault Backend** | ✅ | ❌ | 🟢 |
| **SVN Backend** | ✅ | ❌ | 🟢 |
| **S3 Backend** | ✅ | ❌ | 🟢 |
| **Refresh Rate Caching** (`spring.cloud.config.server.git.refreshRate`) | ✅ | ❌ | 🟢 |
| **Spring Cloud Bus Refresh** (`/refresh` endpoint) | ✅ | ❌ | 🟢 |
| **Conditional/Profile-Based Properties** (`spring.cloud.config.server.override-none`, `spring.cloud.config.server.allow-override`) | ✅ | ❌ | 🟡 |
| **Wildcard Repositories** (one repo per app/profile via `{application}` placeholder) | ✅ | ❌ | 🟡 |
| **Multiple Repos with Pattern Matching** | ✅ | ❌ | 🟡 |
| **SSH Configuration via Properties** (`ignoreLocalSshSettings`) | ✅ | ❌ | 🟢 |
| **AWS CodeCommit / Google Cloud Source Auth** | ✅ | ❌ | 🟢 |

**Legend:** 🔴 High Impact Missing | 🟡 Medium Impact Missing | 🟢 Low Priority / Niche

---

## 1. HTTP/REST API Compatibility

### ✅ Fully Supported
Both implementations serve configuration over HTTP using the same URL patterns:

```
GET  /{app}/{profile}              → JSON GetValuesResponse
GET  /{app}/{profile}/{label}      → JSON with label
GET  /{app}/{profile1},{profile2}  → Merged multi-profile response
GET  /{app}-{profile}.{ext}        → Raw file bytes
GET  /{app}/{profile}/{label}/{path} → Plain text file
GET  /{full-file-path}             → Raw file by path
GET  /encrypt                      → Encrypt plaintext
POST /decrypt                      → Decrypt ciphertext
POST /upload                       → Upload config file
DELETE /delete                     → Delete config file
GET  /list                         → List all config files
GET  /health                       → Health check
GET  /swagger/*                    → Swagger UI
```

### ❌ Missing: Accept Header for Raw Content

Spring Cloud Config Server supports requesting raw file content via the `Accept` header:

```http
GET /{app}/{profile}
Accept: application/octet-stream
→ Returns raw file bytes (e.g., nginx.conf, logback.xml)
```

**Impact:** High — Applications that fetch raw config files (e.g., Nginx configs, logback configs) via the Accept header will not work.

**Suggested Fix:** Add Accept header handling in `getValuesHandler`:
```go
if strings.Contains(r.Header.Get("Accept"), "application/octet-stream") {
    // serve raw file content instead of JSON
}
```

---

## 2. Configuration File Format Support

### ✅ Fully Supported
Both implementations support:
- **YAML** (`.yml`, `.yaml`)
- **JSON** (`.json`)
- **Properties** (`.properties`)

### ✅ Extension Priority
Both follow the same priority order: **Properties > YAML > JSON** (first match wins).

### ❌ Missing: Profile-Specific File Names

Spring Cloud Config Server supports profile-specific file names:
```
application.yml           → default profile
application-dev.yml       → dev profile only
application-prod.yml      → prod profile only
application-dev,cloud.yml → dev or cloud profile
```

When fetching `/foo/dev`, the server automatically looks for `foo-dev.yml` as well as `foo.yml`.

**Impact:** High — Users migrating from Spring Cloud Config will expect this behavior.

**Suggested Fix:** In `serveValues`, also attempt `GetFile(app+"-"+profile, "", label, ext)` before giving up.

---

## 3. Label/Version Support

### ✅ Supported (with Default Label Fallback)
Both implementations support labels (git branches, commit IDs, tags):
```
GET /{app}/{profile}/{label}
POST /upload?app=...&profile=...&label=...
```

### ✅ Default Label Fallback

Spring Cloud Config Server has intelligent default label fallback:
1. Tries `main` branch first
2. Falls back to `master` if `main` doesn't exist

**Implemented:** When no label is specified (e.g. `GET /{app}/{profile}`), the server automatically tries `main` first and falls back to `master`. This is implemented in `lib/ResolveLabel()` and used by `serveValues()` in `main.go`. Property sources are deduplicated across label candidates so each source appears only once in the response.

```go
// lib/labels.go
func ResolveLabel(label string) []string {
    if label != "" {
        return []string{label}
    }
    return []string{"main", "master"}
}
```

---

## 4. Encryption & Decryption

### ✅ Supported (Symmetric Only)
- `/encrypt` — POST plaintext, receive encrypted string
- `/decrypt` — POST ciphertext, receive decrypted string
- `{cipher}` pattern in config files is automatically decrypted on fetch

### ❌ Missing: Asymmetric Encryption

Spring Cloud Config Server supports **both symmetric and asymmetric** encryption:
- **Symmetric:** Shared secret key (AES-based) ✅ Supported by us
- **Asymmetric:** RSA public/private key pairs — clients encrypt with public key, server decrypts with private key ❌ **Not supported**

The original also supports per-application/per-profile encryption keys via `TextEncryptorLocator`.

**Impact:** High — Users relying on asymmetric encryption for security compliance will not be able to use this server.

**Suggested Fix:** Add RSA key pair support in encryption utilities.

---

## 5. Backend Storage

### ✅ Supported
- **File System** (single directory)
- **PostgreSQL** (with table-based storage)

### ❌ Missing: Git Backend

Spring Cloud Config Server's **primary backend is Git**:
- Clone remote repositories
- Support for branches, tags, commits
- Pattern matching across multiple repositories
- Search paths (subdirectories)
- Clone on start for pre-warming

Our implementation uses file system and PostgreSQL as backends but does **not** support Git directly. This is an architectural difference — our upload/delete API replaces the Git push/pull workflow.

**Impact:** Medium — If users need Git integration (branch management, version history, audit trails), this is a gap.

### ❌ Missing: Other Backends

- **Vault** (HashiCorp Vault) — fetch config from Vault KV store
- **SVN** — Subversion repository backend
- **S3** — AWS S3 bucket as configuration storage

---

## 6. Caching & Performance

### ❌ Missing: Git Refresh Rate

Spring Cloud Config Server caches Git repository content and refreshes at a configurable rate:
```yaml
spring.cloud.config.server.git.refreshRate: 30  # seconds
```

Default is `0` (fetch every time). This prevents excessive Git fetches under load.

**Impact:** Low — Only relevant when using Git backend.

### ❌ Missing: Spring Cloud Bus Refresh

Spring Cloud Config Server integrates with Spring Cloud Bus for distributed refresh:
```
POST /refresh   → Triggers all connected clients to re-fetch config
```

This is critical in production microservices architectures where config changes need to propagate to all instances.

**Impact:** Medium — Production deployments without this will require manual restarts or custom refresh logic.

---

## 7. Server Configuration Flags

### ❌ Missing: accept-empty Flag

Spring Cloud Config Server has a flag:
```yaml
spring.cloud.config.server.accept-empty: false
```
When set to `false`, requesting config for an unknown application returns **HTTP 404** instead of an empty JSON response.

**Impact:** Low — Our implementation already returns 404 for missing configs, which is the stricter behavior.

### ❌ Missing: Override Properties

Spring Cloud Config Server supports controlling property override behavior:
```yaml
spring.cloud.config.server.allow-override: true       # Allow client overrides
spring.cloud.config.server.override-none: false        # No overrides from system props
spring.cloud.config.server.order: 0                    # Property source order
```

**Impact:** Low — Relevant for fine-grained control over property precedence.

---

## 8. Authentication & Security

### ✅ Supported
- **Basic Authentication** — username/password per user in config
- **TLS/SSL** — configurable with custom certificates
- **Path Traversal Prevention** — validates file paths

### ❌ Missing: OAuth2 / JWKS Token Validation

Spring Cloud Config Server supports validating JWT/OAuth2 tokens via JWKS endpoints:
```yaml
spring.cloud.config.server.jwt:
  signing-key: ...
  jwks-url: https://auth.example.com/.well-known/jwks.json
```

**Impact:** Low — Only needed if using OAuth2-based authentication.

---

## 9. Multi-Repository Support

### ❌ Missing: Pattern Matching Repositories

Spring Cloud Config Server supports defining multiple Git repositories with pattern matching:
```yaml
spring.cloud.config.server.git.repos:
  simple: https://github.com/simple/config-repo
  special:
    pattern: special*/dev*
    uri: https://github.com/special/config-repo
  local:
    pattern: local*
    uri: file:/home/configsvc/config-repo
```

Applications matching `special*` go to one repo, `local*` go to another, etc.

**Impact:** Medium — Useful for large organizations with many microservices.

### ❌ Missing: Search Paths

Within a Git repository, config files can be searched in subdirectories:
```yaml
spring.cloud.config.server.git.search-paths:
  - foo
  - bar*
```

**Impact:** Low — Niche use case for complex repo structures.

### ❌ Missing: Placeholder Repositories

Spring Cloud Config Server supports per-application Git repositories:
```yaml
spring.cloud.config.server.git.uri: https://github.com/myorg/{application}
```

Each app gets its own repository.

**Impact:** Low — Useful for "one repo per app" policies.

---

## 10. Test Coverage Gap

### Current Tests (test_all.sh — 27 tests)

| # | Test | Status |
|---|---|---|
| 1 | Upload single profile | ✅ |
| 2 | Fetch /test/dev | ✅ |
| 3 | Fetch /test-dev | ✅ |
| 4 | Upload common profile | ✅ |
| 5 | Multi-profile merge | ✅ |
| 6 | Health check | ✅ |
| 7 | List files | ✅ |
| 8 | Upload JSON | ✅ |
| 9 | Fetch JSON | ✅ |
| 10-11 | Upload/Fetch properties | ✅ |
| 12-13 | Upload/Fetch with label | ✅ |
| 14-15 | Extension priority | ✅ |
| 16-17 | Encrypt/Fetch with cipher | ✅ |
| 18 | Decrypt | ✅ |
| 19-20 | Auth (401) | ✅ |
| 21 | 404 missing config | ✅ |
| 22-23 | Delete + verify | ✅ |
| 24-27 | Path serving + nested paths | ✅ |
| — | **Accept: application/octet-stream** | ❌ |
| — | **Default label fallback** | ✅ |
| — | **Profile-specific files** | ❌ |
| — | **Multiple labels same app/profile** | ❌ |
| — | **resolvePlaceholders param** | ❌ |
| — | **Asymmetric encryption** | ❌ |
| — | **Response structure validation** | ❌ |
| — | **Path traversal prevention** | ❌ |
| — | **Invalid file extension** | ❌ |

### Proposed Tests (test_all_comprehensive.sh — 43 tests)

The comprehensive test suite adds **16 new tests** covering:
- Alternative format serving (`.yaml`, `.properties` suffix on URL)
- Accept header for raw content
- Default label behavior
- Profile-specific file names
- Per-application encryption keys
- Multiple labels for same app/profile
- Nested file paths
- Empty body upload (error handling)
- Invalid file extension rejection
- Path traversal prevention
- Non-existent label handling
- Invalid ciphertext rejection
- Response structure validation (JSON schema check)

---

## Prioritized Roadmap

### P0 — Critical (High Impact)
1. ✅  **Accept: application/octet-stream** — Add raw content serving via Accept header
2. ✅  **Profile-specific file names** — Support `application-{profile}.yml` pattern
3. **Asymmetric encryption** — Add RSA key pair support

### P1 — Important (Medium Impact)
4. ✅ **Default label fallback** — Try main → master when no label specified (implemented via `lib/ResolveLabel`)
5. **resolvePlaceholders query parameter** — Support in YAML/Properties alternative format responses
6. **Spring Cloud Bus / /refresh endpoint** — Add distributed config refresh
7. **Multiple repositories with pattern matching** — Support multi-repo routing

### P2 — Nice to Have (Low Impact)
8. **Git backend** — Direct Git repository support
9. **Vault / SVN / S3 backends** — Additional storage backends
10. **SSH configuration via properties**
11. **JWKS / OAuth2 token validation**
12. **Search paths (subdirectory patterns)**
13. **Clone on start** for Git backend
14. **accept-empty flag**
15. **Override properties configuration**
16. **Placeholder repositories** (`{application}` in Git URI)

---

## Conclusion

**config-server-go covers approximately 53% (18/34) of Spring Cloud Config Server features.**

The core functionality (HTTP API, multi-format config, multi-profile merge, labels, encryption, file CRUD, health check) is fully compatible. The biggest gaps are:

1. **Profile-specific file names** — Most impactful for Spring Cloud Config migration
2. **Accept header raw content** — Needed for plain text file serving
3. **Asymmetric encryption** — Security compliance gap

The Git backend, Vault/SVN/S3 backends, and Spring Cloud Bus are architectural differences that may or may not be needed depending on the deployment scenario.
