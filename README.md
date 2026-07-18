# config-server-go

A **Spring Cloud Config Server** compatible configuration server written in Go. Store and serve application configuration as JSON, YAML, or properties files through a REST API.

Built for reliability and performance, this server supports multiple backends (PostgreSQL and filesystem), hierarchical configuration resolution, encryption, and multi-profile merging — all with full Spring Cloud Config protocol compatibility.

---

## Features

| Feature | Status | Description |
|---------|--------|-------------|
| Structured REST endpoints | ✅ | JSON responses with `GetValuesResponse` format |
| Multi-profile merge | ✅ | `profile=dev,common` merges both profiles |
| Hierarchical resolution | ✅ | 4-level: application → application-{profile} → {app} → {app}-{profile} |
| Format support | ✅ | YAML, JSON, Properties — with extension priority |
| Label support | ✅ | `/{app}/{profile}/{label}` for branch/versioning |
| Encryption/Decryption | ✅ | Ciphertext stored, decrypted at fetch time |
| Placeholder resolution | ✅ | `${VAR}` resolved from environment variables |
| Raw file serving | ✅ | `GET /{app}-{profile}.{ext}` returns raw bytes |
| Binary file serving | ✅ | `Accept: application/octet-stream` support |
| Authentication | ✅ | Basic Auth per user with isolated backends |
| Health check | ✅ | `GET /health` with backend status |
| File listing | ✅ | `GET /list` returns all config files |
| File upload/delete | ✅ | Manage configs via `POST /upload` and `DELETE /delete` |
| Swagger UI | ✅ | Interactive API documentation at `/swagger` |
| Path serving | ✅ | Serve files from arbitrary paths via `CONFIGSERVER_FILEPATH` |
| Multi-backend | ✅ | PostgreSQL and filesystem backends |

---

## Quick Start

### 1. Start the services

```bash
# Build and start
docker compose up -d --build

# Verify it's running
curl http://localhost:7777/health
```

### 2. Upload configuration

```bash
# Upload app config
curl -u user2:changeme \
  -X POST "http://localhost:7777/upload?app=myapp&profile=dev&ext=.yaml" \
  -d 'server.port: 8080
spring.datasource.url: jdbc:mysql://localhost:3306/mydb'

# Fetch config
curl -u user2:changeme http://localhost:7777/myapp/dev
```

### 3. Run the test suite

```bash
./test_all_comprehensive.sh
```

---

## API Reference

### Fetch Configuration

#### Single Profile

```bash
# JSON response with property sources
GET http://localhost:7777/myapp/dev

# Response:
# {
#   "name": "myapp",
#   "profiles": ["dev"],
#   "propertySources": [ ... ]
# }
```

#### Multiple Profiles (Merged)

```bash
# Comma-separated profiles — merged in order
GET http://localhost:7777/myapp/dev,common

# Profile order: dev (lowest), common (highest)
# Common values override dev values
```

#### With Label (Branch/Version)

```bash
GET http://localhost:7777/myapp/dev/main

# Label "main" is used when fetching from the backend
```

#### Raw File

```bash
# Returns raw file content
GET http://localhost:7777/myapp-dev.yaml

# Or via Accept header for multi-segment paths
GET http://localhost:7777/myapp/dev
Accept: application/octet-stream
```

---

### Upload Configuration

```bash
# Upload YAML (default extension)
curl -u user2:changeme \
  -X POST "http://localhost:7777/upload?app=myapp&profile=prod&ext=.yaml" \
  -d 'server.port: 8443
logging.level.root: WARN'

# Upload JSON
curl -u user2:changeme \
  -X POST "http://localhost:7777/upload?app=myapp&profile=dev&ext=.json" \
  -d '{"server":{"port":8080},"spring":{"datasource":{"url":"jdbc:mysql://localhost/mydb"}}}'

# Upload properties
curl -u user2:changeme \
  -X POST "http://localhost:7777/upload?app=myapp&profile=dev&ext=.properties" \
  -d 'server.port=8080
spring.datasource.url=jdbc:mysql://localhost/mydb'

# Upload with label
curl -u user2:changeme \
  -X POST "http://localhost:7777/upload?app=myapp&profile=dev&label=main&ext=.yaml" \
  -d 'server.port: 9090'
```

### Delete Configuration

```bash
curl -u user2:changeme -X DELETE \
  "http://localhost:7777/delete?app=myapp&profile=dev&ext=.yaml"
```

### List All Files

```bash
curl -u user2:changeme http://localhost:7777/list
```

### Encrypt / Decrypt

```bash
# Encrypt a value
curl -u user2:changeme \
  -X POST "http://localhost:7777/encrypt" \
  -d 'my-secret-password'
# Response: c8587d34661b484d20d7a9e05d42779f0718c074f3b4f948a98e1a47e746e7a2

# Store with encrypted value in config
# In your YAML: password: ${cipher}c8587d34661b484d20d7a9e05d42779f0718c074f3b4f948a98e1a47e746e7a2
# It will be decrypted automatically when fetched

# Decrypt a value
curl -u user2:changeme \
  -X POST "http://localhost:7777/decrypt" \
  -d 'c8587d34661b484d20d7a9e05d42779f0718c074f3b4f948a98e1a47e746e7a2'
# Response: my-secret-password
```

### Health Check

```bash
curl http://localhost:7777/health
# Response:
# {
#   "status": "UP",
#   "checks": [
#     { "name": "backend", "status": "UP" },
#     { "name": "database", "status": "UP" }
#   ]
# }
```

### Swagger UI

```bash
open http://localhost:7777/swagger/index.html
```

---

## Hierarchical Property Source Resolution

The server follows **Spring Cloud Config Server**'s 4-level hierarchical configuration model. When you request `/myapp/hier`, it resolves files in this order (lowest to highest precedence):

```
1. application.yaml              → Base config shared by ALL apps
2. application-hier.yaml         → Profile-specific base config
3. myapp.yaml                    → App-specific config
4. myapp-hier.yaml               → App + profile specific (highest priority)
```

Higher-precedence values override lower ones. The response returns all 4 levels in the `propertySources` array with highest priority first.

### Example

```bash
# Upload shared base config
curl -u user2:changeme \
  -X POST "http://localhost:7777/upload?app=application&profile=&ext=.yaml" \
  -d 'spring.datasource.driver-class-name: com.mysql.cj.jdbc.Driver
logging.level.root: INFO'

# Upload shared profile config
curl -u user2:changeme \
  -X POST "http://localhost:7777/upload?app=application&profile=prod&ext=.yaml" \
  -d 'spring.datasource.url: jdbc:mysql://prod-server:3306/mydb
logging.level.root: WARN'

# Upload app-specific config
curl -u user2:changeme \
  -X POST "http://localhost:7777/upload?app=foo&profile=&ext=.yaml" \
  -d 'server.port: 8080'

# Upload app + profile config
curl -u user2:changeme \
  -X POST "http://localhost:7777/upload?app=foo&profile=prod&ext=.yaml" \
  -d 'server.port: 8443'

# Fetch — returns all 4 sources merged
curl -u user2:changeme http://localhost:7777/foo/prod
```

Response includes 4 property sources in precedence order:
1. `foo-prod.yaml` (highest priority)
2. `foo.yaml`
3. `application-prod.yaml`
4. `application.yaml` (lowest priority)

---

## Configuration

### config.yaml

```yaml
server:
  port: 7777
  ssl:
    enable: false
    key: /path/to/private/keyfile
    cert: /path/to/certfile
  users:
    # Filesystem backend user
    - username: user1
      password: changeme
      encryption_key: mySecretKey123
      directory: /data/config/user1
      backend: filesystem

    # PostgreSQL backend user
    - username: user2
      password: changeme
      encryption_key: mySecretKey456
      backend: postgres

backend_config:
  filesystem:
    directories:
      - /data/config/user1

  postgres:
    default_connection_string: "postgres://${DATABASE_USER}:${DATABASE_PASSWORD}@${DATABASE_HOST}:${DATABASE_PORT:-5432}/${DATABASE_NAME}?sslmode=disable"
```

### Environment Variables

The config file supports `${VAR}` expansion for sensitive values. Set these in `.env` or the environment:

| Variable | Default | Description |
|----------|---------|-------------|
| `CONFIG_FILE` | `config.yaml` | Config file path |
| `DATABASE_HOST` | `postgres` | PostgreSQL host |
| `DATABASE_PORT` | `5432` | PostgreSQL port |
| `DATABASE_USER` | `configuser` | PostgreSQL user |
| `DATABASE_PASSWORD` | `configpass` | PostgreSQL password |
| `DATABASE_NAME` | `configdb` | PostgreSQL database |

### SSL Configuration

Enable HTTPS by setting `server.ssl.enable: true` and providing key/cert paths. The server uses TLS 1.2+ with strong cipher suites.

---

## Backend Architecture

### PostgreSQL Backend

Configs are stored in a PostgreSQL database. Each user can have their own backend with isolation.

```sql
-- Auto-created migration table
CREATE TABLE IF NOT EXISTS config_server_files (
  username TEXT,
  app TEXT,
  profile TEXT,
  label TEXT,
  ext TEXT,
  content BYTEA,
  path TEXT,
  updated_at TIMESTAMPTZ,
  PRIMARY KEY (username, app, profile, label, ext)
);
```

### Filesystem Backend

Configs are stored on disk in the user's configured directory:

```
/data/config/user1/
  ├── myapp-dev.yaml
  ├── myapp-prod.yaml
  └── foo.json
```

### Backend Resolver

The server resolves backends per user at runtime. Switching backends is done by changing the user's `backend` field in `config.yaml` — no code changes needed.

---

## Extension Priority

When fetching config, files are resolved in this priority order (highest first):

| Extension | Priority | Description |
|-----------|----------|-------------|
| `.properties` | 1 (highest) | Java properties format |
| `.yml` | 2 | YAML short form |
| `.yaml` | 3 | YAML standard form |
| `.json` | 4 (lowest) | JSON format |

If multiple extensions exist for the same app/profile, only the highest-priority file is used.

---

## Security

- **Authentication**: Basic Auth per user. Invalid credentials return 401.
- **Path traversal prevention**: All app/profile/label segments validated (alphanumeric, hyphens, underscores only).
- **Isolation**: Each user's configs are stored separately and never cross-accessible.
- **SSL/TLS**: TLS 1.2+ with strong cipher suites for production deployments.
- **Encryption**: Values can be encrypted before storage and decrypted at fetch time using per-user keys.

---

## Testing

### Comprehensive Test Suite

Run the full test suite covering all features:

```bash
./test_all_comprehensive.sh
```

**46 tests covering:**
- REST API endpoints (upload, fetch, delete, list)
- Multi-profile merging
- Format support (YAML, JSON, properties)
- Label support
- Encryption/decryption
- Placeholder resolution
- Raw file serving
- Binary file serving
- Path traversal prevention
- Hierarchical property source resolution
- Response structure validation

### Unit Tests

```bash
go test ./...
```

---

## Project Structure

```
├── main.go              # Server entry point, handlers, Swagger annotations
├── config.yaml          # Sample configuration
├── docker-compose.yml   # Docker services (app + PostgreSQL)
├── Dockerfile           # Multi-stage Go build
├── go.mod / go.sum      # Go module dependencies
├── backend/
│   ├── postgres.go      # PostgreSQL backend implementation
│   └── gitbackend.go    # Git backend (stub)
├── lib/
│   ├── config.go        # Config parsing, placeholder resolution
│   └── path_serving.go  # File path serving configuration
├── docs/                # Swagger documentation
├── test_all_comprehensive.sh  # Full test suite
└── test-results.md      # Test results documentation
```

---

## Migration from Spring Cloud Config Server

This server is designed for zero-downtime migration from Spring Cloud Config Server:

- **Same API**: `/foo/dev` → JSON `GetValuesResponse`
- **Same config format**: Upload YAML/JSON/properties the same way
- **Same precedence**: 4-level hierarchical resolution
- **Same auth**: Basic Auth with per-user configuration
- **Same encryption**: Spring Cloud Config cipher pattern supported

---

## License

MIT License — see [LICENSE](LICENSE) for details.
