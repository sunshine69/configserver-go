# Swagger API Documentation

This project uses [swaggo/swag](https://github.com/swaggo/swag) to generate OpenAPI 2.0 (Swagger) documentation and serve it via a built-in Swagger UI.

## What's Been Done

### 1. Swagger Annotations Added

All API handlers in `main.go` now include Swagger annotations (`@Summary`, `@Description`, `@Tags`, `@Param`, `@Success`, `@Failure`, `@Router`, `@Security`) for:

| Method | Path | Tag | Description |
|--------|------|-----|-------------|
| `GET` | `/{app}/{profile}` | Config | Retrieve application configuration |
| `POST` | `/encrypt` | Encryption | Encrypt a plaintext value |
| `POST` | `/decrypt` | Encryption | Decrypt a ciphertext value |
| `POST` | `/upload` | Config | Upload a configuration file |

### 2. Swagger UI Route

Added to the HTTP handler in `main.go`:

```go
mux.Handle("/swagger/*", httpSwagger.Handler(
    httpSwagger.URL("/swagger/doc.json"),
))
```

### 3. Pre-generated Docs

The `docs/` directory contains:
- `docs.go` — Go package imported by the binary (`_ "configservergo/docs"`)
- `swagger.json` — OpenAPI 2.0 specification
- `swagger.yaml` — YAML version of the specification

These files are **committed to the repository** and copied into Docker images at build time — no generation step is needed during Docker builds.

### 4. ErrorResponse Type

Added a standard error response type used across all endpoints:

```go
type ErrorResponse struct {
    Description string `json:"description"`
    Status      string `json:"status"`
}
```

---

## How to Access the Swagger UI

Once the server is running, open your browser to:

```
http://localhost:7777/swagger/index.html
```

The Swagger UI will:
- List all available endpoints grouped by tag
- Show request/response schemas
- Allow you to **click "Try it out"** and test endpoints directly from the browser
- Prompt for **Basic Auth** credentials (username/password from `config.yaml`)

---

## How to Update the Swagger Documentation

When you add, modify, or remove API endpoints, you need to regenerate the Swagger docs.

### Prerequisites

Install the `swag` CLI tool:

```bash
go install github.com/swaggo/swag/cmd/swag@latest
```

Verify the installation:

```bash
swag --version
```

> **Note:** The binary is installed to `~/go/bin/`. If this directory is not in your `PATH`, use the full path:
> ```bash
> ~/go/bin/swag --version
> ```

### Regenerate Docs

From the project root, run:

```bash
swag init -g main.go -o docs --parseDependency
```

This will:
1. Parse all Swagger annotations in `main.go`
2. Generate/overwrite `docs/docs.go`, `docs/swagger.json`, and `docs/swagger.yaml`

### Commit the Changes

After regenerating, commit the updated docs files:

```bash
git add docs/
git commit -m "docs: regenerate swagger documentation"
```

---

## Docker Builds

The `docs/` directory is pre-generated and committed to the repository. Docker builds **do not** run `swag init` — they simply copy the pre-built docs into the image.

### Local Docker Build

```bash
docker build -t configservergo:latest .
```

### Kubernetes Container Build

```bash
docker build -f k8s/Container/configserver-go.Dockerfile -t configservergo:k8s .
```

Both Dockerfiles copy the `docs/` directory into the image so the Swagger UI is available at runtime.

---

## Adding New Endpoints

To add Swagger documentation for a new endpoint, add annotations above the handler function:

```go
// @Summary Brief description
// @Description Detailed description of what the endpoint does.
// @Tags TagName
// @Accept json
// @Produce json
// @Param paramName path string true "Parameter description"
// @Param body body SomeType true "Request body description"
// @Success 200 {object} ResponseType "Success description"
// @Failure 400 {object} ErrorResponse "Bad request"
// @Failure 401 {object} ErrorResponse "Unauthorized"
// @Router /some/path [get]
// @Security BasicAuth
func (a *App) someHandler(w http.ResponseWriter, r *http.Request) {
    // ...
}
```

Then regenerate with `swag init` as described above.

---

## Security Note

All endpoints require **HTTP Basic Authentication**. The Swagger UI will prompt for credentials when you click "Try it out". Configure users in `config.yaml` under `server.users`.
