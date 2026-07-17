# Build stage
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Copy go mod files first for caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -o configservergo .

# Runtime stage
FROM alpine:3.24

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# Copy binary, config, and swagger docs from builder
COPY --from=builder /app/configservergo .
COPY config.yaml .
COPY docs/ ./docs/

# Expose the server port
EXPOSE 7777

# Run the application
# Use --migrate flag to run migrations on startup
CMD ["./configservergo", "--migrate"]
