#!/usr/bin/env bash
set -euo pipefail

# update-swagger.sh
# Regenerates Swagger/OpenAPI documentation for the Config Server Go API.
#
# Prerequisites:
#   go install github.com/swaggo/swag/cmd/swag@latest
#
# Usage:
#   ./update-swagger.sh
#
# What it does:
#   1. Checks that the swag CLI is available.
#   2. Runs swag init to regenerate docs/docs.go, docs/swagger.json, docs/swagger.yaml.
#   3. Prints a summary of what changed.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# --- Resolve swag binary ---
# Try common locations where go install places the binary.
SWAG_BIN=""
for candidate in \
    "$HOME/go/bin/swag" \
    "$(go env GOPATH)/bin/swag" \
    "$(which swag 2>/dev/null)"; do
    if [[ -x "$candidate" ]]; then
        SWAG_BIN="$candidate"
        break
    fi
done

if [[ -z "$SWAG_BIN" ]]; then
    echo "❌ swag CLI not found. Install it with:"
    echo ""
    echo "    go install github.com/swaggo/swag/cmd/swag@latest"
    echo ""
    echo "Then ensure $(go env GOPATH)/bin is in your PATH."
    exit 1
fi

echo "📖 Using swag: $SWAG_BIN"
echo "📖 Regenerating Swagger docs..."
echo ""

# Run swag init
"$SWAG_BIN" init -g main.go -o docs --parseDependency 2>&1

echo ""
echo "✅ Swagger docs regenerated:"
echo "   - docs/docs.go"
echo "   - docs/swagger.json"
echo "   - docs/swagger.yaml"
echo ""
echo "📋 Commit the changes:"
echo "   git add docs/"
echo "   git commit -m \"docs: regenerate swagger documentation\""
