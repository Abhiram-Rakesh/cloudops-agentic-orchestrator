#!/usr/bin/env bash
# Builds the one shared Lambda deployment zip for
# arm64/python3.12, containing only runtime dependencies — moto (and every
# other dev-only dependency) is never installed here, matching the
# rule that moto must never be importable from src/ production code.
#
# VERIFY BEFORE DEPLOY: run this once and confirm `unzip -l dist/lambda.zip`
# looks sane, and that the deployed Lambda cold-starts cleanly, before
# relying on it — this was never actually invoked as a real Lambda here
# (no live AWS account, Hard Rule #1/#2).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$ROOT_DIR/.build/lambda"
DIST_DIR="$ROOT_DIR/dist"
ZIP_PATH="$DIST_DIR/lambda.zip"
MAX_SIZE_MB=240 # exit criterion: bundle < 240 MB

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR" "$DIST_DIR"

echo "==> Exporting runtime (non-dev) dependencies"
uv export --frozen --no-dev --no-emit-project --format requirements.txt \
  -o "$BUILD_DIR/requirements.txt"

echo "==> Installing dependencies for aarch64 / Python 3.12"
uv pip install \
  --target "$BUILD_DIR" \
  --python-platform aarch64-manylinux2014 \
  --python-version 3.12 \
  --only-binary=:all: \
  -r "$BUILD_DIR/requirements.txt"

echo "==> Copying application code and runtime data"
cp -r "$ROOT_DIR/src/cloudops_orchestrator" "$BUILD_DIR/"
cp -r "$ROOT_DIR/config" "$BUILD_DIR/config"
cp -r "$ROOT_DIR/knowledge_base" "$BUILD_DIR/knowledge_base"

echo "==> Removing bytecode caches"
find "$BUILD_DIR" -type d -name "__pycache__" -prune -exec rm -rf {} +
find "$BUILD_DIR" -type f -name "*.pyc" -delete

echo "==> Zipping"
rm -f "$ZIP_PATH"
(cd "$BUILD_DIR" && zip -r -X -9 -q "$ZIP_PATH" .)

SIZE_MB=$(du -m "$ZIP_PATH" | cut -f1)
echo "Built $ZIP_PATH (${SIZE_MB} MB)"
if [ "$SIZE_MB" -gt "$MAX_SIZE_MB" ]; then
  echo "ERROR: lambda.zip is ${SIZE_MB} MB, exceeds the ${MAX_SIZE_MB} MB budget." >&2
  exit 1
fi
