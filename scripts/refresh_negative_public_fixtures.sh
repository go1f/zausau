#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR="${TMPDIR:-/tmp}/senscan-negative-public"
NEG_DIR="$ROOT_DIR/testdata/datasets/negative"

rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR" "$NEG_DIR"

git clone --depth 1 https://github.com/Yelp/detect-secrets.git "$WORK_DIR/detect-secrets"
git clone --depth 1 https://github.com/zricethezav/gitleaks.git "$WORK_DIR/gitleaks"

cp "$WORK_DIR/detect-secrets/test_data/files/file_with_no_secrets.py" "$NEG_DIR/public_detect_secrets_file_with_no_secrets.py"
cp "$WORK_DIR/detect-secrets/test_data/only_comments.yaml" "$NEG_DIR/public_detect_secrets_only_comments.yaml"
cp "$WORK_DIR/detect-secrets/test_data/config.md" "$NEG_DIR/public_detect_secrets_config.md"
cp "$WORK_DIR/detect-secrets/test_data/sample.diff" "$NEG_DIR/public_detect_secrets_sample.diff"
cp "$WORK_DIR/gitleaks/testdata/config/simple.toml" "$NEG_DIR/public_gitleaks_simple.toml"

echo "refreshed public negative fixtures under $NEG_DIR"
