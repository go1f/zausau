#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR="${TMPDIR:-/tmp}/senscan-public-fixtures"

rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"
mkdir -p "$ROOT_DIR/testdata/datasets/public"

git clone --depth 1 https://github.com/trufflesecurity/test_keys.git "$WORK_DIR/test_keys"
git clone --depth 1 https://github.com/Yelp/detect-secrets.git "$WORK_DIR/detect-secrets"
git clone --depth 1 https://github.com/zricethezav/gitleaks.git "$WORK_DIR/gitleaks"

cp "$WORK_DIR/test_keys/keys" "$ROOT_DIR/testdata/datasets/public/trufflesecurity_test_keys_keys.txt"
cp "$WORK_DIR/test_keys/new_key" "$ROOT_DIR/testdata/datasets/public/trufflesecurity_test_keys_new_key.ini"
cp "$WORK_DIR/detect-secrets/test_data/files/private_key" "$ROOT_DIR/testdata/datasets/public/detect_secrets_private_key.txt"
cp "$WORK_DIR/detect-secrets/test_data/each_secret.py" "$ROOT_DIR/testdata/datasets/public/detect_secrets_each_secret.py"
cp "$WORK_DIR/gitleaks/testdata/repos/small/api/ignoreCommit.go" "$ROOT_DIR/testdata/datasets/public/gitleaks_ignoreCommit.go"

echo "public fixtures refreshed under $ROOT_DIR/testdata/datasets/public"
