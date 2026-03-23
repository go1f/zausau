#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
NEG_DIR="$ROOT_DIR/testdata/datasets/negative"

mkdir -p "$NEG_DIR"

curl -fsSL \
  "https://raw.githubusercontent.com/n8n-io/n8n/master/.env.local.example" \
  -o "$NEG_DIR/public_n8n_env_local_example.env"

curl -fsSL \
  "https://raw.githubusercontent.com/fastapi/full-stack-fastapi-template/master/.env" \
  -o "$NEG_DIR/public_fastapi_fullstack_env.example"

curl -fsSL \
  "https://raw.githubusercontent.com/calcom/cal.com/main/.env.example" \
  -o "$NEG_DIR/public_calcom_env_example.env"

curl -fsSL \
  "https://raw.githubusercontent.com/swagger-api/swagger-petstore/master/src/main/resources/openapi.yaml" \
  -o "$NEG_DIR/public_swagger_petstore_openapi.yaml"

curl -fsSL \
  "https://raw.githubusercontent.com/bitnami/charts/main/bitnami/postgresql/values.yaml" \
  -o "$NEG_DIR/public_bitnami_postgresql_values.yaml"

curl -fsSL \
  "https://raw.githubusercontent.com/prometheus-community/helm-charts/main/charts/kube-prometheus-stack/values.yaml" \
  -o "$NEG_DIR/public_prometheus_kube_prometheus_values.yaml"

echo "refreshed real-world public negative fixtures under $NEG_DIR"
