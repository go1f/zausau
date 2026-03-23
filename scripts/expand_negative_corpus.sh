#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
NEG_DIR="$ROOT_DIR/testdata/datasets/negative"

mkdir -p "$NEG_DIR"

cat > "$NEG_DIR/generated_near_miss_matrix.txt" <<'EOF'
password_policy=At least 12 chars and one symbol.
secret_label=Shown to users in the settings page.
token_description=Placeholder displayed before configuration.
api_key_hint=Copy the key from the admin console.
access_key_notes=Use a read-only demo key during onboarding.
private_key_format=PEM-encoded blocks start with BEGIN and END markers.
cookie_domain=example.internal
cookie_notice=Session cookies expire after 30 minutes.
session_timeout=30m
session_id_format=uuid-v4
license_sn_help=Shown on the sticker attached to the package.
mobile_number_hint=Use your own contact number in production.
phone_mask_example=138****8000
address_template=No. 1 Example Road, Pudong New Area
location_precision=Coordinates are rounded to 3 decimal places.
latitude_help=North-south coordinate example.
longitude_help=East-west coordinate example.
biometric_notice=Face and fingerprint examples are synthetic and redacted.
face_feature_description=128-dimensional embedding example for docs only.
fingerprint_model_version=v2
browsing_history_retention=30 days
friend_list_export=CSV export is available from the admin page.
gene_panel_description=Demonstration data only, not patient records.
request_id=550e8400-e29b-41d4-a716-446655440000
trace_id=4bf92f3577b34da6a3ce929d0e0e4736
sha1=2fd4e1c67a2d28fced849ee1bb76e7391b93eb12
sha256=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
TOKEN=${TOKEN}
API_KEY=${API_KEY}
SECRET_KEY=<YOUR_SECRET_KEY>
PRIVATE_KEY=REDACTED
EOF

cat > "$NEG_DIR/generated_provider_placeholder_matrix.env" <<'EOF'
OPENAI_API_KEY=${OPENAI_API_KEY}
OPENAI_PROJECT_KEY=<YOUR_OPENAI_PROJECT_KEY>
AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}
GITHUB_TOKEN=<YOUR_GITHUB_TOKEN>
GITLAB_TOKEN=redacted
SLACK_BOT_TOKEN=<YOUR_SLACK_BOT_TOKEN>
SLACK_SIGNING_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
STRIPE_API_KEY=<YOUR_STRIPE_API_KEY>
NPM_TOKEN=${NPM_TOKEN}
DISCORD_BOT_TOKEN=<YOUR_DISCORD_BOT_TOKEN>
SESSION_SECRET=changeme
COOKIE_SECRET=process.env.COOKIE_SECRET
LICENSE_SN=see product packaging
EOF

cat > "$NEG_DIR/generated_docs_snippets.md" <<'EOF'
# Configuration Guide

```env
API_KEY=<YOUR_API_KEY>
TOKEN=${TOKEN}
COOKIE_SECRET=process.env.COOKIE_SECRET
```

```json
{
  "password_policy": "Minimum 12 characters",
  "secret_label": "Shown to workspace admins",
  "phone_example": "138****8000",
  "location_note": "Rounded to city level only"
}
```

```yaml
auth:
  token: "<YOUR_BEARER_TOKEN>"
  session: "${SESSION_ID}"
  cookie: "See browser developer tools"
```
EOF

echo "expanded negative corpus under $NEG_DIR"
