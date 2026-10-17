#!/usr/bin/env bash
# Deploys Northwind Platform (Org A): Cloud Run, europe-west1, min-instances=0.
# Two-pass: Cloud Run assigns the service URL on first deploy, and that URL
# IS the trust domain (the key-distribution host), so it can't be known
# before the first deploy. Pass 1 deploys without it; pass 2 sets it and
# redeploys — idempotent, safe to re-run either way.
set -euo pipefail

PROJECT="${GCP_PROJECT:?set GCP_PROJECT to the non-production project to use}"
REGION="europe-west1"
SERVICE="northwind-vaid"
SECRET_NAME="northwind-vaid-signing-key"
KEY_ID="northwind-k1"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "== project: $PROJECT, region: $REGION =="
gcloud config set project "$PROJECT" >/dev/null

echo "== enabling required APIs (no-op if already on) =="
gcloud services enable run.googleapis.com secretmanager.googleapis.com \
  firestore.googleapis.com cloudbuild.googleapis.com --project "$PROJECT"

echo "== ensuring Firestore database exists (Native mode, $REGION) =="
if ! gcloud firestore databases describe --database='(default)' --project "$PROJECT" >/dev/null 2>&1; then
  gcloud firestore databases create --location="$REGION" --type=firestore-native --project "$PROJECT"
fi

echo "== ensuring signing key secret exists =="
if ! gcloud secrets describe "$SECRET_NAME" --project "$PROJECT" >/dev/null 2>&1; then
  PRIV_B64="$(python3 -c '
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import base64
k = Ed25519PrivateKey.generate()
raw = k.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())
print(base64.b64encode(raw).decode())
')"
  gcloud secrets create "$SECRET_NAME" --project "$PROJECT" --replication-policy=user-managed --locations="$REGION"
  printf '{"private_key_b64":"%s"}' "$PRIV_B64" | gcloud secrets versions add "$SECRET_NAME" --project "$PROJECT" --data-file=-
fi

RUNTIME_SA="$(gcloud run services describe "$SERVICE" --region "$REGION" --project "$PROJECT" \
  --format='value(spec.template.spec.serviceAccountName)' 2>/dev/null || true)"
if [ -z "$RUNTIME_SA" ]; then
  RUNTIME_SA="$(gcloud projects describe "$PROJECT" --format='value(projectNumber)')-compute@developer.gserviceaccount.com"
fi
gcloud secrets add-iam-policy-binding "$SECRET_NAME" --project "$PROJECT" \
  --member="serviceAccount:$RUNTIME_SA" --role="roles/secretmanager.secretAccessor" >/dev/null

echo "== pass 1: deploy without TRUST_DOMAIN to learn the service URL =="
gcloud run deploy "$SERVICE" --project "$PROJECT" --region "$REGION" \
  --source "$HERE" \
  --allow-unauthenticated --min-instances=0 --max-instances=10 \
  --set-env-vars "GCP_PROJECT=$PROJECT,SIGNING_KEY_SECRET=$SECRET_NAME,ORG_A_KEY_ID=$KEY_ID,TRUST_DOMAIN=placeholder.invalid,TENANT_ID=northwind-platform,VAID_TTL_HOURS=1" \
  --quiet

URL="$(gcloud run services describe "$SERVICE" --region "$REGION" --project "$PROJECT" --format='value(status.url)')"
HOST="${URL#https://}"
echo "== service URL: $URL  (trust domain: $HOST) =="

echo "== pass 2: redeploy with TRUST_DOMAIN=$HOST =="
gcloud run deploy "$SERVICE" --project "$PROJECT" --region "$REGION" \
  --source "$HERE" \
  --allow-unauthenticated --min-instances=0 --max-instances=10 \
  --set-env-vars "GCP_PROJECT=$PROJECT,SIGNING_KEY_SECRET=$SECRET_NAME,ORG_A_KEY_ID=$KEY_ID,TRUST_DOMAIN=$HOST,TENANT_ID=northwind-platform,VAID_TTL_HOURS=1" \
  --quiet

echo "ORG_A_URL=$URL"
echo "ORG_A_TRUST_DOMAIN=$HOST"
