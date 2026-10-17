#!/usr/bin/env bash
# Deploys Harbor Ops (Org B): a Lambda behind a Function URL, eu-west-2 only.
# No CloudFront, no ACM, nothing in us-east-1. On-demand DynamoDB table for
# audit (no idle cost), Secrets Manager for Org B's own signing key.
set -euo pipefail

REGION="eu-west-2"
FUNCTION_NAME="harbor-ops-verify"
ROLE_NAME="harbor-ops-verify-role"
TABLE_NAME="harbor-ops-audit"
SECRET_NAME="harbor-ops/signing-key"
KEY_ID="harbor-ops-k1"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT

echo "== building Lambda package in $BUILD_DIR =="
cp "$HERE"/app/*.py "$BUILD_DIR"/

# Pure-python deps straight from the local install.
SITE_PKGS="$(/usr/local/bin/python3 -c 'import vaid_mint, os; print(os.path.dirname(os.path.dirname(vaid_mint.__file__)))')"
for pkg in vaid_mint vaid_pop rfc8785 boto3 botocore s3transfer jmespath python_dateutil urllib3 six; do
  if [ -d "$SITE_PKGS/$pkg" ]; then cp -r "$SITE_PKGS/$pkg" "$BUILD_DIR"/; fi
done
# dateutil's actual package dir is "dateutil", not python_dateutil.
[ -d "$SITE_PKGS/dateutil" ] && cp -r "$SITE_PKGS/dateutil" "$BUILD_DIR"/

# cryptography: pull a manylinux wheel built for the Lambda runtime (py3.12,
# x86_64), never the locally-built macOS wheel.
pip3 install --quiet --target "$BUILD_DIR" --platform manylinux2014_x86_64 \
  --python-version 3.12 --implementation cp --only-binary=:all: --no-deps \
  cryptography cffi pycparser

echo "== packaging zip =="
ZIP_PATH="$BUILD_DIR.zip"
(cd "$BUILD_DIR" && zip -qr "$ZIP_PATH" .)

echo "== ensuring IAM role =="
if ! aws iam get-role --role-name "$ROLE_NAME" --region "$REGION" >/dev/null 2>&1; then
  aws iam create-role --role-name "$ROLE_NAME" --region "$REGION" \
    --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}' >/dev/null
  aws iam attach-role-policy --role-name "$ROLE_NAME" \
    --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole >/dev/null
  sleep 10
fi
ROLE_ARN="$(aws iam get-role --role-name "$ROLE_NAME" --query 'Role.Arn' --output text)"
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"

echo "== ensuring DynamoDB table (on-demand, no idle cost) =="
if ! aws dynamodb describe-table --table-name "$TABLE_NAME" --region "$REGION" >/dev/null 2>&1; then
  aws dynamodb create-table --region "$REGION" --table-name "$TABLE_NAME" \
    --attribute-definitions AttributeName=record_id,AttributeType=S \
    --key-schema AttributeName=record_id,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST >/dev/null
fi

echo "== ensuring Org B signing key in Secrets Manager =="
if ! aws secretsmanager describe-secret --secret-id "$SECRET_NAME" --region "$REGION" >/dev/null 2>&1; then
  PRIV_B64="$(/usr/local/bin/python3 -c '
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import base64, json
k = Ed25519PrivateKey.generate()
raw = k.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())
print(base64.b64encode(raw).decode())
')"
  aws secretsmanager create-secret --region "$REGION" --name "$SECRET_NAME" \
    --secret-string "{\"private_key_b64\":\"$PRIV_B64\"}" >/dev/null
fi

aws iam put-role-policy --role-name "$ROLE_NAME" --policy-name harbor-ops-inline \
  --policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[
    {\"Effect\":\"Allow\",\"Action\":[\"dynamodb:PutItem\",\"dynamodb:Scan\"],\"Resource\":\"arn:aws:dynamodb:$REGION:$ACCOUNT_ID:table/$TABLE_NAME\"},
    {\"Effect\":\"Allow\",\"Action\":[\"secretsmanager:GetSecretValue\"],\"Resource\":\"arn:aws:secretsmanager:$REGION:$ACCOUNT_ID:secret:${SECRET_NAME}*\"}
  ]}" >/dev/null

TRUST_DOMAIN_ALLOWLIST="${ORG_A_TRUST_DOMAIN:-}"
CORS_ORIGIN="${ORG_A_ORIGIN:-*}"

echo "== deploying Lambda (trust domain allowlist: ${TRUST_DOMAIN_ALLOWLIST:-<none set>}) =="
ENV_VARS="Variables={CACHE_WINDOW_SECONDS=60,AUDIT_TABLE=$TABLE_NAME,ORG_B_SIGNING_KEY_SECRET=$SECRET_NAME,ORG_B_KEY_ID=$KEY_ID,TRUST_DOMAIN_ALLOWLIST=$TRUST_DOMAIN_ALLOWLIST,GRANTED_TRUST_DOMAIN=$TRUST_DOMAIN_ALLOWLIST,GRANTED_AGENT_CLASS=infra-agent,GRANTED_RESOURCE_PREFIXES=harbor-ops/deploy/,MAX_DELEGATION_DEPTH=1,CORS_ORIGIN=$CORS_ORIGIN}"

if aws lambda get-function --function-name "$FUNCTION_NAME" --region "$REGION" >/dev/null 2>&1; then
  aws lambda update-function-code --region "$REGION" --function-name "$FUNCTION_NAME" --zip-file "fileb://$ZIP_PATH" >/dev/null
  aws lambda wait function-updated --region "$REGION" --function-name "$FUNCTION_NAME"
  aws lambda update-function-configuration --region "$REGION" --function-name "$FUNCTION_NAME" \
    --environment "$ENV_VARS" --timeout 10 --memory-size 256 >/dev/null
else
  aws lambda create-function --region "$REGION" --function-name "$FUNCTION_NAME" \
    --runtime python3.12 --role "$ROLE_ARN" --handler handler.lambda_handler \
    --zip-file "fileb://$ZIP_PATH" --timeout 10 --memory-size 256 \
    --environment "$ENV_VARS" >/dev/null
  aws lambda wait function-active --region "$REGION" --function-name "$FUNCTION_NAME"
fi

echo "== ensuring Function URL =="
if ! aws lambda get-function-url-config --function-name "$FUNCTION_NAME" --region "$REGION" >/dev/null 2>&1; then
  aws lambda create-function-url-config --region "$REGION" --function-name "$FUNCTION_NAME" \
    --auth-type NONE --cors "{\"AllowOrigins\":[\"$CORS_ORIGIN\"],\"AllowMethods\":[\"*\"],\"AllowHeaders\":[\"content-type\"]}" >/dev/null
  aws lambda add-permission --region "$REGION" --function-name "$FUNCTION_NAME" \
    --statement-id FunctionURLAllowPublicAccess --action lambda:InvokeFunctionUrl \
    --principal "*" --function-url-auth-type NONE >/dev/null
  # As of late 2025, a public (AuthType NONE) Function URL also needs a SEPARATE
  # lambda:InvokeFunction grant conditioned on InvokedViaFunctionUrl — the
  # InvokeFunctionUrl grant above is not sufficient on its own, and the plain
  # `aws lambda add-permission --function-url-auth-type NONE` CLI flag only
  # supports the InvokeFunctionUrl action, not this condition, so it is added
  # via boto3 directly. Without this, anonymous requests get a 403
  # AccessDeniedException even though the resource policy looks complete.
  python3 -c "
import boto3
c = boto3.client('lambda', region_name='$REGION')
c.add_permission(
    FunctionName='$FUNCTION_NAME',
    StatementId='public-invoke-via-url',
    Action='lambda:InvokeFunction',
    Principal='*',
    InvokedViaFunctionUrl=True,
)
"
fi

URL="$(aws lambda get-function-url-config --function-name "$FUNCTION_NAME" --region "$REGION" --query FunctionUrl --output text)"
echo "ORG_B_URL=$URL"
