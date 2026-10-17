#!/usr/bin/env bash
# Wakes both sides of the cross-org demo from scale-to-zero and waits until
# each answers healthy. Both services run at min-instances=0 (Cloud Run) /
# no provisioned concurrency (Lambda), so idle cost is ~$0 and a cold start
# is expected on the first call of the day.
set -euo pipefail

ORG_A_URL="${ORG_A_URL:?set ORG_A_URL to the Cloud Run service URL}"
ORG_B_URL="${ORG_B_URL:?set ORG_B_URL to the Lambda Function URL}"

wait_for() {
  local name="$1" url="$2"
  echo -n "waking $name... "
  for i in $(seq 1 30); do
    if curl -fsS -o /dev/null --max-time 5 "$url"; then
      echo "ready (attempt $i)"
      return 0
    fi
    sleep 2
  done
  echo "FAILED to wake $name after 60s"
  return 1
}

wait_for "Org A (Northwind, GCP)" "$ORG_A_URL/health"
wait_for "Org B (Harbor Ops, AWS)" "${ORG_B_URL%/}/pubkey"

echo "READY"
