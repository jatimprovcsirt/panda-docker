#!/usr/bin/env bash
#
# API contract test.
#
# Runs the Postman collection against a real container. That collection is
# also the file an agency imports to get started, so running it here is what
# stops the two from drifting apart. A change that breaks the documented API
# fails now, rather than in someone's integration six months from now — and
# a collection that no longer matches the service is worse than no
# collection, because it sends people to debug their own code first.
#
# Lives in a script rather than inline in the workflow for the same reason
# smoke.sh does: shell embedded in YAML has to survive two escaping layers,
# and a broken escape fails silently.
#
# Usage: scripts/contract.sh <image>

set -euo pipefail

IMAGE="${1:?usage: contract.sh <image>}"
KEY="$(head -c 32 /dev/urandom | base64)"
INDEX_KEY="$(head -c 32 /dev/urandom | base64)"
KID=contractkey

API_PORT="${CONTRACT_API_PORT:-18080}"
HEALTH_PORT="${CONTRACT_HEALTH_PORT:-18081}"

cleanup() {
  docker rm -f panda-contract >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker run -d --name panda-contract \
  -e PANDA_API_PROTOCOL=rest \
  -e PANDA_ENV=dev \
  -e PANDA_AUTH_MODE=none \
  -e PANDA_I_UNDERSTAND_THIS_IS_INSECURE=true \
  -e PANDA_TLS_ENABLED=false \
  -e PANDA_LOG_LEVEL=error \
  -e "PANDA_KEY_${KID}=${KEY}" \
  -e "PANDA_INDEX_KEY=${INDEX_KEY}" \
  -e "PANDA_DEFAULT_KID=${KID}" \
  -p "${API_PORT}:8080" -p "${HEALTH_PORT}:8081" \
  "$IMAGE" >/dev/null

for _ in $(seq 1 20); do
  if curl -sf "http://127.0.0.1:${HEALTH_PORT}/readyz" >/dev/null 2>&1; then break; fi
  sleep 0.5
done

if ! curl -sf "http://127.0.0.1:${HEALTH_PORT}/readyz" >/dev/null 2>&1; then
  echo "FAIL: the readiness endpoint never came up"
  docker logs panda-contract
  exit 1
fi

# Auth mode `none` grants every scope, including unmask, so the collection
# exercises the real handlers rather than a subset. It is a development-only
# mode: config refuses to start with it in production, and refuses it at all
# without an explicit acknowledgement variable. The API key passed below is
# therefore ignored by the service — it is set so the request carries a
# well-formed header rather than an empty one.
npx --yes newman run postman/panda.postman_collection.json \
  -e postman/panda.postman_environment.json \
  --env-var "baseUrl=http://127.0.0.1:${API_PORT}" \
  --env-var "apiKey=panda_svc_contract_test" \
  --env-var "kid=${KID}" \
  --env-var "plaintext=3201012501990001" \
  --reporters cli \
  --timeout-request 10000
