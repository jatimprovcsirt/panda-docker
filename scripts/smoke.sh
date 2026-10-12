#!/usr/bin/env bash
#
# Container smoke test.
#
# Lives in a script rather than inline in the workflow because embedding shell
# inside YAML means every backslash has to survive two escaping layers, and a
# broken `sed` backreference is silent — it extracts an empty string and the
# assertion below fails for a reason that has nothing to do with the image.
#
# Two properties are checked here that a unit test cannot reach:
#
#   1. The binary starts and serves inside the image it was published in.
#   2. It refuses to start when its configuration is incomplete.
#
# Usage: scripts/smoke.sh <image>

set -euo pipefail

IMAGE="${1:?usage: smoke.sh <image>}"
KEY="$(head -c 32 /dev/urandom | base64)"

# Host ports are configurable so the script runs on a machine where 8080 is
# already taken — which is common, and was how this was discovered. The
# container ports stay fixed; only the published side moves.
API_PORT="${SMOKE_API_PORT:-8080}"
HEALTH_PORT="${SMOKE_HEALTH_PORT:-8081}"

cleanup() {
  docker rm -f panda-smoke-refuse >/dev/null 2>&1 || true
  docker rm -f panda-smoke >/dev/null 2>&1 || true
}
trap cleanup EXIT

# --- 1. refuses to start without a key store --------------------------------
#
# The fail-closed property, against the real image. A service that came up
# without a key store would be one that serves everyone.
echo "== refusing to start with an incomplete configuration =="
set +e
docker run --rm --name panda-smoke-refuse \
  -e PANDA_API_PROTOCOL=rest \
  -e PANDA_ENV=dev \
  -e PANDA_AUTH_MODE=apikey \
  -e PANDA_TLS_ENABLED=false \
  -e "PANDA_KEY_testkey=${KEY}" \
  "$IMAGE" > /tmp/refuse.log 2>&1
code=$?
set -e

if [ "$code" -ne 2 ]; then
  echo "FAIL: exited ${code} without a key store, expected 2"
  cat /tmp/refuse.log
  exit 1
fi
echo "ok: refused to start, exit code 2"

# --- 2. serves when configured ----------------------------------------------
echo "== serving when configured =="
docker run -d --name panda-smoke \
  -e PANDA_API_PROTOCOL=rest \
  -e PANDA_ENV=dev \
  -e PANDA_AUTH_MODE=none \
  -e PANDA_I_UNDERSTAND_THIS_IS_INSECURE=true \
  -e PANDA_TLS_ENABLED=false \
  -e PANDA_LOG_LEVEL=error \
  -e "PANDA_KEY_testkey=${KEY}" \
  -e PANDA_DEFAULT_KID=testkey \
  -p "${API_PORT}:8080" -p "${HEALTH_PORT}:8081" \
  "$IMAGE" >/dev/null

for _ in $(seq 1 20); do
  if curl -sf http://127.0.0.1:${HEALTH_PORT}/readyz >/dev/null; then break; fi
  sleep 0.5
done

if ! curl -sf http://127.0.0.1:${HEALTH_PORT}/readyz >/dev/null; then
  echo "FAIL: the readiness endpoint never came up"
  docker logs panda-smoke
  exit 1
fi

# Parsed with a JSON reader, not sed.
#
# The envelope is a JSON string *inside* JSON, so its quotes arrive escaped and
# a `[^"]*` capture stops at the first one — it extracted `{\` and the failure
# looked like a broken container. Anything that reads this response has to
# understand JSON.
envelope="$(curl -sf -X POST http://127.0.0.1:${API_PORT}/v1/encrypt \
  -H 'Content-Type: application/json' \
  -d '{"plaintext":"3201012501990001","kid":"testkey"}' \
  | node -e 'let d="";process.stdin.on("data",c=>d+=c).on("end",()=>process.stdout.write(JSON.parse(d).envelope))')"

if [ -z "$envelope" ]; then
  echo "FAIL: encrypt returned no envelope"
  docker logs panda-smoke
  exit 1
fi

# Asserting the actual masked value rather than the status code: a 200 with a
# wrong value is exactly the interop break a status check would miss.
masked="$(node -e 'process.stdout.write(JSON.stringify({envelope: process.argv[1]}))' "$envelope" \
  | curl -sf -X POST http://127.0.0.1:${API_PORT}/v1/decrypt \
      -H 'Content-Type: application/json' --data-binary @- \
  | node -e 'let d="";process.stdin.on("data",c=>d+=c).on("end",()=>process.stdout.write(JSON.parse(d).value))')"

if [ "$masked" != "32************01" ]; then
  echo "FAIL: masked value is '${masked}', expected 32************01"
  docker logs panda-smoke
  exit 1
fi

echo "ok: container serves, masking verified"
