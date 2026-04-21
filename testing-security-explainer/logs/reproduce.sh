#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
APP_DIR="$ROOT_DIR/testing-security-explainer"
LOG_DIR="$APP_DIR/logs"
CASE_DIR="$LOG_DIR/cases"
RUN_LOG="$LOG_DIR/runtime.log"

mkdir -p "$CASE_DIR"
rm -f "$CASE_DIR"/* "$LOG_DIR"/http-cases-summary.txt "$LOG_DIR"/security-audit-events.txt "$LOG_DIR"/redis-keys-after-tests.txt "$RUN_LOG"

if ! docker ps --format '{{.Names}}' | grep -q '^dapr_redis$'; then
  echo "Redis container 'dapr_redis' is not running. Start it and re-run." >&2
  exit 1
fi

# Clean previous demo refresh-token keys so learners see only this run's evidence.
docker exec dapr_redis sh -c "redis-cli --scan --pattern 'security:refresh:*' | xargs -r redis-cli del >/dev/null"

pushd "$APP_DIR" >/dev/null
mvn -q -DskipTests spring-boot:run > "$RUN_LOG" 2>&1 &
APP_PID=$!
popd >/dev/null

cleanup() {
  if ps -p "$APP_PID" >/dev/null 2>&1; then
    kill "$APP_PID" >/dev/null 2>&1 || true
    wait "$APP_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

for i in {1..90}; do
  if curl -sS http://localhost:8080/public >/dev/null 2>&1; then
    break
  fi
  sleep 1
  if [[ "$i" == "90" ]]; then
    echo "Application did not start in time. Last 80 log lines:" >&2
    tail -n 80 "$RUN_LOG" >&2 || true
    exit 1
  fi
done

TS="$(date +%s)"
USER_NAME="user${TS}"
ADMIN_NAME="admin${TS}"
PASS='Pass@123'

write_case() {
  local name="$1"
  shift
  local code_file="$CASE_DIR/${name}.code"
  local json_file="$CASE_DIR/${name}.json"
  local code
  code=$(curl -sS -o "$json_file" -w '%{http_code}' "$@")
  printf '%s\n' "$code" > "$code_file"
}

write_case register-user -X POST http://localhost:8080/register \
  -H 'Content-Type: application/json' \
  -d "{\"name\":\"User ${TS}\",\"username\":\"${USER_NAME}\",\"email\":\"${USER_NAME}@example.com\",\"password\":\"${PASS}\",\"rollNo\":\"R${TS}\",\"course\":\"BTECH\",\"department\":\"CSE\"}"

write_case register-admin -X POST http://localhost:8080/register/admin \
  -H 'Content-Type: application/json' \
  -d "{\"name\":\"Admin ${TS}\",\"username\":\"${ADMIN_NAME}\",\"email\":\"${ADMIN_NAME}@example.com\",\"password\":\"${PASS}\",\"facultyId\":\"F${TS}\",\"department\":\"CSE\",\"course\":\"BTECH\"}"

write_case login-user-fail -X POST http://localhost:8080/login \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"${USER_NAME}\",\"password\":\"Wrong@123\"}"

write_case login-user-ok -X POST http://localhost:8080/login \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"${USER_NAME}\",\"password\":\"${PASS}\"}"

write_case login-admin-ok -X POST http://localhost:8080/login \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"${ADMIN_NAME}\",\"password\":\"${PASS}\"}"

USER_ACCESS=$(jq -r '.accessToken // empty' "$CASE_DIR/login-user-ok.json")
USER_REFRESH=$(jq -r '.refreshToken // empty' "$CASE_DIR/login-user-ok.json")
ADMIN_ACCESS=$(jq -r '.accessToken // empty' "$CASE_DIR/login-admin-ok.json")

if [[ -z "$USER_ACCESS" || -z "$USER_REFRESH" || -z "$ADMIN_ACCESS" ]]; then
  echo "Could not parse expected tokens from login responses." >&2
  exit 1
fi

write_case me-no-token http://localhost:8080/me

write_case admin-users-forbidden http://localhost:8080/admin/users \
  -H "Authorization: Bearer ${USER_ACCESS}"

write_case admin-users-ok http://localhost:8080/admin/users \
  -H "Authorization: Bearer ${ADMIN_ACCESS}"

USER_ID=$(jq -r --arg u "$USER_NAME" '.. | objects | select((.username? // "") == $u) | (.id? // empty)' "$CASE_DIR/admin-users-ok.json" | head -n 1)
ADMIN_ID=$(jq -r --arg u "$ADMIN_NAME" '.. | objects | select((.username? // "") == $u) | (.id? // empty)' "$CASE_DIR/admin-users-ok.json" | head -n 1)

if [[ -z "$USER_ID" || -z "$ADMIN_ID" ]]; then
  echo "Could not parse user/admin IDs from /admin/users response." >&2
  exit 1
fi

write_case profile-owner-ok "http://localhost:8080/profile/${USER_ID}" \
  -H "Authorization: Bearer ${USER_ACCESS}"

write_case profile-owner-forbidden "http://localhost:8080/profile/${ADMIN_ID}" \
  -H "Authorization: Bearer ${USER_ACCESS}"

write_case refresh-user-ok -X POST http://localhost:8080/refresh \
  -H 'Content-Type: application/json' \
  -d "{\"refreshToken\":\"${USER_REFRESH}\"}"

ROTATED_REFRESH=$(jq -r '.refreshToken // empty' "$CASE_DIR/refresh-user-ok.json")
if [[ -z "$ROTATED_REFRESH" ]]; then
  echo "Could not parse rotated refresh token." >&2
  exit 1
fi

write_case refresh-user-replay -X POST http://localhost:8080/refresh \
  -H 'Content-Type: application/json' \
  -d "{\"refreshToken\":\"${USER_REFRESH}\"}"

write_case logout-user -X POST http://localhost:8080/logout \
  -H 'Content-Type: application/json' \
  -d "{\"refreshToken\":\"${ROTATED_REFRESH}\"}"

write_case refresh-after-logout -X POST http://localhost:8080/refresh \
  -H 'Content-Type: application/json' \
  -d "{\"refreshToken\":\"${ROTATED_REFRESH}\"}"

write_case refresh-invalid-token -X POST http://localhost:8080/refresh \
  -H 'Content-Type: application/json' \
  -d '{"refreshToken":"invalid.token.value"}'

{
  echo "=== Test Run $(date -Iseconds) ==="
  echo "user=${USER_NAME}"
  echo "admin=${ADMIN_NAME}"
  echo
  echo "HTTP codes"
  for case_name in \
    register-user register-admin login-user-fail login-user-ok login-admin-ok \
    me-no-token admin-users-forbidden admin-users-ok profile-owner-ok profile-owner-forbidden \
    refresh-user-ok refresh-user-replay logout-user refresh-after-logout refresh-invalid-token; do
    printf '%s=%s\n' "$case_name" "$(cat "$CASE_DIR/${case_name}.code")"
  done
} > "$LOG_DIR/http-cases-summary.txt"

{
  grep 'JsonSecurityAuditSink' "$RUN_LOG" || true
  grep 'RedisRefreshTokenStore' "$RUN_LOG" || true
} > "$LOG_DIR/security-audit-events.txt"

docker exec dapr_redis redis-cli --scan --pattern 'security:refresh:*' > "$LOG_DIR/redis-keys-after-tests.txt"

echo "Done. Artifacts generated in $LOG_DIR"
