#!/usr/bin/env bash
set -euo pipefail

APP_SERVICE=${APP_SERVICE:-app}
APP_HEALTH_URL=${APP_HEALTH_URL:-http://localhost:8000/health}
OLLAMA_HEALTH_URL=${OLLAMA_HEALTH_URL:-http://localhost:11434/api/tags}

print_header() {
  printf '\n%s\n' "$1"
  printf '%*s\n' "${#1}" '' | tr ' ' '-'
}

check_compose_service() {
  local service=$1
  if ! command -v docker >/dev/null 2>&1; then
    echo "docker command not found"
    return 1
  fi
  if ! docker compose ps >/dev/null 2>&1; then
    echo "docker compose not configured or unable to connect to daemon"
    return 1
  fi

  if docker compose ps --status=running --services "$service" | grep -qx "$service"; then
    echo "Docker Compose status: running"
  else
    local state
    state=$(docker compose ps "$service" 2>/dev/null | awk 'NR==2 {print $4}')
    state=${state:-unknown}
    echo "Docker Compose status: ${state}"
  fi
}

check_http_endpoint() {
  local url=$1
  local label=$2

  if ! command -v curl >/dev/null 2>&1; then
    echo "curl not installed; skipping HTTP check for ${label}"
    return
  fi

  local body_file http_code
  body_file=$(mktemp)
  http_code=$(curl -sS -m 5 -o "$body_file" -w '%{http_code}' "$url" || true)

  if [[ "$http_code" == "200" ]]; then
    echo "${label} HTTP status: 200 (OK)"
  elif [[ -z "$http_code" ]]; then
    echo "${label} HTTP status: unreachable"
  else
    echo "${label} HTTP status: ${http_code}"
  fi

  if [[ -s "$body_file" ]]; then
    echo "${label} response sample:"
    if command -v jq >/dev/null 2>&1; then
      jq_output=$(jq '.' "$body_file" 2>/dev/null | head -n 10)
      if [[ -n "$jq_output" ]]; then
        printf '%s\n' "$jq_output"
      else
        head -n 5 "$body_file"
      fi
    else
      head -n 5 "$body_file"
    fi
  fi
  rm -f "$body_file"
}

print_header "App Service (${APP_SERVICE})"
check_compose_service "$APP_SERVICE" || true
check_http_endpoint "$APP_HEALTH_URL" "App"

print_header "Ollama Service"
check_http_endpoint "$OLLAMA_HEALTH_URL" "Ollama"

if command -v pgrep >/dev/null 2>&1; then
  if pgrep -f ollama >/dev/null 2>&1; then
    echo "Ollama process: running"
  else
    echo "Ollama process: not found"
  fi
fi
