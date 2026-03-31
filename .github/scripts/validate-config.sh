#!/usr/bin/env bash
set -euo pipefail

CONFIG="ci.config.json"

# --- 1. Existence check ---
if [[ ! -f "$CONFIG" ]]; then
  echo "❌ Error 404: $CONFIG not found"
  exit 404
fi

# --- 2. Non-empty check ---
if [[ ! -s "$CONFIG" ]]; then
  echo "❌ Error 400: $CONFIG is empty"
  exit 400
fi

echo "✔ $CONFIG exists and is non-empty"

# --- 3. JSON value getter helper ---
get_json() {
  local key="$1"
  local value
  value=$(jq -r "$key" "$CONFIG" 2>/dev/null || echo "__jq_error__")

  if [[ "$value" == "__jq_error__" ]]; then
    echo "❌ JSON parse error for key: $key"
    exit 500
  fi

  if [[ "$value" == "null" ]]; then
    echo "❌ Missing required JSON key: $key"
    exit 422
  fi

  echo "$value"
}

# --- 4. Example: read config values ---
STANDALONE=$(get_json '.emscripten.standaloneWasm')
FORBID_EXIT=$(get_json '.emscripten.forbidExitRuntime')

echo "• standaloneWasm = $STANDALONE"
echo "• forbidExitRuntime = $FORBID_EXIT"

# --- 5. Enforce rules ---
if [[ "$STANDALONE" == "true" && "$FORBID_EXIT" == "true" ]]; then
  if grep -R --include="*.sh" -nE "EXIT_RUNTIME|--exit-runtime" .; then
    echo "❌ Forbidden flag detected: EXIT_RUNTIME"
    exit 451
  fi
fi

echo "✔ Config validation complete"
