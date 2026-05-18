#!/bin/sh
set -eu

APP_HOME=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CONFIG_FILE="${APP_HOME}/data/config.json"
PID_FILE="${APP_HOME}/run/kiro-go.pid"
LOG_FILE="${APP_HOME}/logs/stdout.log"
BINARY="${APP_HOME}/kiro-go"

mkdir -p "${APP_HOME}/run" "${APP_HOME}/logs" "${APP_HOME}/data"

if [ ! -f "${CONFIG_FILE}" ]; then
  echo "Config file not found: ${CONFIG_FILE}"
  echo "Create data/config.json before starting Kiro-Go."
  exit 1
fi

if [ ! -f "${BINARY}" ]; then
  echo "Binary not found: ${BINARY}"
  exit 1
fi

chmod +x "${BINARY}"

if [ -f "${PID_FILE}" ]; then
  OLD_PID=$(cat "${PID_FILE}" 2>/dev/null || echo "")
  if [ -n "${OLD_PID}" ] && kill -0 "${OLD_PID}" 2>/dev/null; then
    echo "Stopping old process (PID: ${OLD_PID})..."
    kill "${OLD_PID}" 2>/dev/null || true
    sleep 1
    if kill -0 "${OLD_PID}" 2>/dev/null; then
      kill -9 "${OLD_PID}" 2>/dev/null || true
      sleep 1
    fi
    echo "Old process stopped"
  fi
  rm -f "${PID_FILE}"
fi

echo "Starting Kiro-Go..."
nohup env CONFIG_PATH="${CONFIG_FILE}" "${BINARY}" >> "${LOG_FILE}" 2>&1 &

NEW_PID=$!
echo "${NEW_PID}" > "${PID_FILE}"

echo "Started successfully"
echo "PID: ${NEW_PID}"
echo "Log: ${LOG_FILE}"
echo "Config: ${CONFIG_FILE}"
