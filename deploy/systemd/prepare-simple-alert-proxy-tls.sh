#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${1:-/etc/default/simple-alert-proxy}"
DEST_DIR="/etc/simple-alert-proxy"
DEST_CERT="${DEST_DIR}/tls.crt"
DEST_KEY="${DEST_DIR}/tls.key"
IMAGE="${SIMPLE_ALERT_PROXY_IMAGE:-localhost/simple-alert-proxy:latest}"

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "missing env file: ${ENV_FILE}" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "${ENV_FILE}"

: "${SIMPLE_ALERT_PROXY_TLS_CERT_FILE:?SIMPLE_ALERT_PROXY_TLS_CERT_FILE is required}"
: "${SIMPLE_ALERT_PROXY_TLS_KEY_FILE:?SIMPLE_ALERT_PROXY_TLS_KEY_FILE is required}"

if [[ ! -r "${SIMPLE_ALERT_PROXY_TLS_CERT_FILE}" ]]; then
  echo "certificate file is not readable: ${SIMPLE_ALERT_PROXY_TLS_CERT_FILE}" >&2
  exit 1
fi

if [[ ! -r "${SIMPLE_ALERT_PROXY_TLS_KEY_FILE}" ]]; then
  echo "key file is not readable: ${SIMPLE_ALERT_PROXY_TLS_KEY_FILE}" >&2
  exit 1
fi

container_uid="$(podman run --rm --entrypoint /usr/bin/id "${IMAGE}" -u simple-alert-proxy)"
container_gid="$(podman run --rm --entrypoint /usr/bin/id "${IMAGE}" -g simple-alert-proxy)"

install -d -m 0755 "${DEST_DIR}"
install -o "${container_uid}" -g "${container_gid}" -m 0444 "${SIMPLE_ALERT_PROXY_TLS_CERT_FILE}" "${DEST_CERT}"
install -o "${container_uid}" -g "${container_gid}" -m 0400 "${SIMPLE_ALERT_PROXY_TLS_KEY_FILE}" "${DEST_KEY}"
