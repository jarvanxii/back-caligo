#!/usr/bin/env bash
set -Eeuo pipefail

REPO_DIR="${CALIGO_BACK_REPO_DIR:-/var/www/caligo/back}"
BRANCH="${CALIGO_BACK_BRANCH:-main}"
SERVICE="${CALIGO_BACK_SERVICE:-caligo-back.service}"
LOG_DIR="${CALIGO_BACK_DEPLOY_LOG_DIR:-/var/log/caligo}"
LOG_FILE="${LOG_DIR}/back-deploy.log"
JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-21-openjdk-amd64}"

mkdir -p "$LOG_DIR"
touch "$LOG_FILE"
chmod 0640 "$LOG_FILE" || true

exec > >(tee -a "$LOG_FILE") 2>&1

echo "[$(date -Is)] Caligo backend deploy started"

if [[ ! -d "$REPO_DIR/.git" ]]; then
  echo "Repo no encontrado en ${REPO_DIR}" >&2
  exit 1
fi

cd "$REPO_DIR"
git config --global --add safe.directory "$REPO_DIR" 2>/dev/null || true
git fetch origin "$BRANCH"
git checkout "$BRANCH"
git pull --ff-only origin "$BRANCH"

if [[ -d "$JAVA_HOME" ]]; then
  export JAVA_HOME
  export PATH="${JAVA_HOME}/bin:${PATH}"
fi

mvn -DskipTests package

install -m 0755 "$REPO_DIR/ops/caligo-tool-update.sh" /usr/local/sbin/caligo-tool-update
install -m 0755 "$REPO_DIR/ops/caligo-vpn-control.sh" /usr/local/sbin/caligo-vpn-control

systemctl restart "$SERVICE"

for _ in {1..30}; do
  if curl -fsS http://127.0.0.1:8080/api/health >/dev/null; then
    echo "[$(date -Is)] Caligo backend deploy finished"
    exit 0
  fi
  sleep 2
done

echo "El backend no respondio en /api/health tras el despliegue" >&2
systemctl status "$SERVICE" --no-pager || true
exit 1
