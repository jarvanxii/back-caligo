#!/usr/bin/env bash
set -Eeuo pipefail

REPO_DIR="${CALIGO_BACK_REPO_DIR:-/var/www/caligo/back}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"

if [[ $EUID -ne 0 ]]; then
  echo "Ejecuta este instalador como root." >&2
  exit 1
fi

cd "$REPO_DIR"

install -m 0755 ops/caligo-back-deploy.sh /usr/local/sbin/caligo-back-deploy
install -m 0755 ops/caligo-tool-update.sh /usr/local/sbin/caligo-tool-update
install -m 0755 ops/caligo-vpn-control.sh /usr/local/sbin/caligo-vpn-control

install -m 0644 ops/systemd/caligo-back.service "$SYSTEMD_DIR/caligo-back.service"
install -m 0644 ops/systemd/caligo-back-deploy.service "$SYSTEMD_DIR/caligo-back-deploy.service"
install -m 0644 ops/systemd/caligo-metasploit-rpc.service "$SYSTEMD_DIR/caligo-metasploit-rpc.service"
install -m 0644 ops/systemd/caligo-stack.target "$SYSTEMD_DIR/caligo-stack.target"

systemctl daemon-reload

systemctl disable --now metasploit-rpc.service >/dev/null 2>&1 || true

systemctl enable mariadb.service
systemctl enable redis-server.service
systemctl enable redis-server@openvas.service >/dev/null 2>&1 || true
systemctl enable ospd-openvas.service gvmd.service gsad.service
systemctl enable caligo-metasploit-rpc.service caligo-back.service caligo-stack.target

systemctl restart caligo-metasploit-rpc.service
systemctl restart caligo-back.service

echo "Systemd Caligo instalado. Estado actual:"
systemctl --no-pager --plain --type=service --state=running \
  | grep -E 'caligo|mariadb|redis|gvmd|gsad|ospd|metasploit' || true
