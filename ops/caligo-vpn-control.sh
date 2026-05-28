#!/usr/bin/env bash
set -euo pipefail

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

WIREGUARD_DIR="${CALIGO_VPN_WIREGUARD_DIR:-/etc/caligo/vpn/wireguard}"
OPENVPN_DIR="${CALIGO_VPN_OPENVPN_DIR:-/etc/caligo/vpn/openvpn}"
SAFE_PROFILE='^[A-Za-z0-9._-]{1,80}$'

json_array() {
  local first=1
  printf '['
  for value in "$@"; do
    if [[ "$first" -eq 0 ]]; then
      printf ','
    fi
    first=0
    printf '"%s"' "$(printf '%s' "$value" | sed 's/\\/\\\\/g; s/"/\\"/g')"
  done
  printf ']'
}

require_profile() {
  local profile="${1:-}"
  if [[ ! "$profile" =~ $SAFE_PROFILE ]]; then
    echo "Perfil no permitido: ${profile:-<vacio>}" >&2
    exit 64
  fi
}

wg_path() {
  local profile="$1"
  local file="${WIREGUARD_DIR}/${profile}.conf"
  [[ -f "$file" ]] || { echo "Perfil WireGuard no encontrado: $profile" >&2; exit 66; }
  printf '%s' "$file"
}

ovpn_path() {
  local profile="$1"
  local file="${OPENVPN_DIR}/${profile}.ovpn"
  [[ -f "$file" ]] || { echo "Perfil OpenVPN no encontrado: $profile" >&2; exit 66; }
  printf '%s' "$file"
}

status_json() {
  mapfile -t wg_ifaces < <(wg show interfaces 2>/dev/null | tr ' ' '\n' | sed '/^$/d' || true)
  mapfile -t ovpn_units < <(systemctl list-units 'caligo-openvpn-*.service' --state=running --plain --no-legend 2>/dev/null | awk '{print $1}' | sed -E 's/^caligo-openvpn-(.*)\.service$/\1/' || true)

  local profiles=()
  for iface in "${wg_ifaces[@]}"; do
    profiles+=("wireguard:${iface}")
  done
  for unit in "${ovpn_units[@]}"; do
    profiles+=("openvpn:${unit}")
  done

  printf '{"active":%s,"profiles":' "$([[ "${#profiles[@]}" -gt 0 ]] && printf true || printf false)"
  json_array "${profiles[@]}"
  printf ',"wireguard":'
  json_array "${wg_ifaces[@]}"
  printf ',"openvpn":'
  json_array "${ovpn_units[@]}"
  printf '}'
}

connect_wireguard() {
  local profile="$1"
  require_profile "$profile"
  wg-quick up "$(wg_path "$profile")"
}

disconnect_wireguard() {
  local profile="$1"
  require_profile "$profile"
  wg-quick down "$(wg_path "$profile")"
}

connect_openvpn() {
  local profile="$1"
  require_profile "$profile"
  local file
  file="$(ovpn_path "$profile")"
  systemd-run --unit "caligo-openvpn-${profile}" --collect --property=Restart=on-failure /usr/sbin/openvpn --config "$file"
}

disconnect_openvpn() {
  local profile="$1"
  require_profile "$profile"
  systemctl stop "caligo-openvpn-${profile}.service" || true
}

action="${1:-status}"
protocol="${2:-}"
profile="${3:-}"

case "$action" in
  status)
    status_json
    ;;
  connect)
    case "$protocol" in
      wireguard) connect_wireguard "$profile" ;;
      openvpn) connect_openvpn "$profile" ;;
      *) echo "Protocolo VPN no permitido: ${protocol:-<vacio>}" >&2; exit 64 ;;
    esac
    status_json
    ;;
  disconnect)
    if [[ -z "$protocol" ]]; then
      mapfile -t wg_ifaces < <(wg show interfaces 2>/dev/null | tr ' ' '\n' | sed '/^$/d' || true)
      for iface in "${wg_ifaces[@]}"; do
        [[ "$iface" =~ $SAFE_PROFILE ]] && wg-quick down "$iface" || true
      done
      mapfile -t ovpn_units < <(systemctl list-units 'caligo-openvpn-*.service' --state=running --plain --no-legend 2>/dev/null | awk '{print $1}' | sed -E 's/^caligo-openvpn-(.*)\.service$/\1/' || true)
      for unit in "${ovpn_units[@]}"; do
        [[ "$unit" =~ $SAFE_PROFILE ]] && systemctl stop "caligo-openvpn-${unit}.service" || true
      done
    else
      case "$protocol" in
        wireguard) disconnect_wireguard "$profile" ;;
        openvpn) disconnect_openvpn "$profile" ;;
        *) echo "Protocolo VPN no permitido: ${protocol:-<vacio>}" >&2; exit 64 ;;
      esac
    fi
    status_json
    ;;
  *)
    echo "Accion VPN no permitida: ${action:-<vacia>}" >&2
    exit 64
    ;;
esac
