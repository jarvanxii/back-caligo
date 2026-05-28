#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

tool="${1:-}"

apt_update() {
  apt-get update
  apt-get install --only-upgrade -y "$@"
}

go_update() {
  local module="$1"
  local binary="$2"
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  GOBIN="$tmp" go install "${module}@latest"
  install -m 0755 "${tmp}/${binary}" "/usr/local/bin/${binary}"
}

git_update() {
  local repo="$1"
  git -C "$repo" pull --ff-only
}

gem_update() {
  gem update "$1"
}

python_tool_update() {
  local package="$1"
  local binary="$2"
  apt-get update
  apt-get install -y python3 python3-pip python3-venv pipx
  python3 -m pipx install --force "$package"
  for candidate in \
    "/root/.local/bin/${binary}" \
    "/usr/local/bin/${binary}" \
    "/usr/bin/${binary}"; do
    if [ -x "$candidate" ]; then
      install -m 0755 "$candidate" "/usr/local/bin/${binary}"
      return 0
    fi
  done
  command -v "$binary" >/dev/null 2>&1 || {
    echo "No se encontro el binario ${binary} tras instalar ${package}" >&2
    exit 69
  }
}

case "$tool" in
  nmap)
    apt_update nmap
    ;;
  openvas)
    apt_update gvm gvmd openvas-scanner ospd-openvas gvm-tools
    ;;
  metasploit)
    apt_update metasploit-framework
    ;;
  hydra)
    apt_update hydra
    ;;
  nuclei)
    go_update github.com/projectdiscovery/nuclei/v3/cmd/nuclei nuclei
    nuclei -update-templates -silent || true
    ;;
  searchsploit)
    git_update /opt/exploitdb
    ;;
  nikto)
    apt_update nikto
    ;;
  sqlmap)
    apt_update sqlmap
    ;;
  john)
    apt_update john
    ;;
  hashcat)
    apt_update hashcat
    ;;
  hashid)
    apt_update hashid
    ;;
  crunch)
    apt_update crunch
    ;;
  cewl)
    apt_update cewl
    ;;
  curl)
    apt_update curl
    ;;
  openssl)
    apt_update openssl
    ;;
  whois)
    apt_update whois
    ;;
  dig|nslookup)
    apt_update dnsutils
    ;;
  ffuf)
    apt_update ffuf
    ;;
  httpx)
    go_update github.com/projectdiscovery/httpx/cmd/httpx httpx
    ;;
  katana)
    go_update github.com/projectdiscovery/katana/cmd/katana katana
    ;;
  gau)
    go_update github.com/lc/gau/v2/cmd/gau gau
    ;;
  subfinder)
    go_update github.com/projectdiscovery/subfinder/v2/cmd/subfinder subfinder
    ;;
  amass)
    go_update 'github.com/owasp-amass/amass/v4/...' amass
    ;;
  sherlock)
    python_tool_update sherlock-project sherlock
    ;;
  maigret)
    python_tool_update maigret maigret
    ;;
  social-analyzer)
    python_tool_update social-analyzer social-analyzer
    ;;
  holehe)
    python_tool_update holehe holehe
    ;;
  theharvester)
    python_tool_update theHarvester theHarvester
    ;;
  wireguard)
    apt_update wireguard-tools
    ;;
  openvpn)
    apt_update openvpn
    ;;
  resolvconf)
    apt_update resolvconf
    ;;
  exiftool)
    apt_update libimage-exiftool-perl
    ;;
  steghide)
    apt_update steghide
    ;;
  binwalk)
    apt_update binwalk
    ;;
  zsteg)
    gem_update zsteg
    ;;
  *)
    echo "Herramienta no permitida por Caligo: ${tool:-<vacia>}" >&2
    exit 64
    ;;
esac
