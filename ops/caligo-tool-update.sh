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
