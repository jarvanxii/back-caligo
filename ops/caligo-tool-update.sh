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
  local pipx_home="/opt/caligo-pipx"
  local pipx_bin="/opt/caligo-pipx/bin"
  apt-get update
  apt-get install -y python3 python3-pip python3-venv pipx
  install -d -m 0755 "$pipx_home" "$pipx_bin"
  PIPX_HOME="$pipx_home" PIPX_BIN_DIR="$pipx_bin" python3 -m pipx install --force "$package"
  chmod -R a+rX "$pipx_home"
  for candidate in \
    "${pipx_bin}/${binary}" \
    "/usr/local/bin/${binary}" \
    "/root/.local/bin/${binary}" \
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

theharvester_update() {
  local repo="/opt/theHarvester"
  apt-get update
  apt-get install -y git curl python3 python3-venv
  if [ -d "${repo}/.git" ]; then
    git -C "$repo" pull --ff-only
  else
    rm -rf "$repo"
    git clone https://github.com/laramies/theHarvester.git "$repo"
  fi
  if ! command -v uv >/dev/null 2>&1; then
    curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh
  fi
  cd "$repo"
  uv sync
  cat >/usr/local/bin/theHarvester <<'WRAPPER'
#!/usr/bin/env bash
cd /opt/theHarvester
exec uv run theHarvester "$@"
WRAPPER
  chmod 0755 /usr/local/bin/theHarvester
}

spiderfoot_update() {
  local repo="/opt/spiderfoot"
  apt-get update
  apt-get install -y git python3 python3-dev python3-pip python3-venv build-essential libxml2-dev libxslt1-dev
  if [ -d "${repo}/.git" ]; then
    git -C "$repo" pull --ff-only
  else
    rm -rf "$repo"
    git clone https://github.com/smicallef/spiderfoot.git "$repo"
  fi
  python3 -m venv "${repo}/.venv"
  "${repo}/.venv/bin/pip" install --upgrade pip wheel
  awk '/^lxml[<>=]/ { print "lxml>=5.4,<7"; next } { print }' "${repo}/requirements.txt" >"${repo}/.caligo-requirements.txt"
  "${repo}/.venv/bin/pip" install -r "${repo}/.caligo-requirements.txt"
  cat >/usr/local/bin/spiderfoot <<'WRAPPER'
#!/usr/bin/env bash
cd /opt/spiderfoot
exec /opt/spiderfoot/.venv/bin/python /opt/spiderfoot/sf.py "$@"
WRAPPER
  chmod 0755 /usr/local/bin/spiderfoot
}

trufflehog_update() {
  apt-get update
  apt-get install -y curl ca-certificates
  curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
  chmod 0755 /usr/local/bin/trufflehog
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
    theharvester_update
    ;;
  git-dumper)
    python_tool_update git-dumper git-dumper
    ;;
  spiderfoot)
    spiderfoot_update
    ;;
  trufflehog)
    trufflehog_update
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
