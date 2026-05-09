#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
#  elite_recon.sh v2.0 — Complete Elite Bug Bounty Recon Pipeline
#
#  PASSIVE + ACTIVE modes. Finds what others miss.
#
#  Pipeline:
#    Step 1  → Subdomain enumeration (10 sources + alterx permutations)
#    Step 2  → Live host filtering
#    Step 3  → URL collection (9 tools + GitHub mining)
#    Step 4  → Live URL filtering
#    Step 5  → Asset extraction (JS + JSON + .env + webpack chunks)
#    Step 6  → Deep JS/JSON/ENV analysis (100+ patterns, confidence scoring)
#    Step 7  → Inline script extraction from HTML pages
#    Step 8  → robots.txt + sitemap.xml mining
#    Step 9  → 34-category sensitive URL filtering
#    Step 10 → Active testing (GraphQL, Firebase, S3, CORS, takeover, JWT)
#
#  Usage:
#    ./elite_recon.sh target.com
#    ./elite_recon.sh target.com -gt GITHUB_TOKEN
#    ./elite_recon.sh target.com -gt GITHUB_TOKEN --active
#
#  Flags:
#    -gt TOKEN   GitHub personal access token (enables GitHub mining)
#    --active    Enable active testing (GraphQL, Firebase, S3, CORS, JWT)
#
#  WARNING: Only run against targets you have written permission to test.
# ═══════════════════════════════════════════════════════════════════════

if [ -z "${BASH_VERSION:-}" ]; then exec bash "$0" "$@"; fi
export LANG=C LC_ALL=C
set -uo pipefail

# ── Colors ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; BLUE='\033[0;34m'
BOLD='\033[1m'; NC='\033[0m'

# ── Argument parsing ──────────────────────────────────────────────────
TARGET="${1:-}"
GITHUB_TOKEN=""
ACTIVE_MODE=false

shift || true
while [[ $# -gt 0 ]]; do
    case "$1" in
        -gt)       GITHUB_TOKEN="${2:-}"; shift 2 ;;
        --active)  ACTIVE_MODE=true; shift ;;
        *)         shift ;;
    esac
done

[[ -z "$TARGET" ]] && {
    echo "Usage: $0 target.com [-gt github_token] [--active]"
    echo ""
    echo "  -gt TOKEN   GitHub token for code mining"
    echo "  --active    Enable active testing (GraphQL/Firebase/S3/CORS/JWT)"
    exit 1
}

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUT="elite_recon_${TARGET}_${TIMESTAMP}"

# ── Folder structure ──────────────────────────────────────────────────
mkdir -p "$OUT"/{01_subs,02_live,03_urls/github,04_live_urls}
mkdir -p "$OUT/05_assets"/{js,json,env,webpack,html_scripts}
mkdir -p "$OUT/06_findings"/{HIGH,MEDIUM,LOW}
mkdir -p "$OUT/06_findings/HIGH"/{cloud_secrets,auth_tokens,payment,database,private_keys,api_keys}
mkdir -p "$OUT/06_findings/MEDIUM"/{communication,monitoring,saas,cicd,ecommerce,source_control,ai_ml,infrastructure,pii,endpoints,storage}
mkdir -p "$OUT/06_findings/LOW"/{dev_comments,js_files,generic}
mkdir -p "$OUT/07_urlsecrets"
mkdir -p "$OUT/08_active"/{graphql,firebase,s3,cors,takeover,jwt,env_files}
mkdir -p "$OUT/09_recon"/{robots,sitemaps,tech_stack}

LOG="$OUT/elite_recon.log"
touch "$LOG"
export LOG

# ── Logging ───────────────────────────────────────────────────────────
log()   { echo -e "${GREEN}[+]${NC} $*" | tee -a "$LOG" 2>/dev/null || true; }
warn()  { echo -e "${YELLOW}[!]${NC} $*" | tee -a "$LOG" 2>/dev/null || true; }
info()  { echo -e "${CYAN}[*]${NC} $*"   | tee -a "$LOG" 2>/dev/null || true; }
high()  { echo -e "${RED}${BOLD}[HIGH]${NC} $*"     | tee -a "$LOG" 2>/dev/null || true; }
med()   { echo -e "${YELLOW}${BOLD}[MEDIUM]${NC} $*" | tee -a "$LOG" 2>/dev/null || true; }
low()   { echo -e "${BLUE}[LOW]${NC} $*"            | tee -a "$LOG" 2>/dev/null || true; }
active(){ echo -e "${MAGENTA}${BOLD}[ACTIVE]${NC} $*" | tee -a "$LOG" 2>/dev/null || true; }
step()  { echo ""; echo -e "${CYAN}${BOLD}$*${NC}"; echo ""; }

# ── Banner ────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}${BOLD}║         elite_recon.sh v2.0 — Full Pipeline             ║${NC}"
echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
echo -e "  Target  : ${BOLD}${TARGET}${NC}"
echo -e "  GitHub  : ${BOLD}${GITHUB_TOKEN:+enabled}${GITHUB_TOKEN:-disabled}${NC}"
echo -e "  Active  : ${BOLD}${ACTIVE_MODE}${NC}"
echo -e "  Output  : ${BOLD}${OUT}${NC}"
echo ""

# ══════════════════════════════════════════════════════════════════════
# CORE HELPERS
# ══════════════════════════════════════════════════════════════════════

# ── Save finding with confidence score ───────────────────────────────
# Usage: save_finding HIGH|MEDIUM|LOW <category> <type> <value> <source>
save_finding() {
    local confidence="$1" category="$2" type="$3" value="$4" source="$5"
    local catfile="$OUT/06_findings/${confidence}/${category}/${type}.txt"
    local allfile="$OUT/06_findings/ALL_FINDINGS.txt"
    local entry="[${confidence}][${type}:${value}] source ${source}"

    # Cross-file deduplication — only save if value not seen before
    if ! grep -qF "[${type}:${value}]" "$allfile" 2>/dev/null; then
        echo "$entry" >> "$catfile" 2>/dev/null || true
        echo "$entry" >> "$allfile"

        case "$confidence" in
            HIGH)   high   "[${category}/${type}] ${value:0:80}" ;;
            MEDIUM) med    "[${category}/${type}] ${value:0:80}" ;;
            LOW)    low    "[${category}/${type}] ${value:0:80}" ;;
        esac
        echo "         source → ${source}"
    fi
}
> "$OUT/06_findings/ALL_FINDINGS.txt"

# ── Entropy check — raised to 3.5 for real secrets ───────────────────
check_entropy() {
    local val="$1" threshold="${2:-3.5}"
    python3 -c "
import math, sys
s = sys.argv[1]
t = float(sys.argv[2])
if len(s) < 8: sys.exit(1)
freq = {}
for c in s:
    freq[c] = freq.get(c, 0) + 1
e = -sum((f/len(s))*math.log2(f/len(s)) for f in freq.values())
sys.exit(0 if e >= t else 1)
" "$val" "$threshold" 2>/dev/null
}

# ── False positive check — comprehensive ─────────────────────────────
is_fp() {
    local val="$1"
    # Empty or very short
    [[ -z "$val" || ${#val} -lt 6 ]] && return 0
    # Common placeholders
    echo "$val" | grep -qiE \
        '(YOUR_API|REPLACE_ME|INSERT_HERE|EXAMPLE|placeholder|test123|password123|changeme|xxxx+|1234567890|abcdef+|YOUR_KEY|ADD_YOUR|DUMMY|SAMPLE|FAKE|undefined|null|none|true|false|NaN|void|function|return|window\.|document\.|console\.|Object\.|Array\.|String\.|Number\.|Boolean\.)' \
        && return 0
    # All same character repeated
    python3 -c "
s='''$val'''
if len(set(s)) <= 2: exit(0)
exit(1)
" 2>/dev/null && return 0
    return 1
}

# ── Context validation — check value is real, not code artifact ───────
is_real_value() {
    local val="$1"
    # Skip if looks like JS code/variable
    echo "$val" | grep -qE '^\s*$|^(var|let|const|function|return|if|for|while|class|import|export|this\.|self\.)' && return 1
    # Skip if too many special chars (likely code, not a secret)
    local special_count
    special_count=$(echo "$val" | tr -cd '{}()[]<>;,\n' | wc -c)
    [[ $special_count -gt 3 ]] && return 1
    return 0
}

# ── Skip list — known CDN/library domains (no secrets here) ──────────
is_library_url() {
    local url="$1"
    echo "$url" | grep -qiE \
        '(cdn\.jsdelivr\.net|unpkg\.com|cdnjs\.cloudflare\.com|ajax\.googleapis\.com|code\.jquery\.com|maxcdn\.bootstrapcdn\.com|stackpath\.bootstrapcdn\.com|fonts\.googleapis\.com|polyfill\.io|cdn\.amplitude\.com|cdn\.segment\.com|sentry\.io/js-sdk|browser\.sentry-cdn\.com)' \
        && return 0 || return 1
}

# ── Counter helper ────────────────────────────────────────────────────
inc_counter() { flock "$LOCK_FILE" -c "echo \$(( \$(cat $1) + 1 )) > $1" 2>/dev/null || true; }

# ── Curl with browser headers ─────────────────────────────────────────
_curl() {
    curl -s -L \
        --max-time 20 --connect-timeout 8 \
        -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
        -H "Accept: */*" \
        -H "Accept-Language: en-US,en;q=0.9" \
        -H "Referer: https://${TARGET}/" \
        "$@" 2>/dev/null
}

# ════════════════════════════════════════════════════════════════════════
# STEP 1 — SUBDOMAIN ENUMERATION
# ════════════════════════════════════════════════════════════════════════
step "════ STEP 1: SUBDOMAIN ENUMERATION ════"

RAW_SUBS="$OUT/01_subs/subs_raw.txt"
SUBS="$OUT/01_subs/subs.txt"
> "$RAW_SUBS"

# subfinder
if command -v subfinder &>/dev/null; then
    info "subfinder (all sources)..."
    subfinder -d "$TARGET" -all -silent 2>/dev/null >> "$RAW_SUBS" || true
else warn "subfinder not found — skipping"; fi

# assetfinder
if command -v assetfinder &>/dev/null; then
    info "assetfinder..."
    assetfinder --subs-only "$TARGET" 2>/dev/null >> "$RAW_SUBS" || true
else warn "assetfinder not found — skipping"; fi

# amass passive
if command -v amass &>/dev/null; then
    info "amass passive (timeout 300s)..."
    timeout 300 amass enum -passive -d "$TARGET" \
        -o "$OUT/01_subs/amass.txt" 2>/dev/null || true
    [[ -f "$OUT/01_subs/amass.txt" ]] && cat "$OUT/01_subs/amass.txt" >> "$RAW_SUBS" || true
else warn "amass not found — skipping"; fi

# crt.sh
info "crt.sh..."
curl -s --max-time 30 "https://crt.sh/?q=%25.${TARGET}&output=json" 2>/dev/null \
    | python3 -c "
import sys,json
try:
    data=json.load(sys.stdin)
    for d in data:
        for n in d.get('name_value','').split('\n'):
            print(n.replace('*.','').strip())
except: pass
" 2>/dev/null >> "$RAW_SUBS" || true

# Wayback CDX
info "Wayback CDX subdomains..."
curl -s --max-time 30 \
    "http://web.archive.org/cdx/search/cdx?url=*.${TARGET}&output=text&fl=original&collapse=urlkey" \
    2>/dev/null | grep -oP 'https?://\K[^/]+' \
    | grep -E "\.${TARGET//./\\.}$" >> "$RAW_SUBS" || true

# AlienVault OTX
info "AlienVault OTX..."
curl -s --max-time 30 \
    "https://otx.alienvault.com/api/v1/indicators/domain/${TARGET}/passive_dns" \
    2>/dev/null | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    for r in d.get('passive_dns',[]):
        print(r.get('hostname',''))
except: pass
" 2>/dev/null >> "$RAW_SUBS" || true

# HackerTarget
info "HackerTarget..."
curl -s --max-time 30 \
    "https://api.hackertarget.com/hostsearch/?q=${TARGET}" \
    2>/dev/null | cut -d',' -f1 >> "$RAW_SUBS" || true

# URLScan
info "URLScan..."
curl -s --max-time 30 \
    "https://urlscan.io/api/v1/search/?q=domain:${TARGET}&size=100" \
    2>/dev/null | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    for r in d.get('results',[]):
        print(r.get('page',{}).get('domain',''))
except: pass
" 2>/dev/null >> "$RAW_SUBS" || true

# riddler.io
info "riddler.io..."
curl -s --max-time 30 \
    "https://riddler.io/search/exportcsv?q=pld:${TARGET}" 2>/dev/null \
    | grep -oE "[a-zA-Z0-9._-]+\.${TARGET}" >> "$RAW_SUBS" || true

# github-subdomains
if command -v github-subdomains &>/dev/null && [[ -n "$GITHUB_TOKEN" ]]; then
    info "github-subdomains..."
    github-subdomains -d "$TARGET" -t "$GITHUB_TOKEN" -raw \
        >> "$RAW_SUBS" 2>/dev/null || true
fi

# shosubgo (Shodan)
if command -v shosubgo &>/dev/null; then
    info "shosubgo (Shodan)..."
    shosubgo -d "$TARGET" >> "$RAW_SUBS" 2>/dev/null || true
fi

# Clean and deduplicate
sort -u "$RAW_SUBS" \
    | grep -E "^[a-zA-Z0-9]" \
    | grep -E "\.${TARGET//./\\.}$" \
    | grep -v "^$" > "$SUBS" 2>/dev/null || true

SUBS_COUNT=$(wc -l < "$SUBS")
log "Subdomains found: ${SUBS_COUNT}"

# dnsx resolution + wildcard filtering
if command -v dnsx &>/dev/null; then
    info "Resolving with dnsx..."
    dnsx -l "$SUBS" -silent \
        -o "$OUT/01_subs/resolved_subs.txt" 2>/dev/null || true
    log "Resolved: $(wc -l < "$OUT/01_subs/resolved_subs.txt" 2>/dev/null || echo 0)"
fi

# alterx permutations on confirmed subs
if command -v alterx &>/dev/null && command -v dnsx &>/dev/null; then
    info "alterx permutations (timeout 120s)..."
    touch "$OUT/01_subs/alterx.txt"
    timeout 120 bash -c \
        "alterx -l \"${SUBS}\" -silent | dnsx -silent >> \"$OUT/01_subs/alterx.txt\" 2>/dev/null" \
        || true
    cat "$OUT/01_subs/alterx.txt" >> "$RAW_SUBS" || true
    sort -u "$RAW_SUBS" \
        | grep -E "^[a-zA-Z0-9]" \
        | grep -E "\.${TARGET//./\\.}$" \
        | grep -v "^$" > "$SUBS" 2>/dev/null || true
    log "After alterx: $(wc -l < "$SUBS") subdomains"
fi

# ════════════════════════════════════════════════════════════════════════
# STEP 2 — LIVE HOST FILTERING
# ════════════════════════════════════════════════════════════════════════
step "════ STEP 2: LIVE HOST FILTERING ════"

LIVE_SUBS="$OUT/02_live/live_subs.txt"
> "$LIVE_SUBS"

if command -v httpx &>/dev/null; then
    info "Probing $(wc -l < "$SUBS") subdomains with httpx..."
    httpx -l "$SUBS" \
        -mc 200,301,302,401,403,404 \
        -silent -threads 50 -timeout 10 -retries 2 \
        -follow-redirects \
        -o "$LIVE_SUBS" 2>/dev/null || true
else
    warn "httpx not found — using all subs"
    awk '{print "https://"$1}' "$SUBS" > "$LIVE_SUBS"
fi

LIVE_COUNT=$(wc -l < "$LIVE_SUBS")
log "Live hosts: ${LIVE_COUNT}"

# Plain domains for tools that need them
DOMAINS="$OUT/03_urls/domains_only.txt"
mkdir -p "$OUT/03_urls"
sed 's|https\?://||' "$LIVE_SUBS" | cut -d'/' -f1 | sort -u > "$DOMAINS"

# ════════════════════════════════════════════════════════════════════════
# STEP 3 — URL COLLECTION
# ════════════════════════════════════════════════════════════════════════
step "════ STEP 3: URL COLLECTION ════"

RAW_URLS="$OUT/03_urls/urls_raw.txt"
URLS="$OUT/03_urls/urls.txt"
> "$RAW_URLS"

DOMAIN_COUNT=$(wc -l < "$DOMAINS")
info "Feeding ${DOMAIN_COUNT} domains into URL collectors..."

# 1. waybackurls
if command -v waybackurls &>/dev/null; then
    info "[1/9] waybackurls..."
    cat "$DOMAINS" | waybackurls >> "$RAW_URLS" 2>/dev/null || true
    log "waybackurls → $(wc -l < "$RAW_URLS") URLs"
    sleep 2
else warn "waybackurls not found"; fi

# 2. gau
if command -v gau &>/dev/null; then
    info "[2/9] gau..."
    cat "$DOMAINS" | gau --threads 5 >> "$RAW_URLS" 2>/dev/null || true
    log "gau → $(wc -l < "$RAW_URLS") URLs"
    sleep 2
else warn "gau not found"; fi

# 3. katana
if command -v katana &>/dev/null; then
    info "[3/9] katana (depth 2 + JS parsing)..."
    cat "$LIVE_SUBS" | katana \
        -depth 2 -jc -kf all -fx -silent \
        -rate-limit 10 -nc \
        >> "$RAW_URLS" 2>/dev/null || true
    log "katana → $(wc -l < "$RAW_URLS") URLs"
    sleep 2
else warn "katana not found"; fi

# 4. hakrawler
if command -v hakrawler &>/dev/null; then
    info "[4/9] hakrawler..."
    cat "$LIVE_SUBS" | hakrawler -depth 2 -subs -insecure \
        >> "$RAW_URLS" 2>/dev/null || true
    log "hakrawler → $(wc -l < "$RAW_URLS") URLs"
    sleep 2
else warn "hakrawler not found"; fi

# 5. gospider
if command -v gospider &>/dev/null; then
    info "[5/9] gospider..."
    gospider -S "$LIVE_SUBS" -d 2 --json false -q \
        -o "$OUT/03_urls/gospider_raw" 2>/dev/null || true
    find "$OUT/03_urls/gospider_raw" -maxdepth 1 -type f 2>/dev/null \
        | xargs cat 2>/dev/null \
        | grep -oE 'https?://[^ ]+' >> "$RAW_URLS" || true
    log "gospider → $(wc -l < "$RAW_URLS") URLs"
    sleep 2
else warn "gospider not found"; fi

# 6. paramspider
if command -v paramspider &>/dev/null; then
    info "[6/9] paramspider..."
    PARAM_OUT="$OUT/03_urls/paramspider_out"
    mkdir -p "$PARAM_OUT"
    while IFS= read -r domain; do
        host=$(echo "$domain" | sed 's|https\?://||' | cut -d'/' -f1)
        paramspider -d "$host" --quiet \
            -o "${PARAM_OUT}/${host}.txt" 2>/dev/null || true
    done < "$LIVE_SUBS"
    find "$PARAM_OUT" -name "*.txt" -not -empty 2>/dev/null \
        | xargs cat 2>/dev/null \
        | grep -E "^https?://" >> "$RAW_URLS" || true
    log "paramspider → $(wc -l < "$RAW_URLS") URLs"
    sleep 2
else warn "paramspider not found"; fi

# 7. urlfinder
if command -v urlfinder &>/dev/null; then
    info "[7/9] urlfinder..."
    urlfinder -d "$TARGET" -all -silent \
        -o "$OUT/03_urls/urlfinder.txt" 2>/dev/null || true
    [[ -f "$OUT/03_urls/urlfinder.txt" ]] \
        && cat "$OUT/03_urls/urlfinder.txt" >> "$RAW_URLS" || true
    log "urlfinder → $(wc -l < "$RAW_URLS") URLs"
    sleep 2
else warn "urlfinder not found"; fi

# 8. github-endpoints
if command -v github-endpoints &>/dev/null && [[ -n "$GITHUB_TOKEN" ]]; then
    info "[8/9] github-endpoints..."
    github-endpoints -d "$TARGET" -t "$GITHUB_TOKEN" -raw \
        > "$OUT/03_urls/github_endpoints.txt" 2>/dev/null || true
    grep -E "^https?://" "$OUT/03_urls/github_endpoints.txt" \
        >> "$RAW_URLS" 2>/dev/null || true
    log "github-endpoints → $(wc -l < "$RAW_URLS") URLs"
    sleep 2
fi

# 9. GitHub code mining
if [[ -n "$GITHUB_TOKEN" ]]; then
    info "[9/9] GitHub code mining..."
    GH_OUT="$OUT/03_urls/github/github_urls.txt"
    > "$GH_OUT"
    GH_QUERIES=(
        "${TARGET}"
        "${TARGET} api_key"
        "${TARGET} secret"
        "${TARGET} password"
        "${TARGET} token"
        "${TARGET} mongodb"
        "${TARGET} postgres"
        "${TARGET} aws_access"
        "${TARGET} firebase"
        "${TARGET} internal"
    )
    for query in "${GH_QUERIES[@]}"; do
        encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${query}'))" 2>/dev/null || echo "${query}")
        curl -s \
            -H "Authorization: token ${GITHUB_TOKEN}" \
            -H "Accept: application/vnd.github.v3+json" \
            "https://api.github.com/search/code?q=${encoded}&per_page=100" \
            2>/dev/null | python3 -c "
import sys,json
try:
    data=json.load(sys.stdin)
    for item in data.get('items',[]):
        html_url=item.get('html_url','')
        raw_url=html_url.replace('github.com','raw.githubusercontent.com').replace('/blob/','/')
        repo=item.get('repository',{}).get('full_name','')
        path=item.get('path','')
        if html_url: print(f'[github_code] repo:{repo} file:{path} url:{html_url}')
        if raw_url: print(raw_url)
except: pass
" 2>/dev/null >> "$GH_OUT" || true
        sleep 2
    done
    grep -oE 'https?://raw\.githubusercontent\.com/[^" ]+' "$GH_OUT" \
        >> "$RAW_URLS" 2>/dev/null || true
    log "GitHub mining → $(wc -l < "$GH_OUT") results"
else
    warn "No GitHub token — skipping GitHub mining (use -gt TOKEN)"
fi

# Deduplicate + clean
info "Deduplicating URLs..."
sort -u "$RAW_URLS" \
    | grep -E "^https?://" \
    | grep -F "$TARGET" \
    | python3 -c "
import sys
from urllib.parse import urlsplit,quote,urlunsplit
for line in sys.stdin:
    line=line.strip()
    if not line: continue
    try:
        p=urlsplit(line)
        ep=quote(p.path,safe='/%')
        eq=quote(p.query,safe='=&+%[]@!\$,;:/?')
        print(urlunsplit((p.scheme,p.netloc,ep,eq,p.fragment)))
    except: print(line)
" 2>/dev/null | sort -u > "$URLS" || true

URLS_COUNT=$(wc -l < "$URLS")
log "Total URLs: ${URLS_COUNT}"

# ════════════════════════════════════════════════════════════════════════
# STEP 4 — LIVE URL FILTERING
# ════════════════════════════════════════════════════════════════════════
step "════ STEP 4: LIVE URL FILTERING ════"

LIVE_URLS="$OUT/04_live_urls/live_urls.txt"
AUTH_URLS="$OUT/04_live_urls/authurls.txt"
> "$LIVE_URLS"
> "$AUTH_URLS"

if command -v httpx &>/dev/null; then
    info "Probing $(wc -l < "$URLS") URLs..."
    cat "$URLS" | httpx \
        -mc 200 -silent \
        -threads 100 -timeout 10 -retries 1 \
        -o "$LIVE_URLS" > /dev/null 2>&1 || true
    cat "$URLS" | httpx \
        -mc 200,301,302,401,403 -silent \
        -threads 100 -timeout 10 -retries 1 \
        -o "$AUTH_URLS" > /dev/null 2>&1 || true
else
    cp "$URLS" "$LIVE_URLS"
    cp "$URLS" "$AUTH_URLS"
fi

log "Live (200): $(wc -l < "$LIVE_URLS")"
log "Auth URLs : $(wc -l < "$AUTH_URLS")"

# ════════════════════════════════════════════════════════════════════════
# STEP 5 — ASSET EXTRACTION
# Extract JS, JSON, .env files, webpack chunks from all collected URLs
# ════════════════════════════════════════════════════════════════════════
step "════ STEP 5: ASSET EXTRACTION ════"

JS_VALID="$OUT/05_assets/js/js_valid.txt"
JSON_VALID="$OUT/05_assets/json/json_valid.txt"
ENV_VALID="$OUT/05_assets/env/env_valid.txt"
WEBPACK_VALID="$OUT/05_assets/webpack/webpack_valid.txt"

> "$JS_VALID"
> "$JSON_VALID"
> "$ENV_VALID"
> "$WEBPACK_VALID"

# Source pool — use all collected URLs (live + wayback historical)
ASSET_POOL="$URLS"

info "Extracting assets from URL pool..."

# ── JS files ──────────────────────────────────────────────────────────
sed 's/[[:space:]]*\[[^]]*\]//g' "$LIVE_URLS" \
    | grep -iE '\.js(\?[^#]*)?$' | sort -u >> "$JS_VALID" || true
sed 's/[[:space:]]*\[[^]]*\]//g' "$ASSET_POOL" \
    | grep -iE '\.js(\?[^#]*)?$' | sort -u >> "$JS_VALID" || true

# ── JSON files ────────────────────────────────────────────────────────
# Catch all common JSON files including config, manifest, swagger, etc.
grep -iE '\.(json|jsonld)(\?[^#]*)?$' "$ASSET_POOL" >> "$JSON_VALID" 2>/dev/null || true
grep -iE '/(config|manifest|settings|swagger|openapi|api-docs|package|app|firebase|vercel|next\.config|nuxt\.config|angular\.json|tsconfig|appsettings|\.well-known/[^/]+)(\.[a-zA-Z]+)?(\?[^#]*)?$' \
    "$ASSET_POOL" >> "$JSON_VALID" 2>/dev/null || true

# ── .env files ────────────────────────────────────────────────────────
# These are the jackpot — all common .env locations
grep -iE '/(\.env|\.env\.(local|development|production|staging|test|backup|old|example|prod|dev|docker|k8s)|env\.js|env\.json|config\.env|application\.env)(\?[^#]*)?$' \
    "$ASSET_POOL" >> "$ENV_VALID" 2>/dev/null || true
# Also probe common .env paths directly on each live host
while IFS= read -r host; do
    for envpath in \
        "/.env" "/.env.local" "/.env.production" "/.env.staging" \
        "/.env.backup" "/.env.old" "/.env.example" "/.env.prod" \
        "/api/.env" "/app/.env" "/backend/.env" "/server/.env" \
        "/config/.env" "/src/.env" "/.env.development.local" \
        "/env" "/env.js" "/config/env.js" "/js/env.js" \
        "/.aws/credentials" "/.netrc" "/credentials.json" \
        "/config/database.yml" "/config/database.php" \
        "/config/secrets.yml" "/application.properties" \
        "/application.yml" "/appsettings.json" "/web.config"; do
        echo "${host%/}${envpath}" >> "$ENV_VALID"
    done
done < "$LIVE_SUBS"

# ── Webpack chunks ────────────────────────────────────────────────────
# Regular webpack bundles
grep -iE '/(static/js|static/chunks|_next/static|js/chunk|chunks?)\.[a-f0-9]+\.(js|chunk\.js)' \
    "$ASSET_POOL" >> "$WEBPACK_VALID" 2>/dev/null || true
# Also catch named chunks
grep -iE 'chunk\.[a-f0-9]{8,}\.(js|min\.js)' \
    "$ASSET_POOL" >> "$WEBPACK_VALID" 2>/dev/null || true

# ── Final clean — unique valid https URLs ────────────────────────────
for f in "$JS_VALID" "$JSON_VALID" "$ENV_VALID" "$WEBPACK_VALID"; do
    sort -u "$f" -o "$f" 2>/dev/null || true
    grep -Ei '^https?://' "$f" | grep -v 'is_library' | sort -u > /tmp/asset_clean_$$.txt \
        && mv /tmp/asset_clean_$$.txt "$f" || true
    # Remove known CDN/library URLs
    grep -viE '(cdn\.jsdelivr\.net|unpkg\.com|cdnjs\.cloudflare\.com|ajax\.googleapis\.com|code\.jquery\.com|maxcdn\.bootstrapcdn\.com|stackpath\.bootstrapcdn\.com|fonts\.googleapis\.com|polyfill\.io)' \
        "$f" > /tmp/asset_cdn_$$.txt && mv /tmp/asset_cdn_$$.txt "$f" || true
done

JS_COUNT=$(wc -l < "$JS_VALID")
JSON_COUNT=$(wc -l < "$JSON_VALID")
ENV_COUNT=$(wc -l < "$ENV_VALID")
WEBPACK_COUNT=$(wc -l < "$WEBPACK_VALID")

log "JS files      : ${JS_COUNT}"
log "JSON files    : ${JSON_COUNT}"
log ".env paths    : ${ENV_COUNT}"
log "Webpack chunks: ${WEBPACK_COUNT}"


# ════════════════════════════════════════════════════════════════════════
# STEP 6 — DEEP ANALYSIS ENGINE
# Patterns, confidence scoring, JS/JSON/ENV analysis
# ════════════════════════════════════════════════════════════════════════
step "════ STEP 6: DEEP ANALYSIS ENGINE ════"

> "$OUT/06_findings/ALL_FINDINGS.txt"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ALL DETECTION PATTERNS
# Confidence levels: HIGH = exact format, LOW FP
#                    MEDIUM = format match, needs context
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# ── CLOUD — HIGH confidence (exact formats, real impact) ─────────────
P_AWS_KEY='AKIA[0-9A-Z]{16}'
P_AWS_SECRET='(?i)aws[_\-\s]?secret[_\-\s]?access[_\-\s]?key[\s:="'\''`]+([A-Za-z0-9/+=]{40})'
P_AWS_SESSION='AQoD[a-zA-Z0-9/+=]{100,}|ASIA[0-9A-Z]{16}'
P_GCP_KEY='AIza[0-9A-Za-z\-_]{35}'
P_GCP_SA='[a-z0-9\-]+@[a-z0-9\-]+\.iam\.gserviceaccount\.com'
P_AZURE_SECRET='(?i)azure[_\-\s]?client[_\-\s]?secret[\s:="'\''`]+([a-zA-Z0-9~._\-]{30,})'
P_AZURE_CONN='DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{86}==;'
P_SUPABASE_KEY='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_\-]{50,}\.[a-zA-Z0-9_\-]{30,}'
P_CLOUDFLARE_KEY='(?i)cloudflare[_\-\s]?(?:api[_\-]?key|token|secret)[\s:="'\''`]+([a-zA-Z0-9_\-]{37,})'
P_DIGITALOCEAN='(?i)digitalocean[_\-\s]?(?:token|api[_\-]?key|secret)[\s:="'\''`]+([a-zA-Z0-9]{64})'

# ── AI & ML — HIGH confidence ─────────────────────────────────────────
P_OPENAI='sk-[a-zA-Z0-9]{48}'
P_OPENAI_NEW='sk-proj-[a-zA-Z0-9_\-]{100,}'
P_OPENAI_ORG='org-[a-zA-Z0-9]{24}'
P_ANTHROPIC='sk-ant-[a-zA-Z0-9_\-]{95,}'
P_HUGGINGFACE='hf_[a-zA-Z0-9]{37}'
P_REPLICATE='r8_[a-zA-Z0-9]{40}'
P_GROQ='gsk_[a-zA-Z0-9]{52}'
P_COHERE='(?i)cohere[_\-\s]?(?:api[_\-]?)?key[\s:="'\''`]+([a-zA-Z0-9]{40,})'
P_STABILITY='sk-[a-zA-Z0-9]{32,}'
P_TOGETHER='(?i)together[_\-\s]?(?:api[_\-]?)?key[\s:="'\''`]+([a-zA-Z0-9]{64})'

# ── AUTH & IDENTITY — HIGH confidence ────────────────────────────────
P_JWT='eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}'
P_FIREBASE_FCM='AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}'
P_FIREBASE_URL='https://[a-z0-9\-]+\.firebaseio\.com'
P_FIREBASE_APIKEY='(?i)(?:firebase|firebaseConfig)[^{]{0,50}apiKey[\s:="'\''`]+([A-Za-z0-9_\-]{39})'
P_AUTH0='(?i)auth0[_\-\s]?(?:client[_\-]?secret|token|domain)[\s:="'\''`]+([a-zA-Z0-9_\-\.]{20,})'
P_OKTA='(?i)okta[_\-\s]?(?:api[_\-]?token|secret|client[_\-]?secret)[\s:="'\''`]+([a-zA-Z0-9_\-]{40,})'
P_CLERK_LIVE='sk_live_[a-zA-Z0-9]{40,}'
P_CLERK_TEST='sk_test_[a-zA-Z0-9]{40,}'
P_OAUTH_SECRET='(?i)oauth[_\-\s]?client[_\-\s]?secret[\s:="'\''`]+([a-zA-Z0-9_\-]{20,})'
P_COGNITO='(?i)cognito[_\-\s]?(?:identity[_\-]?pool[_\-]?id|user[_\-]?pool[_\-]?id|client[_\-]?id)[\s:="'\''`]+([a-zA-Z0-9_\-:+]{20,})'

# ── PAYMENT — HIGH confidence ─────────────────────────────────────────
P_STRIPE_LIVE='sk_live_[0-9a-zA-Z]{24,}'
P_STRIPE_TEST='sk_test_[0-9a-zA-Z]{24,}'
P_STRIPE_PK='pk_(live|test)_[0-9a-zA-Z]{24,}'
P_STRIPE_WH='whsec_[a-zA-Z0-9]{32,}'
P_STRIPE_RESTRICTED='rk_live_[0-9a-zA-Z]{24,}'
P_RAZORPAY='rzp_(live|test)_[a-zA-Z0-9]{14}'
P_BRAINTREE='access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}'
P_SQUARE_TOKEN='sq0atp-[0-9A-Za-z\-_]{22}'
P_SQUARE_SECRET='sq0csp-[0-9A-Za-z\-_]{43}'
P_PAYPAL='(?i)paypal[_\-\s]?(?:client[_\-\s]?secret|access[_\-]?token)[\s:="'\''`]+([a-zA-Z0-9_\-]{20,})'
P_ADYEN='(?i)adyen[_\-\s]?(?:api[_\-]?key|hmac[_\-]?key)[\s:="'\''`]+([a-zA-Z0-9+/=]{30,})'
P_MIDTRANS='(?i)midtrans[_\-\s]?(?:server|client)[_\-\s]?key[\s:="'\''`]+([A-Za-z0-9\-]{20,})'
P_XENDIT='xnd_(?:production|development)_[a-zA-Z0-9]{40,}'
P_FLUTTERWAVE='(?i)flutterwave[_\-\s]?(?:secret|public)[_\-\s]?key[\s:="'\''`]+([a-zA-Z0-9_\-]{20,})'
P_PAYSTACK='(?i)(?:sk|pk)_(?:live|test)_[a-zA-Z0-9]{40}'

# ── SOURCE CONTROL — HIGH confidence ─────────────────────────────────
P_GH_PAT='ghp_[0-9a-zA-Z]{36}'
P_GH_PAT_NEW='github_pat_[0-9a-zA-Z_]{82}'
P_GH_OAUTH='gho_[0-9a-zA-Z]{36}'
P_GH_USER='ghu_[0-9a-zA-Z]{36}'
P_GH_SERVER='ghs_[0-9a-zA-Z]{36}'
P_GH_REFRESH='ghr_[0-9a-zA-Z]{76}'
P_GITLAB='glpat-[a-zA-Z0-9_\-]{20}'
P_GITLAB_RUNNER='GR1348941[a-zA-Z0-9_\-]{20}'
P_BITBUCKET='(?i)bitbucket[_\-\s]?(?:token|password|consumer[_\-]?secret)[\s:="'\''`]+([a-zA-Z0-9+/=]{20,})'

# ── API KEYS — MEDIUM confidence (needs entropy + context check) ──────
P_BEARER='(?i)(?:Bearer|Authorization)\s*[:\s]\s*([a-zA-Z0-9_\-\.]{30,})'
P_API_KEY='(?i)(?:api[_\-]?key|apikey)\s*[=:]\s*["\x27`]([a-zA-Z0-9_\-]{20,})["\x27`]'
P_GENERIC_SECRET='(?i)(?<!description\s)(?:client[_\-]?secret|app[_\-]?secret|consumer[_\-]?secret)\s*[=:]\s*["\x27`]([a-zA-Z0-9_\-]{20,})["\x27`]'
P_GENERIC_TOKEN='(?i)(?:access[_\-]?token|auth[_\-]?token)\s*[=:]\s*["\x27`]([a-zA-Z0-9_\-]{20,})["\x27`]'
P_GENERIC_PASS='(?i)(?:password|passwd|pass)\s*[=:]\s*["\x27`]([^"'\''`\s]{8,})["\x27`]'
P_PRIVATE_KEY_HEADER='-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY(?:-----| BLOCK-----)'

# ── EMAIL & MESSAGING — HIGH confidence ──────────────────────────────
P_SENDGRID='SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}'
P_MAILGUN='key-[a-zA-Z0-9]{32}'
P_MAILCHIMP='[0-9a-f]{32}-us[0-9]{1,2}'
P_POSTMARK='(?i)postmark[_\-\s]?(?:server[_\-]?token|api[_\-]?token)[\s:="'\''`]+([a-zA-Z0-9\-]{36})'
P_SPARKPOST='(?i)sparkpost[_\-\s]?api[_\-\s]?key[\s:="'\''`]+([a-zA-Z0-9]{40})'
P_RESEND='re_[a-zA-Z0-9]{36}'
P_BREVO='xkeysib-[a-zA-Z0-9]{64}'
P_COURIER='(?i)courier[_\-\s]?(?:auth[_\-]?token|api[_\-]?key)[\s:="'\''`]+([a-zA-Z0-9_\-]{40,})'
P_TWILIO_SID='AC[a-z0-9]{32}'
P_TWILIO_AUTH='SK[a-z0-9]{32}'
P_SLACK_TOKEN='xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[0-9a-zA-Z]{24,}'
P_SLACK_WH='https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+'
P_DISCORD_TOKEN='(?<![a-zA-Z])[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27}'
P_DISCORD_WH='https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_\-]+'
P_TELEGRAM='[0-9]{8,10}:[a-zA-Z0-9_\-]{35}'
P_VONAGE='(?i)vonage[_\-\s]?api[_\-\s]?(?:key|secret)[\s:="'\''`]+([a-zA-Z0-9]{8,})'

# ── MONITORING — HIGH confidence ──────────────────────────────────────
P_DATADOG='(?i)datadog[_\-\s]?(?:api|app)[_\-\s]?key[\s:="'\''`]+([a-zA-Z0-9]{32,40})'
P_NEW_RELIC='NRAK-[A-Z0-9]{27}'
P_SENTRY_DSN='https://[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io/[0-9]+'
P_ROLLBAR='(?i)rollbar[_\-\s]?(?:server[_\-]?token|post[_\-]?token)[\s:="'\''`]+([a-zA-Z0-9]{32})'
P_PAGERDUTY='(?i)pagerduty[_\-\s]?(?:api[_\-]?key|service[_\-]?key)[\s:="'\''`]+([a-zA-Z0-9+/=]{20,})'
P_GRAFANA_FARO='(?i)(?:faro|grafana)[_\-\s]?(?:api[_\-]?key|token)[\s:="'\''`]+([a-f0-9\-]{32,})'
P_LOGROCKET='(?i)logrocket[_\-\s]?(?:api[_\-]?key|app[_\-]?id)[\s:="'\''`]+([a-zA-Z0-9_\-/]{10,})'
P_BUGSNAG='(?i)bugsnag[_\-\s]?(?:api[_\-]?key|notifier[_\-]?key)[\s:="'\''`]+([a-f0-9]{32})'

# ── ANALYTICS — HIGH confidence ───────────────────────────────────────
P_AMPLITUDE='(?i)amplitude[_\-\s]?(?:api[_\-]?key|secret[_\-]?key)[\s:="'\''`]+([a-zA-Z0-9]{32})'
P_MIXPANEL='(?i)mixpanel[_\-\s]?token[\s:="'\''`]+([a-zA-Z0-9]{32})'
P_SEGMENT='(?i)(?:segment[_\-\s]?)?write[_\-]?key[\s:="'\''`]+([a-zA-Z0-9]{32,})'
P_POSTHOG='phc_[a-zA-Z0-9]{43}'
P_LAUNCHDARKLY='(?i)(?:sdk[_\-]?key|client[_\-]?side[_\-]?id)[\s:="'\''`]+([a-zA-Z0-9\-_]{20,})'
P_ALGOLIA_APP='(?i)algolia[_\-\s]?app(?:lication)?[_\-\s]?id[\s:="'\''`]+([A-Z0-9]{10})'
P_ALGOLIA_KEY='(?i)algolia[_\-\s]?(?:api|search|admin)[_\-\s]?key[\s:="'\''`]+([a-zA-Z0-9]{32})'
P_PUSHER='(?i)pusher[_\-\s]?(?:app[_\-]?key|app[_\-]?secret)[\s:="'\''`]+([a-zA-Z0-9]{8,})'
P_ONESIGNAL='(?i)onesignal[_\-\s]?(?:app[_\-]?id|rest[_\-]?api[_\-]?key)[\s:="'\''`]+([a-zA-Z0-9\-]{36,})'
P_INTERCOM='(?i)intercom[_\-\s]?(?:access[_\-]?token|api[_\-]?key|secret[_\-]?key)[\s:="'\''`]+([a-zA-Z0-9_\-]{20,})'

# ── SAAS — MEDIUM/HIGH ────────────────────────────────────────────────
P_NOTION='secret_[a-zA-Z0-9]{43}'
P_MAPBOX='pk\.[a-zA-Z0-9_\-]{60,}'
P_AIRTABLE='pat[a-zA-Z0-9]{14}\.[a-zA-Z0-9]{64}|key[a-zA-Z0-9]{14}'
P_DROPBOX='sl\.[A-Za-z0-9_\-]{100,}'
P_HUBSPOT='pat-[a-z]{2}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
P_ZENDESK='(?i)zendesk[_\-\s]?(?:api[_\-]?token|oauth[_\-]?token)[\s:="'\''`]+([a-zA-Z0-9/+]{40})'
P_LINEAR='lin_api_[a-zA-Z0-9]{40}'
P_FIGMA='(?i)figma[_\-\s]?(?:token|api[_\-]?key)[\s:="'\''`]+([a-zA-Z0-9\-_]{40,})'
P_CLOUDINARY='cloudinary://[a-zA-Z0-9]+:[a-zA-Z0-9_\-]+@[a-zA-Z0-9]+'
P_CLOUDINARY_URL='(?i)cloudinary_url[\s:="'\''`]+cloudinary://[^\s"'\''`]+'
P_TWILIO_SENDGRID='SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}'

# ── CI/CD — HIGH confidence ───────────────────────────────────────────
P_NPM='npm_[a-zA-Z0-9]{36}'
P_PYPI='pypi-[a-zA-Z0-9_\-]{100,}'
P_RUBYGEMS='rubygems_[a-zA-Z0-9]{48}'
P_DOCKER='dckr_pat_[a-zA-Z0-9_\-]{32,}'
P_VERCEL='(?i)vercel[_\-\s]?(?:token|access[_\-]?token)[\s:="'\''`]+([a-zA-Z0-9_\-]{24,})'
P_NETLIFY='(?i)netlify[_\-\s]?(?:access[_\-]?token|auth[_\-]?token)[\s:="'\''`]+([a-zA-Z0-9_\-]{40,})'
P_CIRCLECI='(?i)circle[_\-\s]?ci[_\-\s]?token[\s:="'\''`]+([a-zA-Z0-9]{40})'
P_TRAVIS='(?i)travis[_\-\s]?(?:api[_\-]?key|access[_\-]?token)[\s:="'\''`]+([a-zA-Z0-9_\-]{22})'
P_HEROKU='(?i)heroku[_\-\s]?api[_\-\s]?key[\s:="'\''`]+([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})'

# ── ECOMMERCE ─────────────────────────────────────────────────────────
P_SHOPIFY='shpat_[a-fA-F0-9]{32}'
P_SHOPIFY_PRIV='shppa_[a-fA-F0-9]{32}'
P_SHOPIFY_SEC='shpss_[a-fA-F0-9]{32}'
P_SHOPIFY_CUSTOM='shpca_[a-fA-F0-9]{32}'
P_WOO_KEY='ck_[a-zA-Z0-9]{40}'
P_WOO_SECRET='cs_[a-zA-Z0-9]{40}'
P_WOOCOMMERCE_WH='(?i)woocommerce[_\-\s]?(?:webhook[_\-]?secret|consumer[_\-]?secret)[\s:="'\''`]+([a-zA-Z0-9]{40})'

# ── DATABASE — HIGH confidence (connection strings = instant win) ─────
P_MONGO='mongodb(?:\+srv)?://[a-zA-Z0-9_%\-\.]+:[^@\s"'\''`]+@[a-zA-Z0-9._\-:]+'
P_POSTGRES='postgres(?:ql)?://[a-zA-Z0-9_%\-\.]+:[^@\s"'\''`]+@[a-zA-Z0-9._\-:]+'
P_MYSQL='mysql(?:2)?://[a-zA-Z0-9_%\-\.]+:[^@\s"'\''`]+@[a-zA-Z0-9._\-:]+'
P_REDIS='redis(?:s)?://(?:[a-zA-Z0-9_%\-\.]+:[^@\s"'\''`]+@)?[a-zA-Z0-9._\-]+:[0-9]+'
P_ELASTIC='https?://[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-]+@[a-zA-Z0-9._\-]+:9200'
P_MSSQL='(?i)Server=[^;]+;Database=[^;]+;User[^;]+;Password=[^;]+'
P_SQLITE='(?i)sqlite[_\-\s]?(?:db[_\-]?path|database[_\-]?path|uri)[\s:="'\''`]+([a-zA-Z0-9/._\-]+\.(?:db|sqlite|sqlite3))'
P_PLANETSCALE='(?i)pscale://[a-zA-Z0-9_\-]+:[^@\s"'\''`]+@[a-zA-Z0-9._\-]+'
P_NEON='(?i)postgresql://[a-zA-Z0-9._\-]+:[^@\s"'\''`]+@[a-zA-Z0-9._\-]+\.neon\.tech'
P_TURSO='libsql://[a-zA-Z0-9_\-]+\.turso\.io'

# ── INFRASTRUCTURE ────────────────────────────────────────────────────
P_GRAPHQL='/(graphql|v[0-9]+/graphql|api/graphql|gql)(?:[/?#]|$)'
P_ACTUATOR='/(actuator|management)/(env|health|metrics|trace|heapdump|dump|threaddump|loggers|sessions|mappings)(?:[/?#]|$)'
P_DEBUG_ENDPOINT='/(debug|_debug|__debug__|debugger|trace|profiler|console|shell)(?:[/?#]|$)'
P_METADATA_AWS='http://169\.254\.169\.254/(latest|[0-9\-]+)/(meta-data|user-data|dynamic)'
P_METADATA_GCP='http://metadata(?:\.google)?\.internal/computeMetadata'
P_INTERNAL_HOST='(?i)https?://(internal|staging|dev|test|qa|preprod|backup|uat|sandbox)\.[a-zA-Z0-9\-]+\.'
P_FEATURE_FLAG='(?i)(feature[_\-]?flag|debug[_\-]?mode|admin[_\-]?mode|dev[_\-]?mode)\s*[=:]\s*["\x27]?(true|1|enabled)'
P_TOKEN_IN_URL='[?&](token|access_token|auth_token|api_key|key|secret|password|passwd)=[a-zA-Z0-9\-_\.%+]{10,}'
P_STORAGE_URL='https?://[a-zA-Z0-9_\-]+\.(?:s3|s3-[a-z0-9\-]+)\.amazonaws\.com|https?://storage\.googleapis\.com/[a-zA-Z0-9_\-]+|https?://[a-zA-Z0-9_\-]+\.blob\.core\.windows\.net'
P_SOURCEMAP='//# sourceMappingURL=([^\s]+\.map)'
P_PRIVATE_IP='(?<![0-9])(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})(?![0-9])'

# ── CAPTCHA KEYS (exposed = bypass) ──────────────────────────────────
P_RECAPTCHA_SITE='6L[a-zA-Z0-9_\-]{38}'
P_RECAPTCHA_SECRET='(?i)recaptcha[_\-\s]?secret[\s:="'\''`]+([a-zA-Z0-9_\-]{40})'
P_HCAPTCHA='(?i)hcaptcha[_\-\s]?secret[\s:="'\''`]+0x[a-fA-F0-9]{40}'
P_TURNSTILE='(?i)turnstile[_\-\s]?secret[\s:="'\''`]+([0-9A-Za-z_\-]{30,})'

# ── PII ───────────────────────────────────────────────────────────────
P_EMAIL='[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
P_SSN='(?<![0-9])[0-9]{3}-[0-9]{2}-[0-9]{4}(?![0-9])'
P_CC='(?<![0-9])[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}(?![0-9])'


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# analyze_js() — Deep JS content analysis
# Called with: analyze_js <url> <content>
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
analyze_js() {
    local url="$1"
    local content="$2"
    [[ -z "$content" ]] && return

    # Helper: pattern → confidence → category → type
    _cs() {
        local pattern="$1" conf="$2" cat="$3" type="$4"
        while IFS= read -r match; do
            [[ -z "$match" ]] && continue
            is_fp "$match"      && continue
            is_real_value "$match" || continue
            # HIGH confidence patterns skip entropy (exact formats)
            if [[ "$conf" == "MEDIUM" ]]; then
                check_entropy "$match" 3.5 || continue
            fi
            save_finding "$conf" "$cat" "$type" "$match" "$url"
        done < <(echo "$content" | grep -oP "$pattern" 2>/dev/null | sort -u || true)
    }

    # ── CLOUD — HIGH ─────────────────────────────────────────────────
    _cs "$P_AWS_KEY"        HIGH cloud_secrets aws_access_key_id
    _cs "$P_AWS_SECRET"     HIGH cloud_secrets aws_secret_access_key
    _cs "$P_AWS_SESSION"    HIGH cloud_secrets aws_session_token
    _cs "$P_GCP_KEY"        HIGH cloud_secrets gcp_api_key
    _cs "$P_GCP_SA"         HIGH cloud_secrets gcp_service_account
    _cs "$P_AZURE_SECRET"   HIGH cloud_secrets azure_client_secret
    _cs "$P_AZURE_CONN"     HIGH cloud_secrets azure_storage_conn_string
    _cs "$P_SUPABASE_KEY"   HIGH cloud_secrets supabase_jwt_key
    _cs "$P_CLOUDFLARE_KEY" HIGH cloud_secrets cloudflare_api_key
    _cs "$P_DIGITALOCEAN"   HIGH cloud_secrets digitalocean_token

    # ── AI / ML — HIGH ───────────────────────────────────────────────
    _cs "$P_OPENAI"         HIGH ai_ml openai_api_key
    _cs "$P_OPENAI_NEW"     HIGH ai_ml openai_project_key
    _cs "$P_OPENAI_ORG"     HIGH ai_ml openai_org_id
    _cs "$P_ANTHROPIC"      HIGH ai_ml anthropic_api_key
    _cs "$P_HUGGINGFACE"    HIGH ai_ml huggingface_token
    _cs "$P_REPLICATE"      HIGH ai_ml replicate_token
    _cs "$P_GROQ"           HIGH ai_ml groq_api_key
    _cs "$P_COHERE"         HIGH ai_ml cohere_api_key
    _cs "$P_TOGETHER"       HIGH ai_ml together_ai_key

    # ── AUTH — HIGH ───────────────────────────────────────────────────
    _cs "$P_JWT"            HIGH auth_tokens jwt_token
    _cs "$P_FIREBASE_FCM"   HIGH auth_tokens firebase_fcm_server_key
    _cs "$P_FIREBASE_APIKEY" HIGH auth_tokens firebase_api_key
    _cs "$P_AUTH0"          HIGH auth_tokens auth0_secret
    _cs "$P_OKTA"           HIGH auth_tokens okta_api_token
    _cs "$P_CLERK_LIVE"     HIGH auth_tokens clerk_live_key
    _cs "$P_CLERK_TEST"     HIGH auth_tokens clerk_test_key
    _cs "$P_OAUTH_SECRET"   HIGH auth_tokens oauth_client_secret
    _cs "$P_COGNITO"        HIGH auth_tokens aws_cognito_id

    # ── PAYMENT — HIGH ────────────────────────────────────────────────
    _cs "$P_STRIPE_LIVE"     HIGH payment stripe_live_secret_key
    _cs "$P_STRIPE_TEST"     HIGH payment stripe_test_secret_key
    _cs "$P_STRIPE_PK"       HIGH payment stripe_publishable_key
    _cs "$P_STRIPE_WH"       HIGH payment stripe_webhook_secret
    _cs "$P_STRIPE_RESTRICTED" HIGH payment stripe_restricted_key
    _cs "$P_RAZORPAY"        HIGH payment razorpay_key
    _cs "$P_BRAINTREE"       HIGH payment braintree_access_token
    _cs "$P_SQUARE_TOKEN"    HIGH payment square_token
    _cs "$P_SQUARE_SECRET"   HIGH payment square_secret
    _cs "$P_PAYPAL"          HIGH payment paypal_client_secret
    _cs "$P_ADYEN"           HIGH payment adyen_api_key
    _cs "$P_MIDTRANS"        HIGH payment midtrans_server_key
    _cs "$P_XENDIT"          HIGH payment xendit_secret_key
    _cs "$P_FLUTTERWAVE"     HIGH payment flutterwave_secret_key
    _cs "$P_PAYSTACK"        HIGH payment paystack_key

    # ── SOURCE CONTROL — HIGH ─────────────────────────────────────────
    _cs "$P_GH_PAT"          HIGH source_control github_pat
    _cs "$P_GH_PAT_NEW"      HIGH source_control github_pat_v2
    _cs "$P_GH_OAUTH"        HIGH source_control github_oauth_token
    _cs "$P_GH_USER"         HIGH source_control github_user_token
    _cs "$P_GH_SERVER"       HIGH source_control github_server_token
    _cs "$P_GH_REFRESH"      HIGH source_control github_refresh_token
    _cs "$P_GITLAB"          HIGH source_control gitlab_pat
    _cs "$P_GITLAB_RUNNER"   HIGH source_control gitlab_runner_token
    _cs "$P_BITBUCKET"       HIGH source_control bitbucket_token

    # ── API KEYS — MEDIUM (needs entropy + context) ───────────────────
    _cs "$P_BEARER"          MEDIUM api_keys bearer_token
    _cs "$P_API_KEY"         MEDIUM api_keys generic_api_key
    _cs "$P_GENERIC_SECRET"  MEDIUM api_keys generic_client_secret
    _cs "$P_GENERIC_TOKEN"   MEDIUM api_keys generic_access_token
    _cs "$P_GENERIC_PASS"    MEDIUM api_keys hardcoded_password

    # Private key headers — always HIGH (literal match)
    while IFS= read -r match; do
        [[ -z "$match" ]] && continue
        save_finding HIGH api_keys private_key_header "$match" "$url"
    done < <(echo "$content" | grep -oP "$P_PRIVATE_KEY_HEADER" 2>/dev/null | sort -u || true)

    # ── MESSAGING — HIGH ──────────────────────────────────────────────
    _cs "$P_SENDGRID"        HIGH communication sendgrid_api_key
    _cs "$P_MAILGUN"         HIGH communication mailgun_api_key
    _cs "$P_MAILCHIMP"       HIGH communication mailchimp_api_key
    _cs "$P_POSTMARK"        HIGH communication postmark_server_token
    _cs "$P_SPARKPOST"       HIGH communication sparkpost_api_key
    _cs "$P_RESEND"          HIGH communication resend_api_key
    _cs "$P_BREVO"           HIGH communication brevo_api_key
    _cs "$P_TWILIO_SID"      HIGH communication twilio_account_sid
    _cs "$P_TWILIO_AUTH"     HIGH communication twilio_auth_token
    _cs "$P_SLACK_TOKEN"     HIGH communication slack_bot_token
    _cs "$P_SLACK_WH"        HIGH communication slack_webhook_url
    _cs "$P_DISCORD_TOKEN"   HIGH communication discord_bot_token
    _cs "$P_DISCORD_WH"      HIGH communication discord_webhook_url
    _cs "$P_TELEGRAM"        HIGH communication telegram_bot_token
    _cs "$P_VONAGE"          HIGH communication vonage_api_key

    # ── MONITORING — HIGH ─────────────────────────────────────────────
    _cs "$P_DATADOG"         HIGH monitoring datadog_api_key
    _cs "$P_NEW_RELIC"       HIGH monitoring new_relic_ingest_key
    _cs "$P_SENTRY_DSN"      HIGH monitoring sentry_dsn
    _cs "$P_ROLLBAR"         HIGH monitoring rollbar_server_token
    _cs "$P_PAGERDUTY"       HIGH monitoring pagerduty_api_key
    _cs "$P_GRAFANA_FARO"    HIGH monitoring grafana_faro_api_key
    _cs "$P_LOGROCKET"       HIGH monitoring logrocket_api_key
    _cs "$P_BUGSNAG"         HIGH monitoring bugsnag_api_key

    # ── ANALYTICS — MEDIUM ────────────────────────────────────────────
    _cs "$P_AMPLITUDE"       MEDIUM saas amplitude_api_key
    _cs "$P_MIXPANEL"        MEDIUM saas mixpanel_token
    _cs "$P_SEGMENT"         MEDIUM saas segment_write_key
    _cs "$P_POSTHOG"         HIGH   saas posthog_api_key
    _cs "$P_LAUNCHDARKLY"    MEDIUM saas launchdarkly_sdk_key
    _cs "$P_ALGOLIA_APP"     MEDIUM saas algolia_app_id
    _cs "$P_ALGOLIA_KEY"     HIGH   saas algolia_api_key
    _cs "$P_PUSHER"          MEDIUM saas pusher_app_key
    _cs "$P_ONESIGNAL"       MEDIUM saas onesignal_api_key
    _cs "$P_INTERCOM"        MEDIUM saas intercom_access_token
    _cs "$P_CLOUDINARY"      HIGH   saas cloudinary_url

    # ── SAAS ──────────────────────────────────────────────────────────
    _cs "$P_NOTION"          HIGH saas notion_integration_token
    _cs "$P_MAPBOX"          HIGH saas mapbox_public_token
    _cs "$P_AIRTABLE"        HIGH saas airtable_api_key
    _cs "$P_DROPBOX"         HIGH saas dropbox_access_token
    _cs "$P_HUBSPOT"         HIGH saas hubspot_private_app_token
    _cs "$P_ZENDESK"         HIGH saas zendesk_api_token
    _cs "$P_LINEAR"          HIGH saas linear_api_key
    _cs "$P_FIGMA"           HIGH saas figma_personal_token

    # ── CI/CD ─────────────────────────────────────────────────────────
    _cs "$P_NPM"             HIGH cicd npm_token
    _cs "$P_DOCKER"          HIGH cicd docker_hub_pat
    _cs "$P_VERCEL"          HIGH cicd vercel_token
    _cs "$P_NETLIFY"         HIGH cicd netlify_access_token
    _cs "$P_CIRCLECI"        HIGH cicd circleci_token
    _cs "$P_TRAVIS"          HIGH cicd travis_ci_token
    _cs "$P_HEROKU"          HIGH cicd heroku_api_key

    # ── ECOMMERCE ─────────────────────────────────────────────────────
    _cs "$P_SHOPIFY"         HIGH ecommerce shopify_admin_token
    _cs "$P_SHOPIFY_PRIV"    HIGH ecommerce shopify_private_app_key
    _cs "$P_SHOPIFY_SEC"     HIGH ecommerce shopify_shared_secret
    _cs "$P_SHOPIFY_CUSTOM"  HIGH ecommerce shopify_custom_app_token
    _cs "$P_WOO_KEY"         HIGH ecommerce woocommerce_consumer_key
    _cs "$P_WOO_SECRET"      HIGH ecommerce woocommerce_consumer_secret

    # ── DATABASE — HIGH (connection strings) ──────────────────────────
    _cs "$P_MONGO"           HIGH database mongodb_connection_string
    _cs "$P_POSTGRES"        HIGH database postgresql_connection_string
    _cs "$P_MYSQL"           HIGH database mysql_connection_string
    _cs "$P_REDIS"           HIGH database redis_connection_string
    _cs "$P_ELASTIC"         HIGH database elasticsearch_credentials
    _cs "$P_MSSQL"           HIGH database mssql_connection_string
    _cs "$P_PLANETSCALE"     HIGH database planetscale_connection
    _cs "$P_NEON"            HIGH database neon_postgres_url
    _cs "$P_TURSO"           HIGH database turso_db_url

    # ── CAPTCHA — MEDIUM ─────────────────────────────────────────────
    _cs "$P_RECAPTCHA_SITE"  MEDIUM api_keys recaptcha_site_key
    _cs "$P_RECAPTCHA_SECRET" HIGH  api_keys recaptcha_secret_key
    _cs "$P_HCAPTCHA"        HIGH   api_keys hcaptcha_secret_key
    _cs "$P_TURNSTILE"       HIGH   api_keys cloudflare_turnstile_secret

    # ── INFRASTRUCTURE ────────────────────────────────────────────────
    while IFS= read -r match; do
        [[ -z "$match" ]] && continue
        save_finding MEDIUM infrastructure graphql_endpoint "$match" "$url"
    done < <(echo "$content" | grep -oP "$P_GRAPHQL" 2>/dev/null | sort -u || true)

    while IFS= read -r match; do
        [[ -z "$match" ]] && continue
        save_finding HIGH infrastructure actuator_endpoint_exposed "$match" "$url"
    done < <(echo "$content" | grep -oP "$P_ACTUATOR" 2>/dev/null | sort -u || true)

    while IFS= read -r match; do
        [[ -z "$match" ]] && continue
        save_finding MEDIUM infrastructure debug_endpoint "$match" "$url"
    done < <(echo "$content" | grep -oP "$P_DEBUG_ENDPOINT" 2>/dev/null | sort -u || true)

    while IFS= read -r match; do
        [[ -z "$match" ]] && continue
        save_finding HIGH infrastructure aws_metadata_ssrf_url "$match" "$url"
    done < <(echo "$content" | grep -oP "$P_METADATA_AWS" 2>/dev/null | sort -u || true)

    while IFS= read -r match; do
        [[ -z "$match" ]] && continue
        save_finding HIGH infrastructure gcp_metadata_ssrf_url "$match" "$url"
    done < <(echo "$content" | grep -oP "$P_METADATA_GCP" 2>/dev/null | sort -u || true)

    while IFS= read -r match; do
        [[ -z "$match" ]] && continue
        save_finding MEDIUM infrastructure internal_hostname "$match" "$url"
    done < <(echo "$content" | grep -oP "$P_INTERNAL_HOST" 2>/dev/null | sort -u || true)

    while IFS= read -r match; do
        [[ -z "$match" ]] && continue
        save_finding MEDIUM infrastructure feature_flag_enabled "$match" "$url"
    done < <(echo "$content" | grep -oP "$P_FEATURE_FLAG" 2>/dev/null | sort -u || true)

    while IFS= read -r match; do
        [[ -z "$match" ]] && continue
        save_finding HIGH infrastructure token_in_url "$match" "$url"
    done < <(echo "$content" | grep -oP "$P_TOKEN_IN_URL" 2>/dev/null | sort -u || true)

    while IFS= read -r match; do
        [[ -z "$match" ]] && continue
        save_finding MEDIUM storage cloud_storage_bucket_url "$match" "$url"
    done < <(echo "$content" | grep -oP "$P_STORAGE_URL" 2>/dev/null | sort -u || true)

    # Firebase DB URL — check for .json open access
    while IFS= read -r fburl; do
        [[ -z "$fburl" ]] && continue
        save_finding HIGH infrastructure firebase_db_url "$fburl" "$url"
    done < <(echo "$content" | grep -oP "$P_FIREBASE_URL" 2>/dev/null | sort -u || true)

    # Private IPs
    while IFS= read -r match; do
        [[ -z "$match" ]] && continue
        save_finding MEDIUM infrastructure private_ip_hardcoded "$match" "$url"
    done < <(echo "$content" | grep -oP "$P_PRIVATE_IP" 2>/dev/null | sort -u || true)

    # PII
    while IFS= read -r match; do
        [[ -z "$match" ]] && continue
        echo "$match" | grep -qiE "(example|test|noreply|no-reply|support|info@|admin@|hello@|contact@|user@|mail@|do-not-reply|donotreply)" && continue
        is_fp "$match" && continue
        save_finding MEDIUM pii email_address "$match" "$url"
    done < <(echo "$content" | grep -oP "$P_EMAIL" 2>/dev/null | sort -u || true)

    while IFS= read -r match; do
        [[ -z "$match" ]] && continue
        save_finding HIGH pii ssn_pattern "$match" "$url"
    done < <(echo "$content" | grep -oP "$P_SSN" 2>/dev/null | sort -u || true)

    while IFS= read -r match; do
        [[ -z "$match" ]] && continue
        save_finding HIGH pii credit_card_number "$match" "$url"
    done < <(echo "$content" | grep -oP "$P_CC" 2>/dev/null | sort -u || true)

    # ── API endpoints from JS (deep) ──────────────────────────────────
    while IFS= read -r route; do
        [[ -z "$route" ]] && continue
        save_finding MEDIUM endpoints api_endpoint_in_js "$route" "$url"
    done < <(echo "$content" | \
        grep -oE '"/(api|v[0-9]+|admin|internal|debug|graphql|auth|user|account|dashboard|config|payment|webhook|stripe|twilio|sendgrid|firebase)[a-zA-Z0-9_/.\-]*"' \
        2>/dev/null | tr -d '"' | sort -u || true)

    # fetch()/axios()/XHR calls — extract endpoint being called
    while IFS= read -r match; do
        [[ -z "$match" ]] && continue
        save_finding MEDIUM endpoints fetch_axios_call "$match" "$url"
    done < <(echo "$content" | \
        grep -oP '(?:fetch|axios\.(?:get|post|put|delete|patch)|new XMLHttpRequest)\s*\(\s*["\x27`](https?://[^"'\''`\s]{10,})["\x27`]' \
        2>/dev/null | grep -oP 'https?://[^"'\''`\s]{10,}' | sort -u || true)

    # Environment variable names exposed to frontend (Next.js/React)
    while IFS= read -r match; do
        [[ -z "$match" ]] && continue
        save_finding MEDIUM infrastructure env_var_exposed_to_frontend "$match" "$url"
    done < <(echo "$content" | \
        grep -oP 'process\.env\.[A-Z_][A-Z0-9_]{3,}' \
        2>/dev/null | sort -u || true)

    # window.__INITIAL_STATE__, window.__REDUX_STATE__ etc — config dump
    while IFS= read -r match; do
        [[ -z "$match" ]] && continue
        is_fp "$match" && continue
        save_finding MEDIUM infrastructure global_state_object "$match" "$url"
    done < <(echo "$content" | \
        grep -oP '(?:window|self|globalThis)\.__[A-Z_]+__\s*=' \
        2>/dev/null | sort -u || true)

    # Source maps
    while IFS= read -r mapfile; do
        [[ -z "$mapfile" ]] && continue
        save_finding MEDIUM endpoints sourcemap_reference "$mapfile" "$url"
    done < <(echo "$content" | grep -oP "$P_SOURCEMAP" 2>/dev/null | \
        grep -oP '[^\s]+\.map' | sort -u || true)

    # Dev comments containing sensitive words — STRICT filter
    while IFS= read -r comment; do
        [[ -z "$comment" ]] && continue
        # Must have a value after the keyword — not just mentioning it
        echo "$comment" | grep -qiE '(password|secret|key|token|credential|api)[=:\s]+[a-zA-Z0-9_\-]{8,}' || continue
        save_finding LOW dev_comments sensitive_dev_comment "$comment" "$url"
    done < <(echo "$content" | \
        grep -oP '//[^\n]{0,200}' 2>/dev/null | \
        grep -iE "(password|secret|key|token|credential|private|bypass|backdoor|admin|internal)" | \
        head -10 | sort -u || true)
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# analyze_json() — Parse JSON properly with python3
# Walks the entire JSON tree recursively — no grep noise
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
analyze_json() {
    local url="$1"
    local filepath="$2"
    [[ ! -s "$filepath" ]] && return

    python3 << PYEOF 2>/dev/null
import json, re, sys, os

url = """$url"""
filepath = """$filepath"""
out_dir = """$OUT/06_findings"""
all_findings = """$OUT/06_findings/ALL_FINDINGS.txt"""

# Secret patterns — applied to JSON values
PATTERNS = {
    # HIGH confidence — exact formats
    "HIGH": {
        "aws_access_key_id":       r'AKIA[0-9A-Z]{16}',
        "aws_secret_access_key":   r'(?i)^[A-Za-z0-9/+=]{40}$',
        "gcp_api_key":             r'AIza[0-9A-Za-z\-_]{35}',
        "openai_api_key":          r'sk-[a-zA-Z0-9]{48}',
        "openai_project_key":      r'sk-proj-[a-zA-Z0-9_\-]{100,}',
        "anthropic_key":           r'sk-ant-[a-zA-Z0-9_\-]{95,}',
        "github_pat":              r'ghp_[0-9a-zA-Z]{36}',
        "github_pat_v2":           r'github_pat_[0-9a-zA-Z_]{82}',
        "stripe_live_key":         r'sk_live_[0-9a-zA-Z]{24,}',
        "stripe_test_key":         r'sk_test_[0-9a-zA-Z]{24,}',
        "stripe_webhook":          r'whsec_[a-zA-Z0-9]{32,}',
        "razorpay_key":            r'rzp_(live|test)_[a-zA-Z0-9]{14}',
        "firebase_fcm_key":        r'AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}',
        "sendgrid_key":            r'SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}',
        "slack_token":             r'xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[0-9a-zA-Z]{24,}',
        "slack_webhook":           r'https://hooks\.slack\.com/services/',
        "discord_webhook":         r'https://discord(app)?\.com/api/webhooks/',
        "discord_bot_token":       r'[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27}',
        "telegram_bot_token":      r'[0-9]{8,10}:[a-zA-Z0-9_\-]{35}',
        "mongodb_uri":             r'mongodb(\+srv)?://[a-zA-Z0-9_%\-\.]+:[^@\s"]+@',
        "postgresql_uri":          r'postgres(ql)?://[a-zA-Z0-9_%\-\.]+:[^@\s"]+@',
        "mysql_uri":               r'mysql(2)?://[a-zA-Z0-9_%\-\.]+:[^@\s"]+@',
        "redis_uri":               r'redis(s)?://[^\s"]{10,}:[0-9]+',
        "shopify_token":           r'shp(at|pa|ss|ca)_[a-fA-F0-9]{32}',
        "gitlab_pat":              r'glpat-[a-zA-Z0-9_\-]{20}',
        "npm_token":               r'npm_[a-zA-Z0-9]{36}',
        "huggingface_token":       r'hf_[a-zA-Z0-9]{37}',
        "posthog_key":             r'phc_[a-zA-Z0-9]{43}',
        "sentry_dsn":              r'https://[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io/',
        "private_key":             r'-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY',
        "jwt_token":               r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}',
        "firebase_db_url":         r'https://[a-z0-9\-]+\.firebaseio\.com',
        "twilio_account_sid":      r'AC[a-z0-9]{32}',
        "twilio_auth_token":       r'SK[a-z0-9]{32}',
        "mailgun_key":             r'key-[a-zA-Z0-9]{32}',
        "notion_token":            r'secret_[a-zA-Z0-9]{43}',
        "mapbox_token":            r'pk\.[a-zA-Z0-9_\-]{60,}',
        "new_relic_key":           r'NRAK-[A-Z0-9]{27}',
        "docker_token":            r'dckr_pat_[a-zA-Z0-9_\-]{32,}',
        "azure_storage_connstring":r'DefaultEndpointsProtocol=https;AccountName=',
        "cloudinary_url":          r'cloudinary://[a-zA-Z0-9]+:[a-zA-Z0-9_\-]+@',
        "linear_api_key":          r'lin_api_[a-zA-Z0-9]{40}',
        "groq_api_key":            r'gsk_[a-zA-Z0-9]{52}',
        "resend_api_key":          r're_[a-zA-Z0-9]{36}',
        "brevo_api_key":           r'xkeysib-[a-zA-Z0-9]{64}',
        "xendit_key":              r'xnd_(?:production|development)_[a-zA-Z0-9]{40,}',
        "paystack_key":            r'(?:sk|pk)_(?:live|test)_[a-zA-Z0-9]{40}',
    },
    # MEDIUM confidence — need context from the key name
    "MEDIUM": {
        "api_key":           r'[a-zA-Z0-9_\-]{20,}',
        "secret":            r'[a-zA-Z0-9_\-]{20,}',
        "token":             r'[a-zA-Z0-9_\-]{20,}',
        "password":          r'.{8,}',
        "private_key":       r'.{20,}',
        "client_secret":     r'[a-zA-Z0-9_\-]{20,}',
        "access_token":      r'[a-zA-Z0-9_\-\.]{20,}',
        "refresh_token":     r'[a-zA-Z0-9_\-\.]{20,}',
        "signing_key":       r'[a-zA-Z0-9_\-]{20,}',
        "encryption_key":    r'[a-zA-Z0-9_\-+/=]{20,}',
        "db_password":       r'.{6,}',
        "database_url":      r'https?://.{10,}',
        "connection_string": r'.{20,}',
    }
}

FP_WORDS = {'YOUR_API', 'REPLACE_ME', 'INSERT_HERE', 'EXAMPLE', 'placeholder',
            'test123', 'password123', 'changeme', 'YOUR_KEY', 'ADD_YOUR',
            'DUMMY', 'SAMPLE', 'FAKE', 'undefined', 'null', 'none', 'true',
            'false', 'YOUR_SECRET', 'xxxxxxxxxxxx', 'aaaaaaaaaaaa'}

SENSITIVE_KEYS = {'api_key','apikey','api_secret','secret','secret_key',
                  'private_key','password','passwd','pass','token','access_token',
                  'refresh_token','auth_token','client_secret','signing_key',
                  'encryption_key','database_url','connection_string',
                  'db_password','db_pass','mongo_uri','postgres_uri','redis_url',
                  'jwt_secret','webhook_secret','hmac_secret','stripe_key',
                  'stripe_secret','firebase_key','sendgrid_key','twilio_token',
                  'slack_token','discord_token','aws_secret','gcp_key','azure_secret',
                  'openai_key','anthropic_key','huggingface_token','replicate_token'}

def shannon_entropy(s):
    if len(s) < 8: return 0
    freq = {}
    for c in s: freq[c] = freq.get(c, 0) + 1
    return -sum((f/len(s)) * __import__('math').log2(f/len(s)) for f in freq.values())

def is_fp(val):
    if not val or len(str(val)) < 6: return True
    sv = str(val).strip().upper()
    for fp in FP_WORDS:
        if fp in sv: return True
    if len(set(sv)) <= 2: return True
    return False

def save(conf, cat, typ, val, src):
    entry = f"[{conf}][{typ}:{val}] source {src}\n"
    # dedup
    try:
        with open(all_findings, 'r') as f:
            if f"[{typ}:{val}]" in f.read(): return
    except: pass
    cat_dir = os.path.join(out_dir, conf, cat)
    os.makedirs(cat_dir, exist_ok=True)
    with open(os.path.join(cat_dir, f"{typ}.txt"), 'a') as f:
        f.write(entry)
    with open(all_findings, 'a') as f:
        f.write(entry)
    level = {"HIGH": "[HIGH]", "MEDIUM": "[MEDIUM]", "LOW": "[LOW]"}[conf]
    print(f"\033[1;31m{level}\033[0m [{cat}/{typ}] {str(val)[:80]}")
    print(f"         source → {src}")

def walk(obj, path=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            walk(v, f"{path}.{k}" if path else k)
            # Check if key name is sensitive
            k_lower = k.lower().replace('-','_').replace(' ','_')
            if isinstance(v, (str, int, float)) and v and not is_fp(str(v)):
                val = str(v).strip()
                # HIGH patterns — check every value
                for pat_name, pat in PATTERNS["HIGH"].items():
                    if re.search(pat, val):
                        save("HIGH", infer_category(pat_name), pat_name, val, url)
                        break
                # MEDIUM — only if key name is suspicious
                if k_lower in SENSITIVE_KEYS or any(s in k_lower for s in ('key','secret','token','password','pass','credential','auth')):
                    if len(val) >= 8 and shannon_entropy(val) >= 3.5:
                        for pat_name in PATTERNS["MEDIUM"]:
                            if k_lower.endswith(pat_name.replace('_','')) or pat_name in k_lower:
                                save("MEDIUM", "api_keys", f"suspicious_{k_lower}", val, url)
                                break
                        else:
                            save("MEDIUM", "api_keys", f"suspicious_{k_lower}", val, url)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            walk(item, f"{path}[{i}]")
    elif isinstance(obj, str):
        # Check string values directly for HIGH patterns
        for pat_name, pat in PATTERNS["HIGH"].items():
            if re.search(pat, obj):
                if not is_fp(obj):
                    save("HIGH", infer_category(pat_name), pat_name, obj, url)

def infer_category(pat_name):
    if any(x in pat_name for x in ('aws','gcp','azure','cloud','supabase','cloudflare','digitalocean')): return 'cloud_secrets'
    if any(x in pat_name for x in ('stripe','razorpay','paypal','braintree','square','adyen','payment','xendit','paystack','flutterwave')): return 'payment'
    if any(x in pat_name for x in ('mongodb','postgresql','mysql','redis','elasticsearch','mssql','sqlite','neon','turso','planetscale')): return 'database'
    if any(x in pat_name for x in ('github','gitlab','bitbucket')): return 'source_control'
    if any(x in pat_name for x in ('openai','anthropic','huggingface','replicate','groq','cohere','together')): return 'ai_ml'
    if any(x in pat_name for x in ('sendgrid','mailgun','mailchimp','twilio','slack','discord','telegram','brevo','resend','vonage')): return 'communication'
    if any(x in pat_name for x in ('sentry','datadog','newrelic','pagerduty','rollbar','grafana','logrocket','bugsnag')): return 'monitoring'
    if any(x in pat_name for x in ('shopify','woocommerce')): return 'ecommerce'
    if any(x in pat_name for x in ('npm','docker','vercel','netlify','circleci','travis','heroku')): return 'cicd'
    if any(x in pat_name for x in ('jwt','firebase','auth0','okta','clerk','oauth','cognito')): return 'auth_tokens'
    if any(x in pat_name for x in ('private_key','rsa','openssh','pgp')): return 'api_keys'
    if any(x in pat_name for x in ('notion','mapbox','airtable','dropbox','hubspot','zendesk','linear','figma','cloudinary','posthog')): return 'saas'
    return 'api_keys'

try:
    with open(filepath, 'r', errors='replace') as f:
        raw = f.read()
    data = json.loads(raw)
    walk(data)
except json.JSONDecodeError:
    # Not valid JSON — run grep patterns on raw content
    for pat_name, pat in PATTERNS["HIGH"].items():
        for match in re.findall(pat, raw):
            if match and not is_fp(match):
                save("HIGH", infer_category(pat_name), pat_name, match, url)
except Exception as e:
    pass
PYEOF
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# analyze_env() — Parse .env / config files
# These are the most valuable — every variable is suspect
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
analyze_env() {
    local url="$1"
    local content="$2"
    [[ -z "$content" ]] && return

    # .env files: KEY=VALUE format — every line is a potential secret
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        [[ "$line" == \#* ]] && continue  # skip comments
        # Split on first = only
        local key="${line%%=*}"
        local val="${line#*=}"
        # Strip quotes
        val="${val#\"}" ; val="${val%\"}"
        val="${val#\'}"  ; val="${val%\'}"
        val="${val// /}"

        [[ -z "$key" || -z "$val" ]] && continue
        is_fp "$val" && continue

        local key_upper="${key^^}"

        # Determine confidence by key name
        local conf="LOW"
        if echo "$key_upper" | grep -qE "(SECRET|PASSWORD|PASSWD|PRIVATE_KEY|TOKEN|CREDENTIAL|API_KEY|APIKEY|ACCESS_KEY|AUTH_KEY|SIGNING_KEY|ENCRYPTION_KEY|MASTER_KEY|WEBHOOK_SECRET|JWT_SECRET|DB_PASS|DATABASE_URL|MONGO_URI|REDIS_URL|POSTGRES|CONNECTION_STRING|STRIPE|SENDGRID|TWILIO|SLACK|DISCORD|TELEGRAM|AWS_SECRET|GCP_KEY|AZURE|FIREBASE|GITHUB_TOKEN|GITLAB_TOKEN|OPENAI|ANTHROPIC|HUGGINGFACE)"; then
            conf="HIGH"
        elif echo "$key_upper" | grep -qE "(URL|HOST|PORT|USER|NAME|ID|KEY|TOKEN|ENV|MODE|DEBUG|BASE|ENDPOINT|DOMAIN|REGION)"; then
            conf="MEDIUM"
        fi

        # Always run HIGH patterns regardless
        local matched=false
        for pat in "$P_AWS_KEY" "$P_GCP_KEY" "$P_OPENAI" "$P_ANTHROPIC" "$P_STRIPE_LIVE" "$P_STRIPE_TEST" \
                   "$P_GH_PAT" "$P_MONGO" "$P_POSTGRES" "$P_MYSQL" "$P_REDIS" \
                   "$P_JWT" "$P_SENDGRID" "$P_SLACK_TOKEN" "$P_DISCORD_WH" "$P_TELEGRAM" \
                   "$P_FIREBASE_FCM" "$P_SHOPIFY" "$P_RAZORPAY" "$P_GROQ" "$P_PRIVATE_KEY_HEADER"; do
            if echo "$val" | grep -qP "$pat" 2>/dev/null; then
                local matched_val
                matched_val=$(echo "$val" | grep -oP "$pat" 2>/dev/null | head -1)
                [[ -n "$matched_val" ]] && save_finding HIGH cloud_secrets "env_${key,,}" "$matched_val" "$url"
                matched=true
                break
            fi
        done

        if [[ "$matched" == "false" && "$conf" != "LOW" ]]; then
            # Check entropy for MEDIUM/HIGH key names
            check_entropy "$val" 3.5 && save_finding "$conf" api_keys "env_${key,,}" "$val" "$url" || true
        fi

    done <<< "$content"

    # Also run full JS analysis on .env content (catches multi-line values, URLs)
    analyze_js "$url" "$content"
}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# WORKER — fetch + analyze a single asset (JS, JSON, ENV)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
process_asset() {
    local asseturl="$1"
    local assettype="$2"   # js | json | env | webpack
    local idx="$3"
    local total="$4"

    [[ -z "$asseturl" ]] && return

    # Skip known CDN/library URLs
    is_library_url "$asseturl" && return

    inc_counter "$COUNTER_FILE"
    local cur; cur=$(cat "$COUNTER_FILE")
    echo -e "${BOLD}[${cur}/${total}][${assettype^^}]${NC} ${asseturl:0:110}"

    local tmpfile; tmpfile=$(mktemp /tmp/elite_asset_XXXXXX)

    local http_code
    http_code=$(_curl \
        --max-time 25 --connect-timeout 8 \
        -w "%{http_code}" -o "$tmpfile" \
        "$asseturl" 2>/dev/null || echo "000")

    # Rate limit backoff
    if [[ "$http_code" == "429" ]]; then
        warn "[Worker-$$] Rate limited — backing off 20s"
        sleep 20
        http_code=$(_curl --max-time 25 -w "%{http_code}" -o "$tmpfile" "$asseturl" 2>/dev/null || echo "000")
    fi

    case "$http_code" in
        200|206) ;;
        000|403|404|410|429|5*)
            inc_counter "$FAILED_FILE"
            echo "  ✗ HTTP ${http_code} — skipping"
            rm -f "$tmpfile"; sleep 0.2; return ;;
    esac

    local filesize; filesize=$(wc -c < "$tmpfile" 2>/dev/null || echo 0)
    if [[ "$filesize" -lt 10 ]]; then
        inc_counter "$FAILED_FILE"
        rm -f "$tmpfile"; sleep 0.2; return
    fi

    inc_counter "$SUCCESS_FILE"
    echo -e "  ${GREEN}✓ HTTP ${http_code} | ${filesize} bytes${NC}"

    # Record this asset was fetched
    flock "$LOCK_FILE" -c \
        "echo '[asset:${asseturl}] type:${assettype} size:${filesize}' >> '$OUT/06_findings/assets_fetched.txt'" \
        2>/dev/null || true

    # ── Source map probe (for JS + webpack) ──────────────────────────
    if [[ "$assettype" == "js" || "$assettype" == "webpack" ]]; then
        local mapurl="${asseturl%%\?*}.map"
        local maptmp; maptmp=$(mktemp /tmp/elite_map_XXXXXX.json)
        local map_code
        map_code=$(_curl --max-time 10 -w "%{http_code}" -o "$maptmp" "$mapurl" 2>/dev/null || echo "000")
        if [[ "$map_code" == "200" ]] && [[ -s "$maptmp" ]]; then
            echo -e "  ${MAGENTA}[SOURCE MAP EXPOSED] ${mapurl}${NC}"
            save_finding HIGH endpoints sourcemap_exposed "$mapurl" "$asseturl"
            # Extract original source file paths
            python3 -c "
import sys,json
try:
    d=json.load(open('$maptmp'))
    for s in d.get('sources',[]):
        print(s)
except: pass
" 2>/dev/null | head -30 | while read -r src; do
                [[ -n "$src" ]] && save_finding MEDIUM endpoints sourcemap_original_source "$src" "$mapurl"
            done
        fi
        rm -f "$maptmp"
    fi

    # ── Strip null bytes + analyze ───────────────────────────────────
    local content
    content=$(tr -d '\000' < "$tmpfile" 2>/dev/null || echo "")

    case "$assettype" in
        js|webpack)
            analyze_js "$asseturl" "$content"
            ;;
        json)
            analyze_json "$asseturl" "$tmpfile"
            # Also run JS analysis on raw content (catches embedded secrets)
            analyze_js "$asseturl" "$content"
            ;;
        env)
            analyze_env "$asseturl" "$content"
            ;;
    esac

    rm -f "$tmpfile"
    sleep 0.3
}

# ── Setup counters + locks ────────────────────────────────────────────
COUNTER_FILE=$(mktemp /tmp/elite_counter_XXXXXX)
SUCCESS_FILE=$(mktemp /tmp/elite_success_XXXXXX)
FAILED_FILE=$(mktemp /tmp/elite_failed_XXXXXX)
LOCK_FILE=$(mktemp /tmp/elite_lock_XXXXXX)
echo 0 > "$COUNTER_FILE"; echo 0 > "$SUCCESS_FILE"; echo 0 > "$FAILED_FILE"
touch "$LOCK_FILE"

# ── Export everything for subshells ──────────────────────────────────
export -f process_asset analyze_js analyze_json analyze_env save_finding \
           check_entropy is_fp is_real_value is_library_url \
           inc_counter warn info high med low active log step _curl
export OUT TARGET LOG ACTIVE_MODE LOCK_FILE COUNTER_FILE SUCCESS_FILE FAILED_FILE
export RED GREEN YELLOW CYAN MAGENTA BLUE BOLD NC
# Export all patterns
export P_AWS_KEY P_AWS_SECRET P_AWS_SESSION P_GCP_KEY P_GCP_SA
export P_AZURE_SECRET P_AZURE_CONN P_SUPABASE_KEY P_CLOUDFLARE_KEY P_DIGITALOCEAN
export P_OPENAI P_OPENAI_NEW P_OPENAI_ORG P_ANTHROPIC P_HUGGINGFACE P_REPLICATE P_GROQ P_COHERE P_STABILITY P_TOGETHER
export P_JWT P_FIREBASE_FCM P_FIREBASE_URL P_FIREBASE_APIKEY P_AUTH0 P_OKTA
export P_CLERK_LIVE P_CLERK_TEST P_OAUTH_SECRET P_COGNITO
export P_STRIPE_LIVE P_STRIPE_TEST P_STRIPE_PK P_STRIPE_WH P_STRIPE_RESTRICTED
export P_RAZORPAY P_BRAINTREE P_SQUARE_TOKEN P_SQUARE_SECRET P_PAYPAL P_ADYEN
export P_MIDTRANS P_XENDIT P_FLUTTERWAVE P_PAYSTACK
export P_GH_PAT P_GH_PAT_NEW P_GH_OAUTH P_GH_USER P_GH_SERVER P_GH_REFRESH
export P_GITLAB P_GITLAB_RUNNER P_BITBUCKET
export P_BEARER P_API_KEY P_GENERIC_SECRET P_GENERIC_TOKEN P_GENERIC_PASS P_PRIVATE_KEY_HEADER
export P_SENDGRID P_MAILGUN P_MAILCHIMP P_POSTMARK P_SPARKPOST P_RESEND P_BREVO P_COURIER
export P_TWILIO_SID P_TWILIO_AUTH P_SLACK_TOKEN P_SLACK_WH
export P_DISCORD_TOKEN P_DISCORD_WH P_TELEGRAM P_VONAGE
export P_DATADOG P_NEW_RELIC P_SENTRY_DSN P_ROLLBAR P_PAGERDUTY P_GRAFANA_FARO P_LOGROCKET P_BUGSNAG
export P_AMPLITUDE P_MIXPANEL P_SEGMENT P_POSTHOG P_LAUNCHDARKLY
export P_ALGOLIA_APP P_ALGOLIA_KEY P_PUSHER P_ONESIGNAL P_INTERCOM
export P_NOTION P_MAPBOX P_AIRTABLE P_DROPBOX P_HUBSPOT P_ZENDESK P_LINEAR P_FIGMA
export P_CLOUDINARY P_CLOUDINARY_URL
export P_NPM P_PYPI P_RUBYGEMS P_DOCKER P_VERCEL P_NETLIFY P_CIRCLECI P_TRAVIS P_HEROKU
export P_SHOPIFY P_SHOPIFY_PRIV P_SHOPIFY_SEC P_SHOPIFY_CUSTOM P_WOO_KEY P_WOO_SECRET P_WOOCOMMERCE_WH
export P_MONGO P_POSTGRES P_MYSQL P_REDIS P_ELASTIC P_MSSQL P_SQLITE P_PLANETSCALE P_NEON P_TURSO
export P_GRAPHQL P_ACTUATOR P_DEBUG_ENDPOINT P_METADATA_AWS P_METADATA_GCP
export P_INTERNAL_HOST P_FEATURE_FLAG P_TOKEN_IN_URL P_STORAGE_URL P_SOURCEMAP P_PRIVATE_IP
export P_RECAPTCHA_SITE P_RECAPTCHA_SECRET P_HCAPTCHA P_TURNSTILE
export P_EMAIL P_SSN P_CC
export P_GCP_SA P_STRIPE_RESTRICTED

# ── Build combined asset list ─────────────────────────────────────────
COMBINED_ASSETS=$(mktemp /tmp/elite_assets_XXXXXX)

# Tag each URL with its type
while IFS= read -r u; do [[ -n "$u" ]] && echo "js|${u}"; done < "$JS_VALID" >> "$COMBINED_ASSETS"
while IFS= read -r u; do [[ -n "$u" ]] && echo "webpack|${u}"; done < "$WEBPACK_VALID" >> "$COMBINED_ASSETS"
while IFS= read -r u; do [[ -n "$u" ]] && echo "json|${u}"; done < "$JSON_VALID" >> "$COMBINED_ASSETS"
while IFS= read -r u; do [[ -n "$u" ]] && echo "env|${u}"; done < "$ENV_VALID" >> "$COMBINED_ASSETS"

TOTAL_ASSETS=$(wc -l < "$COMBINED_ASSETS")
log "Total assets to analyze: ${TOTAL_ASSETS} (JS:${JS_COUNT} Webpack:${WEBPACK_COUNT} JSON:${JSON_COUNT} ENV:${ENV_COUNT})"

WORKERS=5
info "Starting analysis — ${WORKERS} parallel workers..."

# ── Parallel execution ────────────────────────────────────────────────
run_asset() {
    local line="$1"
    local idx="$2"
    local type="${line%%|*}"
    local url="${line#*|}"
    process_asset "$url" "$type" "$idx" "$TOTAL_ASSETS"
}
export -f run_asset

if command -v parallel &>/dev/null; then
    parallel -j "$WORKERS" --keep-order \
        run_asset {} {#} \
        :::: "$COMBINED_ASSETS"
else
    warn "GNU parallel not found — using manual worker pool"
    job_count=0; idx=0
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        idx=$((idx + 1))
        run_asset "$line" "$idx" &
        job_count=$((job_count + 1))
        if [[ $job_count -ge $WORKERS ]]; then wait; job_count=0; fi
        if [[ $((idx % 20)) -eq 0 ]]; then
            echo ""
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            echo "  Progress  : ${idx}/${TOTAL_ASSETS}"
            echo "  Success   : $(cat "$SUCCESS_FILE") | Failed: $(cat "$FAILED_FILE")"
            echo "  HIGH hits : $(grep -c '\[HIGH\]' "$OUT/06_findings/ALL_FINDINGS.txt" 2>/dev/null || echo 0)"
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            echo ""
        fi
    done < "$COMBINED_ASSETS"
    wait
fi

rm -f "$COMBINED_ASSETS"

ASSETS_SCANNED=$(cat "$COUNTER_FILE" 2>/dev/null || echo 0)
ASSETS_SUCCESS=$(cat "$SUCCESS_FILE" 2>/dev/null || echo 0)
ASSETS_FAILED=$(cat  "$FAILED_FILE"  2>/dev/null || echo 0)
rm -f "$COUNTER_FILE" "$SUCCESS_FILE" "$FAILED_FILE" "$LOCK_FILE"

# Deduplicate all findings
find "$OUT/06_findings" -name "*.txt" | while read -r f; do
    [[ -s "$f" ]] && sort -u "$f" -o "$f"
done

TOTAL_FINDINGS=$(wc -l < "$OUT/06_findings/ALL_FINDINGS.txt" 2>/dev/null || echo 0)
HIGH_COUNT=$(grep -c '\[HIGH\]' "$OUT/06_findings/ALL_FINDINGS.txt" 2>/dev/null || echo 0)
MED_COUNT=$(grep -c '\[MEDIUM\]' "$OUT/06_findings/ALL_FINDINGS.txt" 2>/dev/null || echo 0)

log "Analysis complete — Scanned: ${ASSETS_SCANNED} | Success: ${ASSETS_SUCCESS} | Findings: ${TOTAL_FINDINGS} (HIGH: ${HIGH_COUNT} MEDIUM: ${MED_COUNT})"


# ════════════════════════════════════════════════════════════════════════
# STEP 7 — INLINE SCRIPT EXTRACTION FROM HTML PAGES
# Fetches live HTML pages, extracts <script> block contents
# Secrets hardcoded in <script> tags are missed by JS file grep
# ════════════════════════════════════════════════════════════════════════
step "════ STEP 7: INLINE SCRIPT EXTRACTION ════"

INLINE_OUT="$OUT/05_assets/html_scripts"
HTML_FINDINGS="$OUT/06_findings/ALL_FINDINGS.txt"

# Pick top 200 live URLs (homepage + important pages — too many = slow)
HEAD_URLS=$(mktemp /tmp/elite_html_XXXXXX)
# Prioritize: homepages, login, dashboard, config, account pages
grep -iE '/(login|signin|dashboard|account|profile|config|settings|admin|app|portal|checkout|payment|index|home)?$' \
    "$LIVE_URLS" 2>/dev/null | head -100 >> "$HEAD_URLS" || true
# Add live subs root pages
sed 's|/$||' "$LIVE_SUBS" | head -100 >> "$HEAD_URLS" || true
sort -u "$HEAD_URLS" -o "$HEAD_URLS"

HTML_TOTAL=$(wc -l < "$HEAD_URLS")
info "Extracting inline scripts from ${HTML_TOTAL} HTML pages..."

COUNTER_FILE=$(mktemp /tmp/elite_counter_XXXXXX)
LOCK_FILE=$(mktemp /tmp/elite_lock_XXXXXX)
echo 0 > "$COUNTER_FILE"; touch "$LOCK_FILE"

process_html() {
    local pageurl="$1"
    [[ -z "$pageurl" ]] && return

    local tmphtml; tmphtml=$(mktemp /tmp/elite_html_XXXXXX.html)

    local http_code
    http_code=$(_curl --max-time 20 -w "%{http_code}" -o "$tmphtml" "$pageurl" 2>/dev/null || echo "000")

    [[ "$http_code" != "200" ]] && { rm -f "$tmphtml"; return; }
    [[ ! -s "$tmphtml" ]] && { rm -f "$tmphtml"; return; }

    inc_counter "$COUNTER_FILE"
    local cur; cur=$(cat "$COUNTER_FILE")
    echo -e "  ${CYAN}[${cur}]${NC} Inline scripts → ${pageurl:0:90}"

    # Extract content of every <script> block (not src= links)
    python3 << PYEOF 2>/dev/null
import re, sys

with open("$tmphtml", "r", errors="replace") as f:
    html = f.read()

# Extract inline script blocks
scripts = re.findall(r'<script(?:\s+[^>]*)?>([\s\S]*?)</script>', html, re.IGNORECASE)

pageurl = """$pageurl"""
out_dir = """$INLINE_OUT"""

for i, script in enumerate(scripts):
    script = script.strip()
    if len(script) < 20: continue
    # Skip if this is just a JSON config that is already in JSON list
    # Save script content to file for analysis
    import os
    os.makedirs(out_dir, exist_ok=True)
    # Use hash to avoid duplicates
    import hashlib
    h = hashlib.md5(script.encode()).hexdigest()[:8]
    outfile = os.path.join(out_dir, f"inline_{h}.js")
    if not os.path.exists(outfile):
        with open(outfile, "w") as f:
            f.write(f"// Source: {pageurl}\n")
            f.write(script)
        print(outfile)

# Also extract window.__NEXT_DATA__, window.__INITIAL_STATE__ etc
config_blocks = re.findall(
    r'(?:window\.__(?:NEXT_DATA|INITIAL_STATE|REDUX_STATE|APP_CONFIG|CONFIG|ENV|DATA)__\s*=\s*|__NUXT__\s*=\s*)(\{[\s\S]{0,50000}?\})\s*(?:;|$|\n)',
    html, re.MULTILINE
)
for i, block in enumerate(config_blocks):
    if len(block) > 20:
        import os
        h = hashlib.md5(block.encode()).hexdigest()[:8]
        outfile = os.path.join(out_dir, f"config_dump_{h}.json")
        if not os.path.exists(outfile):
            with open(outfile, "w") as f:
                f.write(f"// Source: {pageurl}\n")
                f.write(block)
            print(outfile)
PYEOF

    rm -f "$tmphtml"
}

export -f process_html inc_counter _curl warn info
export COUNTER_FILE LOCK_FILE INLINE_OUT OUT TARGET LOG RED GREEN YELLOW CYAN MAGENTA BLUE BOLD NC

# Process HTML pages — 5 at a time (polite)
job_count=0
while IFS= read -r pageurl; do
    [[ -z "$pageurl" ]] && continue
    process_html "$pageurl" &
    job_count=$((job_count + 1))
    [[ $job_count -ge 5 ]] && { wait; job_count=0; }
done < "$HEAD_URLS"
wait

rm -f "$HEAD_URLS" "$COUNTER_FILE" "$LOCK_FILE"

# Now analyze all extracted inline scripts + config dumps
INLINE_COUNT=$(find "$INLINE_OUT" -name "*.js" -o -name "*.json" 2>/dev/null | wc -l || echo 0)
log "Inline scripts extracted: ${INLINE_COUNT}"

if [[ $INLINE_COUNT -gt 0 ]]; then
    COUNTER_FILE=$(mktemp /tmp/elite_counter_XXXXXX)
    LOCK_FILE=$(mktemp /tmp/elite_lock_XXXXXX)
    echo 0 > "$COUNTER_FILE"; touch "$LOCK_FILE"
    export COUNTER_FILE LOCK_FILE

    job_count=0
    while IFS= read -r scriptfile; do
        [[ -z "$scriptfile" || ! -f "$scriptfile" ]] && continue
        (
            content=$(tr -d '\000' < "$scriptfile" 2>/dev/null || echo "")
            src_url=$(head -1 "$scriptfile" | grep -oE 'https?://[^ ]+' || echo "$scriptfile")
            if [[ "$scriptfile" == *.json ]]; then
                analyze_json "$src_url" "$scriptfile"
            else
                analyze_js "$src_url" "$content"
            fi
        ) &
        job_count=$((job_count + 1))
        [[ $job_count -ge 5 ]] && { wait; job_count=0; }
    done < <(find "$INLINE_OUT" -type f 2>/dev/null)
    wait

    rm -f "$COUNTER_FILE" "$LOCK_FILE"
    log "Inline script analysis complete"
fi


# ════════════════════════════════════════════════════════════════════════
# STEP 8 — ROBOTS.TXT + SITEMAP + TECH FINGERPRINTING
# ════════════════════════════════════════════════════════════════════════
step "════ STEP 8: ROBOTS / SITEMAP / TECH FINGERPRINT ════"

ROBOTS_OUT="$OUT/09_recon/robots"
SITEMAPS_OUT="$OUT/09_recon/sitemaps"
TECH_OUT="$OUT/09_recon/tech_stack"

# Probe every live host
while IFS= read -r host; do
    [[ -z "$host" ]] && continue
    basehost="${host%/}"

    # ── robots.txt ───────────────────────────────────────────────────
    robots_content=$(_curl --max-time 10 "${basehost}/robots.txt" 2>/dev/null || true)
    if [[ -n "$robots_content" ]] && echo "$robots_content" | grep -q "Disallow"; then
        hostfile=$(echo "$basehost" | sed 's|https\?://||' | tr '/' '_')
        echo "$robots_content" > "${ROBOTS_OUT}/${hostfile}_robots.txt"

        # Extract disallowed paths — these are hidden/admin paths
        echo "$robots_content" | grep -iE '^Disallow:' | awk '{print $2}' | \
        while read -r path; do
            [[ -z "$path" || "$path" == "/" ]] && continue
            full_url="${basehost}${path}"
            echo "$full_url" >> "${ROBOTS_OUT}/hidden_paths.txt"
            # Try to fetch disallowed path
            code=$(_curl --max-time 10 -o /dev/null -w "%{http_code}" "$full_url" 2>/dev/null || echo "000")
            [[ "$code" =~ ^(200|401|403)$ ]] && {
                echo "[robots_disallow:${full_url}] HTTP:${code}" >> "$OUT/06_findings/ALL_FINDINGS.txt"
                log "robots.txt hidden path accessible: ${full_url} (HTTP ${code})"
                save_finding MEDIUM infrastructure robots_hidden_path "$full_url" "${basehost}/robots.txt"
            }
        done

        # Extract sitemap URLs from robots
        echo "$robots_content" | grep -i "Sitemap:" | awk '{print $2}' >> "${SITEMAPS_OUT}/sitemap_urls.txt" 2>/dev/null || true
    fi

    # ── sitemap.xml ──────────────────────────────────────────────────
    for sitemap_path in "/sitemap.xml" "/sitemap_index.xml" "/sitemap.txt" \
                        "/wp-sitemap.xml" "/post-sitemap.xml" "/page-sitemap.xml"; do
        sitemap_url="${basehost}${sitemap_path}"
        sitemap_content=$(_curl --max-time 15 "$sitemap_url" 2>/dev/null || true)
        if [[ -n "$sitemap_content" ]] && echo "$sitemap_content" | grep -qiE '<url|<loc|<sitemap'; then
            hostfile=$(echo "$basehost" | sed 's|https\?://||' | tr '/' '_')
            echo "$sitemap_content" > "${SITEMAPS_OUT}/${hostfile}${sitemap_path//\//_}.xml"
            # Extract all URLs from sitemap
            echo "$sitemap_content" | grep -oP '(?<=<loc>)[^<]+' >> "${SITEMAPS_OUT}/all_sitemap_urls.txt" 2>/dev/null || true
            break
        fi
    done

    # ── Tech fingerprinting ───────────────────────────────────────────
    if command -v whatweb &>/dev/null; then
        whatweb -q "$basehost" >> "${TECH_OUT}/whatweb.txt" 2>/dev/null || true
    fi

    # Detect tech from headers
    headers=$(_curl --max-time 10 -I "$basehost" 2>/dev/null || true)
    if [[ -n "$headers" ]]; then
        echo "=== ${basehost} ===" >> "${TECH_OUT}/headers.txt"
        echo "$headers" >> "${TECH_OUT}/headers.txt"
        # Known vulnerable header combos
        echo "$headers" | grep -iE 'X-Powered-By|Server|X-Generator|X-Drupal|X-WordPress|X-Joomla' \
            >> "${TECH_OUT}/tech_headers.txt" 2>/dev/null || true
        # Version disclosure
        if echo "$headers" | grep -qiE 'PHP/[0-9]|Apache/[0-9]|nginx/[0-9]|Express|Laravel|Django|Rails|ASP\.NET [0-9]'; then
            version_info=$(echo "$headers" | grep -iE 'PHP/[0-9]|Apache/[0-9]|nginx/[0-9]|Express|Laravel|Django|Rails|ASP\.NET [0-9]')
            save_finding LOW infrastructure version_disclosure "$version_info" "$basehost"
        fi
    fi

done < "$LIVE_SUBS"

# Add sitemap URLs to URL pool for analysis
if [[ -s "${SITEMAPS_OUT}/all_sitemap_urls.txt" ]]; then
    SM_COUNT=$(sort -u "${SITEMAPS_OUT}/all_sitemap_urls.txt" | wc -l)
    log "Sitemap URLs discovered: ${SM_COUNT}"
    sort -u "${SITEMAPS_OUT}/all_sitemap_urls.txt" >> "$URLS"
    # Also add to live_urls pool (will need filtering)
    sort -u "${SITEMAPS_OUT}/all_sitemap_urls.txt" >> "$AUTH_URLS"
fi

ROBOTS_HIDDEN=$(wc -l < "${ROBOTS_OUT}/hidden_paths.txt" 2>/dev/null || echo 0)
log "robots.txt hidden paths found: ${ROBOTS_HIDDEN}"


# ════════════════════════════════════════════════════════════════════════
# STEP 9 — SENSITIVE URL FILTERING (34 categories)
# ════════════════════════════════════════════════════════════════════════
step "════ STEP 9: SENSITIVE URL FILTERING (34 categories) ════"

URL_SOURCE="$AUTH_URLS"
[[ ! -s "$URL_SOURCE" ]] && URL_SOURCE="$LIVE_URLS"
[[ ! -s "$URL_SOURCE" ]] && URL_SOURCE="$URLS"

if [[ ! -s "$URL_SOURCE" ]]; then
    warn "No URL source available — skipping Step 9"
else

S="$OUT/07_urlsecrets"
info "Scanning $(wc -l < "$URL_SOURCE") URLs across 34 categories..."

_CHUNK_DIR=$(mktemp -d); _GW=4

_grep_cat() {
    local pattern="$1" outfile="$2"
    local tmp="${_CHUNK_DIR}/$(basename "$outfile")"
    mkdir -p "$tmp"
    split -n "l/${_GW}" "$URL_SOURCE" "${tmp}/chunk_" 2>/dev/null || cp "$URL_SOURCE" "${tmp}/chunk_aa"
    local pids=()
    for chunk in "${tmp}"/chunk_*; do
        grep -aiP "$pattern" "$chunk" > "${chunk}.out" 2>/dev/null || true &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done
    cat "${tmp}"/*.out 2>/dev/null | sort -u > "$outfile" || true
}

info "[1/34]  Sensitive file extensions"
_grep_cat '\.(zip|rar|tar|tar\.gz|tgz|gz|bz2|7z|xz|sql|sqlite|sqlite3|db|dump|mdb|accdb|log|logs|bak|backup|old|orig|save|swp|tmp|temp|config|cfg|conf|ini|env|properties|yaml|yml|toml|htaccess|htpasswd|npmrc|dockerenv|dockerfile|pem|key|crt|cer|pfx|p12|der|csr|ppk|pub|java|class|jar|war|ear|xlsx|xls|csv|tsv|json|xml|pdf|doc|docx|pptx|ppt|odt|sh|bash|zsh|py|rb|pl|php|asp|aspx|jsp)(\?.*)?$' "$S/cat01a_files.txt"

info "[2/34]  Business doc keywords"
_grep_cat '(?i)(?:/[^/]*(?:invoice|receipt|transaction|payment|billing|payroll|salary|budget|financial|nda|non.?disclosure|contract|agreement|passport|national.?id|ssn|social.?security|kyc|medical.?record|health.?record|customer.?data|user.?data|data.?export|db.?backup|pentest|security.?audit|private.?key|seed.?phrase|credit.?card|bank.?statement)[^/]*\.(?:pdf|doc|docx|xls|xlsx|csv|txt|json|xml|zip|gz|sql|bak|log)$)' "$S/cat01b_keywords.txt"

info "[3/34]  Credential/API key patterns"
_grep_cat '(?:access_key|access_token|admin_pass|api_key|api_secret|app_key|app_secret|auth_token|aws_access_key_id|aws_secret|azure_client_secret|client_secret|firebase_api_key|github_token|gitlab_token|groq_api_key|jwt_secret|mailchimp_api_key|mailgun_api_key|notion_api_key|npm_token|openai_api_key|password|private_key|sendgrid_api_key|slack_token|slack_webhook|stripe_key|supabase_key|telegram_bot_token|twilio_auth_token|webhook_secret|zendesk_api_token)[a-z0-9_.,-]{0,25}[:<>=|&]{1,2}.{0,5}['"'"'"]([0-9A-Za-z\-_=+/]{8,100})['"'"'"]' "$S/cat02_creds.txt"

info "[4/34]  IDOR parameters"
_grep_cat '[?&](id|uid|user_id|userid|account_id|customer_id|client_id|order_id|invoice_id|ticket_id|file_id|document_id|record_id|profile_id|patient_id|employee_id|product_id|transaction_id|message_id|uuid|guid|token|hash|key|code)=[0-9a-fA-F\-]{1,64}' "$S/cat03_idor.txt"

info "[5/34]  Debug/admin endpoints"
_grep_cat '(?:/(?:admin|administrator|superadmin|wp-admin|wp-login|phpmyadmin|adminer|phpinfo|debug|debugger|console|shell|terminal|test|dev|staging|backup|config|swagger|swagger-ui|api-docs|openapi\.json|redoc|graphql|graphiql|actuator|actuator/env|actuator/health|\.git|\.env|\.htaccess|server-status|nginx_status|internal|h2-console|telescope|horizon|nova)(?:[/?#]|$))' "$S/cat04_debug.txt"

info "[6/34]  Tokens/JWTs in URLs"
_grep_cat '[?&](?:token|access_token|auth_token|bearer|jwt|id_token|refresh_token|oauth_token|session|api_token|x_auth_token)=[A-Za-z0-9\-_=+/.%]{16,}|eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+' "$S/cat05_tokens.txt"

info "[7/34]  Cloud/infra exposure"
_grep_cat 'https?://(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.0\.0\.1|localhost)|169\.254\.169\.254|[a-z0-9][a-z0-9\-]*\.s3(?:[\.\-][\w\-]+)?\.amazonaws\.com|storage\.googleapis\.com/[a-z0-9][a-z0-9\-]*|[a-z0-9]+\.blob\.core\.windows\.net' "$S/cat06_infra.txt"

info "[8/34]  Injection/traversal sinks"
_grep_cat '[?&](?:file|filename|filepath|path|dir|include|require|load|read|fetch|view|display|page|template|module|config|document|content|data|resource|layout|theme|lang|redirect|url|src|img|image|script|pdf|attachment|upload|download|log|report|debug|output|cmd|exec|command|shell|ping|host)=[^&]{1,200}' "$S/cat07_inject.txt"

info "[9/34]  Mass assignment params"
_grep_cat '[?&](?:role|roles|group|permission|is_admin|admin|superuser|is_staff|is_active|verified|approved|enabled|account_type|user_type|plan|tier|level|access_level|subscription|balance|credit|quota|scope|grant|debug|verbose|test|mock|sandbox|bypass|override|force|expand|fields|format|version|api_version)=[^&]{1,100}' "$S/cat08_massassign.txt"

info "[10/34] Serialization exposure"
_grep_cat 'rO0AB[A-Za-z0-9+/=]{8,}|[?&][^=]+=(?:a:[0-9]+:\{|s:[0-9]+:"|O:[0-9]+:"|b:[01];)|__VIEWSTATE=[A-Za-z0-9+/%=]{10,}|__EVENTVALIDATION=[A-Za-z0-9+/%=]{10,}' "$S/cat09_serial.txt"

info "[11/34] Webhook exposure"
_grep_cat 'hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+|discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+|api\.telegram\.org/bot[0-9]+:[A-Za-z0-9_\-]{30,}|[?&](?:webhook|webhook_url|callback|callback_url|notify_url|hook|endpoint)=https?[^&]{10,}|whsec_[A-Za-z0-9]{30,}' "$S/cat10_webhook.txt"

info "[12/34] GraphQL"
_grep_cat '(?:/graphql|/graphiql|/gql|/api/graphql|/v[0-9]/graphql|/playground|/altair|/__graphql|/graphql\.php)(?:[/?#]|$)|[?&](?:query|mutation|subscription)=.*(?:__schema|__type|introspection)' "$S/cat11_graphql.txt"

info "[13/34] Internal infrastructure"
_grep_cat '(?:/(?:metrics|prometheus|grafana|jaeger|zipkin|kibana|elasticsearch|jenkins|jenkins/script|argocd|portainer|pgadmin|phpmyadmin|adminer|mongo-express|redis-commander|rabbitmq|kafka-ui|airflow|superset|netdata|nagios|zabbix|_cluster|_cat|_nodes|actuator/heapdump|actuator/threaddump|jolokia|h2-console|readyz|livez|healthz)(?:[/?#]|$))' "$S/cat12_internal.txt"

info "[14/34] OAuth/SSO misconfigs"
_grep_cat '[?&](?:redirect_uri|redirect_url|return_uri|callback_uri)=[^&]{5,}|[#&](?:access_token|id_token|token_type)=[A-Za-z0-9\-_.=+/]{20,}|(?:/.well-known/openid-configuration|/oauth/authorize|/oauth/token|/oauth2/authorize|/auth/callback|/saml/consume|/login/oauth)(?:[/?#]|$)' "$S/cat13_oauth.txt"

info "[15/34] Source/backup file leaks"
_grep_cat '(?:/\.git/(?:config|HEAD|index|packed-refs|logs/HEAD)|/\.svn/|/\.hg/|/[^/]+\.(?:php|py|rb|js|conf|env)~$|/[^/]+\.(?:php|py|rb|js|conf|env)\.(?:bak|orig|backup|old|save)$|\.js\.map$|\.css\.map$|/\.DS_Store$|/(?:wp-config\.php|settings\.py|web\.config|phpinfo\.php|\.bash_history|\.ssh/id_rsa|\.aws/credentials|\.netrc|Dockerfile|docker-compose\.yml|\.travis\.yml|Jenkinsfile)$)' "$S/cat14_srcleaks.txt"

info "[16/34] Business logic/payments"
_grep_cat '[?&](?:price|amount|total|cost|fee|charge|rate|discount|coupon|promo|voucher|gift_card|points|reward_points|cashback|credit|quantity|qty|stock)=[^&]{1,50}|/(?:transfer|withdraw|deposit|refund|redeem|cashout|payout|apply.?coupon|checkout|purchase|subscribe|upgrade|activate)(?:[/?#&]|$)' "$S/cat15_bizlogic.txt"

info "[17/34] File upload endpoints"
_grep_cat '(?:/(?:upload|uploads|file.?upload|image.?upload|media.?upload|avatar.?upload|import|bulk.?import|csv.?import|dropzone|multipart|chunked.?upload)(?:[/?#]|$))|[?&](?:upload|file|files|attachment|media|image|photo|document)=[^&]{3,}' "$S/cat16_upload.txt"

info "[18/34] Framework debug/admin"
_grep_cat '(?:/(?:telescope|horizon|nova|_debugbar|__debug__|django-admin|silk|rails/info|rails/info/routes|actuator/heapdump|jolokia/exec|h2-console|__clockwork__|webpack-dev-server|_next/webpack-hmr|wp-json/wp/v2/users|xmlrpc\.php|phpdebugbar|firebaseio\.com)(?:[/?#]|$))|/(?:config/database\.php|application\.properties|application\.yml|appsettings\.json|local\.settings\.json)$' "$S/cat17_framework.txt"

info "[19/34] API data exposure"
_grep_cat '(?:/(?:api/)?(?:v[0-9]+/)?(?:users|accounts|customers|members|profiles|employees|transactions|payments|invoices|orders|config|settings|env|logs|audit|events|export|exports|dump|backup|backups|internal|admin|metrics|stats|analytics|notifications)(?:[/?#]|$))|[?&](?:limit|per_page|page_size|count|size|rows|take)=(?:9{3,}|1000|10000|all|everything|[0-9]{5,})' "$S/cat18_apiexpose.txt"

info "[20/34] Path-based IDOR (BOLA)"
_grep_cat '(?:/(?:user|users|account|accounts|customer|customers|order|orders|invoice|invoices|payment|payments|transaction|transactions|ticket|tickets|report|reports|document|documents|record|records|message|messages|project|projects|contract|contracts|booking|bookings)/[0-9]{1,10}(?:[/?#]|$))|/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}(?:[/?#]|$)' "$S/cat19_pathidor.txt"

info "[21/34] Third-party misconfigs"
_grep_cat '[a-z0-9-]+\.firebaseio\.com(?:/[^?#]*\.json)?|\.lambda-url\.[a-z0-9-]+\.on\.aws|\.cloudfunctions\.net/[a-zA-Z0-9_-]+|https?://[a-f0-9]{32}@(?:o[0-9]+\.)?ingest\.sentry\.io/[0-9]+' "$S/cat20_thirdparty.txt"

info "[22/34] Prototype pollution/DOM XSS"
_grep_cat '[?&](?:__proto__|constructor|prototype)(?:\[|%5B)(?:[a-zA-Z0-9_]+)(?:\]|%5D)|[?&](?:html|innerHTML|content|markup|raw_html)=[^&]{3,}|[?&][^=]+=(?:javascript:|vbscript:|data:text/html|%6a%61%76%61%73%63%72%69%70%74)' "$S/cat21_clientside.txt"

info "[23/34] Cache poisoning"
_grep_cat '[?&](?:x_forwarded_host|x_host|x_forwarded_for|x_original_url|x_rewrite_url)=[^&]{3,}|[?&](?:_method|method_override|X-HTTP-Method-Override)=(?:PUT|DELETE|PATCH|POST|HEAD|OPTIONS)' "$S/cat22_cache.txt"

info "[24/34] HTTP smuggling targets"
_grep_cat '(?:/(?:proxy|reverse-proxy|load-balancer|haproxy|nginx|varnish|traefik|envoy|api-gateway|gateway|ingress)(?:[/?#]|$))|[?&](?:backend|upstream|forward_to|proxy_to|route_to|service|destination)=(?:https?://|[a-z0-9-]+:[0-9]{2,5})[^&]{3,}' "$S/cat23_smuggling.txt"

info "[25/34] Mobile/deep link endpoints"
_grep_cat '(?:/(?:mobile|app|android|ios|react-native|flutter|api/mobile|mobile/api)(?:[/?#]|$))|[?&](?:deep_link|deeplink|app_link|intent|scheme|device_id|device_token|push_token|fcm_token|app_version|platform)=[^&]{3,}' "$S/cat24_mobile.txt"

info "[26/34] SSRF deep patterns"
_grep_cat '(?:169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com|100\.100\.100\.200)|[?&](?:url|uri|path|dest|redirect|proxy|fetch|load|request|resource|endpoint|target|host|server|image_url|feed|rss|webhook|callback|download|import|file|document|template|wsdl|xsd)=(?:https?(?:%3A|:)//|file(?:%3A|:)//|dict(?:%3A|:)//|gopher(?:%3A|:)//|//|%2F%2F)[^&]{3,}' "$S/cat25_ssrf.txt"

info "[27/34] Race condition targets"
_grep_cat '(?:/(?:api/)?(?:v[0-9]+/)?(?:transfer|withdraw|deposit|cashout|payout|redeem|refund|apply.?coupon|use.?coupon|checkout|purchase|subscribe|activate|vote|verify|confirm|otp|2fa|mfa)(?:[/?#]|$))|[?&](?:quantity|qty|units|stock|inventory)=[0-9]{1,6}' "$S/cat26_race.txt"

info "[28/34] CORS/JSONP/WebSocket"
_grep_cat '[?&](?:origin|cors|access_control|allow_origin|trusted_origin)=[^&]{5,}|[?&](?:callback|cb|jsonp|jsoncallback|padding|function|fn)=[a-zA-Z_$][a-zA-Z0-9_$]{1,50}|(?:/(?:ws|wss|websocket|socket\.io|sockjs|signalr|sse|events|stream|push|subscribe|pubsub|live|realtime|notify)(?:[/?#]|$))' "$S/cat27_cors.txt"

info "[29/34] Error/stack trace dumps"
_grep_cat '[?&](?:error|err|exception|trace|stacktrace|error_message|error_detail|message|detail|reason|cause)=[^&]{10,}|[?&][^=]+=(?:[A-Z][a-zA-Z]+(?:Exception|Error|Fault|Warning)|java\.|com\.|org\.|javax\.)' "$S/cat28_errordump.txt"

info "[30/34] Sensitive param names"
_grep_cat '[?&](?:master_key|master_password|master_secret|root_password|admin_password|admin_secret|admin_key|admin_token|super_secret|private_key|private_token|encryption_key|signing_key|hmac_key|salt|pepper|bypass_token|debug_token|backdoor|skeleton_key|passphrase|license_key|otp_secret|totp_secret|mfa_secret|recovery_code|backup_code)=[^&]{1,}' "$S/cat29_sensitiveparam.txt"

info "[31/34] JSON endpoints"
_grep_cat '(?:/[^?#]+\.json(?:[?#]|$))|[?&](?:format|output|type|response_type)=(?:json|raw|data)|/(?:config|settings|data|manifest|schema|endpoints|credentials|secrets|keys|tokens|env|database|logs|audit|backup|stats)\.json(?:[?#]|$)|firebaseio\.com/[^?#]*\.json' "$S/cat30_json.txt"

info "[32/34] PII & identity"
_grep_cat '(?:/(?:api/)?(?:v[0-9]+/)?(?:kyc|kyc.?document|identity|id.?verify|passport|national.?id|ssn|social.?security|dob|date.?of.?birth|medical.?record|health.?record|pii|personal.?data|gdpr|ccpa|data.?subject)(?:[/?#]|$))' "$S/cat31_pii.txt"

info "[33/34] Account takeover vectors"
_grep_cat '(?:/(?:api/)?(?:v[0-9]+/)?(?:impersonate|act.?as|switch.?user|sudo|password.?reset|reset.?password|forgot.?password|password.?change|email.?change|2fa.?disable|disable.?2fa|mfa.?bypass|session.?kill|token.?revoke|account.?recovery|magic.?link|privilege.?escalat|account.?merge)(?:[/?#]|$))' "$S/cat32_ato.txt"

info "[34/34] Financial + admin ops"
_grep_cat '(?:/(?:api/)?(?:v[0-9]+/)?(?:invoice|billing|loan|loan.?apply|loan.?approve|disbursement|repayment|credit.?limit|blacklist|whitelist|risk.?score|fraud|fraud.?check|payroll|salary|payslip|chargeback|dispute|virtual.?account|wallet|top.?up|employee.?terminate|user.?delete|account.?wipe|pii.?export|data.?export|bulk.?export|admin.?execute|system.?command|config.?update|maintenance.?mode|flush.?cache|mass.?email|generate.?report|audit.?log|security.?log|flag.?user|content.?flag)(?:[/?#]|$))' "$S/cat33_34_fin_admin.txt"

rm -rf "$_CHUNK_DIR"

cat "$S"/cat*.txt 2>/dev/null | sort -u > "$S/secreturls.txt" || true

URL_TOTAL=$(wc -l < "$S/secreturls.txt" 2>/dev/null || echo 0)
log "Sensitive URLs total: ${URL_TOTAL}"

echo ""
echo -e "${BOLD}URL Secrets by category:${NC}"
for f in "$S"/cat*.txt; do
    cnt=$(wc -l < "$f" 2>/dev/null || echo 0)
    [[ $cnt -gt 0 ]] && printf "  %-50s : %d\n" "$(basename "$f")" "$cnt"
done

fi  # end URL_SOURCE check


# ════════════════════════════════════════════════════════════════════════
# STEP 10 — ACTIVE TESTING
# Only runs with --active flag
# Tests: GraphQL introspection, Firebase open read, S3 access,
#        CORS misconfiguration, subdomain takeover, JWT weak secrets,
#        .env file probing, open redirect, SSRF metadata
# ════════════════════════════════════════════════════════════════════════
step "════ STEP 10: ACTIVE TESTING ════"

if [[ "$ACTIVE_MODE" != "true" ]]; then
    warn "Active mode disabled — skipping. Use --active to enable."
    warn "Active tests include: GraphQL, Firebase, S3, CORS, takeover, JWT crack, .env probe"
else

active "Active testing enabled — starting all checks..."
ACTIVE_OUT="$OUT/08_active"

# ── 10.1 GraphQL Introspection ────────────────────────────────────────
active "[10.1] GraphQL introspection auto-test..."

GRAPHQL_ENDPOINTS=$(grep -hiE '/(graphql|graphiql|gql|api/graphql|v[0-9]+/graphql)' \
    "$OUT/07_urlsecrets/cat11_graphql.txt" "$OUT/07_urlsecrets/cat04_debug.txt" \
    "$LIVE_URLS" 2>/dev/null | sort -u | head -50)

# Also probe each live host for common GraphQL paths
while IFS= read -r host; do
    for gpath in /graphql /api/graphql /v1/graphql /gql /graphiql; do
        echo "${host%/}${gpath}"
    done
done < "$LIVE_SUBS" >> /tmp/elite_gql_candidates_$$.txt 2>/dev/null || true
echo "$GRAPHQL_ENDPOINTS" >> /tmp/elite_gql_candidates_$$.txt
sort -u /tmp/elite_gql_candidates_$$.txt > /tmp/elite_gql_$$.txt

INTROSPECTION_QUERY='{"query":"{__schema{types{name fields{name}}}}"}'

while IFS= read -r gqlurl; do
    [[ -z "$gqlurl" ]] && continue
    response=$(_curl --max-time 15 \
        -X POST -H "Content-Type: application/json" \
        -d "$INTROSPECTION_QUERY" \
        "$gqlurl" 2>/dev/null || true)
    if echo "$response" | grep -q '"__schema"'; then
        active "[GRAPHQL INTROSPECTION OPEN] ${gqlurl}"
        echo "$response" > "${ACTIVE_OUT}/graphql/introspection_${gqlurl//[^a-zA-Z0-9]/_}.json"
        save_finding HIGH infrastructure graphql_introspection_enabled "$gqlurl" "$gqlurl"
        # Extract type names
        python3 -c "
import json,sys
try:
    d=json.loads('''${response}''')
    types=[t['name'] for t in d.get('data',{}).get('__schema',{}).get('types',[]) if not t['name'].startswith('__')]
    for t in types: print(t)
except: pass
" 2>/dev/null | head -30 >> "${ACTIVE_OUT}/graphql/types_${gqlurl//[^a-zA-Z0-9]/_}.txt" || true
    fi
    sleep 0.5
done < /tmp/elite_gql_$$.txt
rm -f /tmp/elite_gql_candidates_$$.txt /tmp/elite_gql_$$.txt

# ── 10.2 Firebase Open Read ───────────────────────────────────────────
active "[10.2] Firebase database open read test..."

# Collect Firebase URLs from findings + URL patterns
grep -h 'firebaseio\.com' \
    "$OUT/06_findings/ALL_FINDINGS.txt" \
    "$OUT/07_urlsecrets/cat20_thirdparty.txt" \
    "$OUT/07_urlsecrets/cat30_json.txt" \
    2>/dev/null | grep -oP 'https://[a-z0-9\-]+\.firebaseio\.com' | sort -u > /tmp/elite_fb_$$.txt

while IFS= read -r fburl; do
    [[ -z "$fburl" ]] && continue
    # Test root .json access — if returns data = public read enabled
    response=$(_curl --max-time 15 "${fburl}/.json?shallow=true" 2>/dev/null || true)
    if echo "$response" | grep -qE '^\{|^\[|^"'; then
        active "[FIREBASE OPEN READ] ${fburl}/.json"
        echo "$response" | head -100 > "${ACTIVE_OUT}/firebase/open_read_${fburl//[^a-zA-Z0-9]/_}.json"
        save_finding HIGH cloud_secrets firebase_database_open_read "${fburl}/.json" "$fburl"
    fi
    sleep 0.5
done < /tmp/elite_fb_$$.txt
rm -f /tmp/elite_fb_$$.txt

# ── 10.3 S3 Bucket Access Test ────────────────────────────────────────
active "[10.3] S3 bucket public access test..."

grep -h 's3' "$OUT/06_findings/ALL_FINDINGS.txt" "$OUT/07_urlsecrets/cat06_infra.txt" \
    2>/dev/null | grep -oP '[a-zA-Z0-9_\-]+\.s3[^"\s]*\.amazonaws\.com[^\s"'\'']*' | \
    grep -oP 'https?://[a-zA-Z0-9_\-]+\.s3[^"\s]*\.amazonaws\.com' | sort -u \
    > /tmp/elite_s3_$$.txt

# Also check storage URLs from findings
grep -oP 'https?://[a-zA-Z0-9_\-]+\.s3[^"\s]*\.amazonaws\.com' \
    "$OUT/06_findings/ALL_FINDINGS.txt" 2>/dev/null >> /tmp/elite_s3_$$.txt || true

sort -u /tmp/elite_s3_$$.txt -o /tmp/elite_s3_$$.txt

while IFS= read -r s3url; do
    [[ -z "$s3url" ]] && continue
    bucketname=$(echo "$s3url" | grep -oP '^https?://\K[a-zA-Z0-9_\-]+(?=\.s3)')

    # Test public list
    list_resp=$(_curl --max-time 15 "${s3url}/" 2>/dev/null || true)
    if echo "$list_resp" | grep -qE '<ListBucketResult|<Contents>'; then
        active "[S3 PUBLIC LIST] ${s3url}"
        echo "$list_resp" > "${ACTIVE_OUT}/s3/list_${bucketname}.xml"
        save_finding HIGH cloud_secrets s3_bucket_public_list "$s3url" "$s3url"
        # Count objects
        obj_count=$(echo "$list_resp" | grep -c '<Key>' || echo 0)
        active "  → ${obj_count} objects visible"
    fi

    # Test public read on a random object
    if echo "$list_resp" | grep -q '<Key>'; then
        first_key=$(echo "$list_resp" | grep -oP '(?<=<Key>)[^<]+' | head -1)
        [[ -n "$first_key" ]] && {
            obj_code=$(_curl --max-time 10 -o /dev/null -w "%{http_code}" "${s3url}/${first_key}" 2>/dev/null || echo "000")
            [[ "$obj_code" == "200" ]] && save_finding HIGH cloud_secrets s3_bucket_public_read "${s3url}/${first_key}" "$s3url"
        }
    fi

    # Test write access (safe: just check if we get permission denied or success)
    write_resp=$(_curl --max-time 10 -X PUT \
        -H "Content-Type: text/plain" \
        --data "elite_recon_test" \
        "${s3url}/elite_recon_test.txt" -w "%{http_code}" -o /dev/null 2>/dev/null || echo "000")
    [[ "$write_resp" == "200" ]] && {
        active "[S3 PUBLIC WRITE] ${s3url} — CRITICAL"
        save_finding HIGH cloud_secrets s3_bucket_public_write "$s3url" "$s3url"
        # Delete our test file
        _curl --max-time 10 -X DELETE "${s3url}/elite_recon_test.txt" > /dev/null 2>&1 || true
    }

    sleep 0.5
done < /tmp/elite_s3_$$.txt
rm -f /tmp/elite_s3_$$.txt

# ── 10.4 CORS Misconfiguration Test ──────────────────────────────────
active "[10.4] CORS misconfiguration test..."

# Test each live host with a crafted evil origin
while IFS= read -r host; do
    [[ -z "$host" ]] && continue
    basehost="${host%/}"

    for test_origin in \
        "https://evil.com" \
        "https://${TARGET}.evil.com" \
        "null" \
        "https://evil.${TARGET}"; do

        cors_resp=$(_curl --max-time 10 \
            -H "Origin: ${test_origin}" \
            -I "$basehost" 2>/dev/null || true)

        acao=$(echo "$cors_resp" | grep -i "access-control-allow-origin" | tr -d '\r')
        acac=$(echo "$cors_resp" | grep -i "access-control-allow-credentials" | tr -d '\r')

        if echo "$acao" | grep -qiE "evil\.com|null|\*"; then
            if echo "$acac" | grep -qi "true"; then
                active "[CORS + CREDENTIALS EXPOSED] ${basehost} — Origin: ${test_origin}"
                save_finding HIGH infrastructure cors_with_credentials "${basehost} (Origin:${test_origin})" "$basehost"
            else
                active "[CORS MISCONFIGURED] ${basehost} — Origin: ${test_origin}"
                save_finding MEDIUM infrastructure cors_misconfigured "${basehost} (Origin:${test_origin})" "$basehost"
            fi
            echo "  ACAO: ${acao}" >> "${ACTIVE_OUT}/cors/cors_findings.txt"
            echo "  ACAC: ${acac}" >> "${ACTIVE_OUT}/cors/cors_findings.txt"
        fi
    done
    sleep 0.3
done < "$LIVE_SUBS"

# ── 10.5 Subdomain Takeover Detection ────────────────────────────────
active "[10.5] Subdomain takeover detection..."

# Known fingerprints for takeover-vulnerable services
declare -A TAKEOVER_FP=(
    ["GitHub Pages"]="There isn't a GitHub Pages site here"
    ["Heroku"]="no-such-app.herokuapp.com|herokucdn.com/error-pages/no-such-app"
    ["Netlify"]="Not Found - Request ID"
    ["Vercel"]="The deployment you are looking for does not exist"
    ["AWS S3"]="NoSuchBucket"
    ["AWS Cloudfront"]="Bad request|ERROR: The request could not be satisfied"
    ["Ghost"]="The thing you were looking for is no longer here"
    ["Shopify"]="Sorry, this shop is currently unavailable"
    ["Tumblr"]="Whatever you were looking for doesn\'t currently exist"
    ["Fastly"]="Fastly error: unknown domain"
    ["Zendesk"]="Help Center Closed"
    ["Squarespace"]="No Such Account"
    ["Cargo Collective"]="404 Not Found"
    ["WP Engine"]="The site you were looking for couldn\'t be found"
    ["HubSpot"]="Domain not configured"
)

while IFS= read -r host; do
    [[ -z "$host" ]] && continue
    basehost="${host%/}"
    domain=$(echo "$basehost" | sed 's|https\?://||')

    # Check if CNAME points to external service
    cname=$(dig +short CNAME "$domain" 2>/dev/null | head -1 || true)
    [[ -z "$cname" ]] && continue

    # Fetch page content
    page_content=$(_curl --max-time 10 "$basehost" 2>/dev/null || true)

    for service in "${!TAKEOVER_FP[@]}"; do
        fp="${TAKEOVER_FP[$service]}"
        if echo "$page_content" | grep -qiP "$fp"; then
            active "[SUBDOMAIN TAKEOVER] ${basehost} → CNAME: ${cname} → ${service}"
            echo "${basehost} CNAME:${cname} Service:${service}" >> "${ACTIVE_OUT}/takeover/vulnerable_subs.txt"
            save_finding HIGH infrastructure subdomain_takeover_vulnerable "${basehost} (${service} via ${cname})" "$basehost"
            break
        fi
    done
    sleep 0.2
done < "$LIVE_SUBS"

TAKEOVER_COUNT=$(wc -l < "${ACTIVE_OUT}/takeover/vulnerable_subs.txt" 2>/dev/null || echo 0)
log "Subdomain takeover candidates: ${TAKEOVER_COUNT}"

# ── 10.6 JWT Weak Secret Test ─────────────────────────────────────────
active "[10.6] JWT weak secret crack attempt..."

# Extract all JWTs from findings
grep -oP 'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}' \
    "$OUT/06_findings/ALL_FINDINGS.txt" 2>/dev/null | sort -u > /tmp/elite_jwts_$$.txt

JWT_COUNT=$(wc -l < /tmp/elite_jwts_$$.txt)
info "Testing ${JWT_COUNT} JWTs for weak secrets..."

COMMON_JWT_SECRETS=(
    "secret" "password" "123456" "qwerty" "admin" "test" "key"
    "jwt_secret" "your-256-bit-secret" "your-secret" "mysecret"
    "secret123" "password123" "changeme" "supersecret" "p@ssw0rd"
    "abc123" "letmein" "welcome" "monkey" "1234567890" "pass"
    "$TARGET" "${TARGET}secret" "${TARGET}key" "${TARGET}jwt"
    "default" "example" "development" "production" "staging"
)

while IFS= read -r jwt; do
    [[ -z "$jwt" ]] && continue
    # Decode header and payload
    header=$(echo "$jwt" | cut -d. -f1 | python3 -c "
import sys,base64,json
b64=sys.stdin.read().strip()
b64+='=='*((4-len(b64)%4)%4)
try: print(json.dumps(json.loads(base64.urlsafe_b64decode(b64))))
except: pass
" 2>/dev/null)
    # Only crack HS256/HS384/HS512
    echo "$header" | grep -qiE '"alg"\s*:\s*"HS' || continue

    python3 << JWTCRACK 2>/dev/null
import hmac, hashlib, base64, json

jwt = """$jwt"""
parts = jwt.split('.')
if len(parts) != 3: exit(1)
header_payload = f"{parts[0]}.{parts[1]}".encode()
sig = parts[2]
# Pad base64
sig_padded = sig + '==' * ((4 - len(sig) % 4) % 4)
try:
    sig_bytes = base64.urlsafe_b64decode(sig_padded)
except: exit(1)

secrets = [${COMMON_JWT_SECRETS[@]/#/\"} ]
import ast
secrets = [s.strip('"') for s in """${COMMON_JWT_SECRETS[@]}""".split()]

for alg_name, hashfn in [('HS256', hashlib.sha256), ('HS384', hashlib.sha384), ('HS512', hashlib.sha512)]:
    for secret in secrets:
        try:
            test_sig = hmac.new(secret.encode(), header_payload, hashfn).digest()
            if hmac.compare_digest(test_sig, sig_bytes):
                print(f"[JWT CRACKED] alg:{alg_name} secret:{secret} jwt:{jwt[:50]}...")
                with open("$ACTIVE_OUT/jwt/cracked_jwts.txt", "a") as f:
                    f.write(f"SECRET:{secret}|ALG:{alg_name}|JWT:{jwt}\n")
                exit(0)
        except: pass
JWTCRACK

done < /tmp/elite_jwts_$$.txt
rm -f /tmp/elite_jwts_$$.txt

# Check cracked JWTs
if [[ -s "${ACTIVE_OUT}/jwt/cracked_jwts.txt" ]]; then
    CRACKED=$(wc -l < "${ACTIVE_OUT}/jwt/cracked_jwts.txt")
    active "[${CRACKED} JWTs CRACKED — CHECK ${ACTIVE_OUT}/jwt/cracked_jwts.txt]"
    while IFS= read -r line; do
        secret=$(echo "$line" | grep -oP 'SECRET:\K[^|]+')
        save_finding HIGH auth_tokens jwt_secret_cracked "secret:${secret}" "$TARGET"
    done < "${ACTIVE_OUT}/jwt/cracked_jwts.txt"
fi

# ── 10.7 .env File Active Probe ───────────────────────────────────────
active "[10.7] Active .env file probing..."

while IFS= read -r host; do
    [[ -z "$host" ]] && continue
    basehost="${host%/}"

    for envpath in \
        "/.env" "/.env.local" "/.env.production" "/.env.staging" \
        "/.env.backup" "/.env.old" "/.env.prod" "/.env.dev" \
        "/.env.example" "/.env.development.local" "/.env.test" \
        "/api/.env" "/backend/.env" "/app/.env" "/server/.env" \
        "/src/.env" "/config/.env" "/public/.env" \
        "/.aws/credentials" "/.netrc" \
        "/config/secrets.yml" "/config/database.yml" \
        "/application.properties" "/application.yml" \
        "/appsettings.json" "/local.settings.json" \
        "/config/local.json" "/config/default.json" \
        "/.docker/config.json" "/docker-compose.yml" \
        "/.npmrc" "/.pypirc" "/Makefile"; do

        url="${basehost}${envpath}"
        code=$(_curl --max-time 10 -o /tmp/elite_env_probe_$$.txt -w "%{http_code}" "$url" 2>/dev/null || echo "000")

        if [[ "$code" == "200" ]] && [[ -s /tmp/elite_env_probe_$$.txt ]]; then
            content=$(cat /tmp/elite_env_probe_$$.txt)
            # Validate it's actually an env file (has KEY=VALUE or looks like config)
            if echo "$content" | grep -qE '^[A-Z_]+=' || echo "$content" | grep -qiE '(password|secret|key|token|api|database|mongo|redis|stripe|aws)'; then
                active "[.ENV EXPOSED] ${url}"
                envfile="${ACTIVE_OUT}/env_files/$(echo "$url" | tr '/:' '__').txt"
                cp /tmp/elite_env_probe_$$.txt "$envfile"
                save_finding HIGH cloud_secrets env_file_exposed "$url" "$url"
                # Analyze the exposed env file
                analyze_env "$url" "$content"
            fi
        fi
        rm -f /tmp/elite_env_probe_$$.txt
        sleep 0.2
    done
done < "$LIVE_SUBS"

# ── 10.8 Open Redirect Test ───────────────────────────────────────────
active "[10.8] Open redirect test..."

# Collect redirect parameters from URL secrets
redirect_urls=$(grep -hP '[?&](?:redirect|redirect_uri|redirect_url|next|return|returnUrl|return_to|goto|dest|forward|url|continue)=' \
    "$OUT/07_urlsecrets/cat13_oauth.txt" \
    "$OUT/07_urlsecrets/cat07_inject.txt" \
    2>/dev/null | head -50 | sort -u)

while IFS= read -r rurl; do
    [[ -z "$rurl" ]] && continue
    # Replace the redirect param value with evil.com
    test_url=$(echo "$rurl" | sed -E 's/([?&](redirect|redirect_uri|redirect_url|next|return|returnUrl|return_to|goto|dest|forward|url|continue)=)[^&]*/\1https:\/\/evil.com/g')
    [[ "$test_url" == "$rurl" ]] && continue

    response_url=$(_curl --max-time 10 -w "%{url_effective}" -o /dev/null "$test_url" 2>/dev/null || true)
    if echo "$response_url" | grep -q "evil.com"; then
        active "[OPEN REDIRECT] ${test_url}"
        save_finding HIGH infrastructure open_redirect_confirmed "$test_url" "$test_url"
    fi
    sleep 0.3
done <<< "$redirect_urls"

# ── 10.9 SSRF Metadata Probe ──────────────────────────────────────────
active "[10.9] SSRF metadata endpoint probe..."

# Collect SSRF-suspect parameters from URL secrets
ssrf_params=$(grep -hiP '[?&](?:url|uri|path|dest|proxy|fetch|load|request|resource|endpoint|target|host|server|image_url|feed|rss|webhook|callback|download|import|file|document|template|wsdl)=' \
    "$OUT/07_urlsecrets/cat25_ssrf.txt" \
    2>/dev/null | head -30 | sort -u)

SSRF_TARGETS=(
    "http://169.254.169.254/latest/meta-data/"
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    "http://metadata.google.internal/computeMetadata/v1/"
    "http://100.100.100.200/latest/meta-data/"
    "http://localhost/"
    "http://127.0.0.1/"
    "http://[::1]/"
)

while IFS= read -r surl; do
    [[ -z "$surl" ]] && continue
    for ssrf_target in "${SSRF_TARGETS[@]}"; do
        # Inject SSRF target into the parameter
        test_url=$(echo "$surl" | sed -E "s|([?&](url|uri|path|dest|proxy|fetch|load|request|resource|endpoint|target|host|server|image_url|feed|rss|webhook|callback|download|import|file|document|template|wsdl)=)[^&]*|\1${ssrf_target}|g")
        [[ "$test_url" == "$surl" ]] && continue

        response=$(_curl --max-time 10 "$test_url" 2>/dev/null || true)
        if echo "$response" | grep -qiE '(ami-id|instance-id|placement|security-credentials|computeMetadata|iam:|project-id|kube-env)'; then
            active "[SSRF CONFIRMED] ${test_url} → metadata leaked"
            save_finding HIGH infrastructure ssrf_metadata_confirmed "$test_url" "$test_url"
            echo "$response" | head -50 > "${ACTIVE_OUT}/graphql/ssrf_response_$$.txt"
        fi
        sleep 0.3
    done
done <<< "$ssrf_params"

# ── 10.10 HTTP Methods Test ───────────────────────────────────────────
active "[10.10] Dangerous HTTP methods test..."

while IFS= read -r host; do
    [[ -z "$host" ]] && continue
    methods_resp=$(_curl --max-time 10 -X OPTIONS -I "$host" 2>/dev/null || true)
    allowed=$(echo "$methods_resp" | grep -i "Allow:" | tr -d '\r')
    if echo "$allowed" | grep -qiE '\b(PUT|DELETE|TRACE|CONNECT)\b'; then
        active "[DANGEROUS METHODS] ${host} → ${allowed}"
        save_finding MEDIUM infrastructure dangerous_http_methods "${host}: ${allowed}" "$host"
    fi
    sleep 0.2
done < "$LIVE_SUBS"

active "Active testing complete."

fi  # end ACTIVE_MODE check


# ════════════════════════════════════════════════════════════════════════
# FINAL REPORT
# ════════════════════════════════════════════════════════════════════════
step "════ FINAL REPORT ════"

# Deduplicate all findings
find "$OUT/06_findings" -name "*.txt" 2>/dev/null | while read -r f; do
    [[ -s "$f" ]] && sort -u "$f" -o "$f"
done

TOTAL_FINDINGS=$(wc -l < "$OUT/06_findings/ALL_FINDINGS.txt" 2>/dev/null || echo 0)
HIGH_FINAL=$(grep -c '\[HIGH\]'   "$OUT/06_findings/ALL_FINDINGS.txt" 2>/dev/null || echo 0)
MED_FINAL=$(grep -c '\[MEDIUM\]'  "$OUT/06_findings/ALL_FINDINGS.txt" 2>/dev/null || echo 0)
LOW_FINAL=$(grep -c '\[LOW\]'     "$OUT/06_findings/ALL_FINDINGS.txt" 2>/dev/null || echo 0)
URL_HITS=$(wc -l < "$OUT/07_urlsecrets/secreturls.txt" 2>/dev/null || echo 0)
TAKEOVER_HITS=$(wc -l < "$OUT/08_active/takeover/vulnerable_subs.txt" 2>/dev/null || echo 0)
JWT_CRACKED=$(wc -l < "$OUT/08_active/jwt/cracked_jwts.txt" 2>/dev/null || echo 0)
ENV_EXPOSED=$(find "$OUT/08_active/env_files" -type f 2>/dev/null | wc -l || echo 0)
GQL_OPEN=$(find "$OUT/08_active/graphql" -name "introspection_*.json" 2>/dev/null | wc -l || echo 0)

echo ""
echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}${BOLD}║          elite_recon v2.0 — COMPLETE SCAN REPORT            ║${NC}"
echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
printf "  %-42s : %s\n" "Target"                     "$TARGET"
printf "  %-42s : %s\n" "Mode"                        "${ACTIVE_MODE:+Active + Passive}"
printf "  %-42s : %s\n" "Subdomains found"            "$(wc -l < "$OUT/01_subs/subs.txt" 2>/dev/null || echo 0)"
printf "  %-42s : %s\n" "Live hosts"                  "$(wc -l < "$OUT/02_live/live_subs.txt" 2>/dev/null || echo 0)"
printf "  %-42s : %s\n" "Total URLs collected"        "$(wc -l < "$OUT/03_urls/urls.txt" 2>/dev/null || echo 0)"
printf "  %-42s : %s\n" "Live URLs (200)"             "$(wc -l < "$OUT/04_live_urls/live_urls.txt" 2>/dev/null || echo 0)"
printf "  %-42s : %s\n" "Assets analyzed"             "${ASSETS_SCANNED:-0} (JS+JSON+ENV+Webpack)"
printf "  %-42s : %s\n" "Assets success"              "${ASSETS_SUCCESS:-0}"
echo ""
echo -e "${RED}${BOLD}  ── Security Findings ─────────────────────────────────────────${NC}"
printf "  %-42s : %s\n" "TOTAL FINDINGS"              "$TOTAL_FINDINGS"
printf "  %-42s : ${RED}${BOLD}%s${NC}\n" "  HIGH confidence"         "$HIGH_FINAL"
printf "  %-42s : ${YELLOW}%s${NC}\n"     "  MEDIUM confidence"       "$MED_FINAL"
printf "  %-42s : ${BLUE}%s${NC}\n"       "  LOW confidence"          "$LOW_FINAL"
echo ""
echo -e "${BOLD}  ── Active Testing Results ────────────────────────────────────${NC}"
printf "  %-42s : %s\n" "Sensitive URLs (34 categories)"  "$URL_HITS"
printf "  %-42s : %s\n" "GraphQL introspection open"      "$GQL_OPEN"
printf "  %-42s : %s\n" ".env files exposed"              "$ENV_EXPOSED"
printf "  %-42s : %s\n" "Subdomain takeover candidates"   "$TAKEOVER_HITS"
printf "  %-42s : %s\n" "JWTs cracked"                    "$JWT_CRACKED"
echo ""
echo -e "${BOLD}  ── Top Findings by Category ──────────────────────────────────${NC}"
for conf in HIGH MEDIUM; do
    for cat_dir in "$OUT/06_findings/${conf}"/*/; do
        [[ -d "$cat_dir" ]] || continue
        cat_name=$(basename "$cat_dir")
        count=0
        for f in "$cat_dir"*.txt; do
            [[ -f "$f" ]] && c=$(wc -l < "$f" 2>/dev/null || echo 0) && count=$((count + c))
        done
        [[ $count -gt 0 ]] && printf "  %-42s : %d [%s]\n" "$cat_name" "$count" "$conf"
    done
done
echo ""
echo -e "${BOLD}  ── Output Structure ──────────────────────────────────────────${NC}"
echo "  ${OUT}/"
echo "  ├── 01_subs/             → All subdomains"
echo "  ├── 02_live/             → Live hosts"
echo "  ├── 03_urls/             → All collected URLs"
echo "  ├── 04_live_urls/        → Confirmed live URLs"
echo "  ├── 05_assets/           → JS / JSON / .env / Webpack / Inline scripts"
echo "  ├── 06_findings/"
echo "  │   ├── ALL_FINDINGS.txt → Every finding in one file"
echo "  │   ├── HIGH/            → ${HIGH_FINAL} HIGH confidence findings"
echo "  │   ├── MEDIUM/          → ${MED_FINAL} MEDIUM confidence findings"
echo "  │   └── LOW/             → ${LOW_FINAL} LOW confidence findings"
echo "  ├── 07_urlsecrets/       → 34-category sensitive URLs"
echo "  │   └── secreturls.txt   → All ${URL_HITS} sensitive URLs merged"
echo "  ├── 08_active/           → Active test results"
echo "  │   ├── graphql/         → GraphQL introspection dumps"
echo "  │   ├── firebase/        → Firebase open read responses"
echo "  │   ├── s3/              → S3 bucket listings"
echo "  │   ├── cors/            → CORS misconfiguration findings"
echo "  │   ├── takeover/        → Subdomain takeover candidates"
echo "  │   ├── jwt/             → Cracked JWTs"
echo "  │   └── env_files/       → Exposed .env file contents"
echo "  └── 09_recon/"
echo "      ├── robots/          → robots.txt + hidden paths"
echo "      ├── sitemaps/        → sitemap URLs"
echo "      └── tech_stack/      → Technology fingerprinting"
echo ""
echo "  Start here → ${OUT}/06_findings/ALL_FINDINGS.txt"
echo "  Sort by confidence:"
echo "    grep '\[HIGH\]'   ${OUT}/06_findings/ALL_FINDINGS.txt"
echo "    grep '\[MEDIUM\]' ${OUT}/06_findings/ALL_FINDINGS.txt"
echo ""
echo -e "${GREEN}${BOLD}════ ELITE RECON v2.0 COMPLETE — HAPPY HUNTING! ════${NC}"
echo -e "${RED}${BOLD}  ${HIGH_FINAL} HIGH  |  ${MED_FINAL} MEDIUM  |  ${LOW_FINAL} LOW  |  ${URL_HITS} URL HITS${NC}"
echo -e "${GREEN}  Output: ${OUT}/${NC}"
