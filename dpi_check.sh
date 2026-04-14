#!/usr/bin/env bash
# ┌─────────────────────────────────────────────────────────────┐
# │  dpi_check.sh — DPI Masquerade Inspector                    │
# │  Checks TCP/TLS (Reality/VLESS) and UDP/QUIC (Hysteria2)    │
# │  https://github.com/...                                     │
# └─────────────────────────────────────────────────────────────┘
#
# Usage:
#   ./dpi_check.sh <host|vless://...|hysteria2://...> [port] [options]
#
# Options:
#   -m, --mode  tcp|udp|auto    Protocol mode (default: auto)
#   -s, --sni   DOMAIN          Override SNI for TLS probes
#   -t, --timeout N             Seconds per probe (default: 5)
#       --no-color              Disable colored output
#   -h, --help                  Show this help
#
# Dependencies:
#   TCP mode : nmap, openssl, curl, nc
#   UDP mode : python3 + pip install aioquic

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="2.0.0"
TIMEOUT=5

# ── Colors ────────────────────────────────────────────────────
setup_colors() {
  if [[ -t 1 ]]; then
    R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m'
    C='\033[0;36m' W='\033[1;37m' DIM='\033[2m' BOLD='\033[1m' NC='\033[0m'
  else
    R='' G='' Y='' C='' W='' DIM='' BOLD='' NC=''
  fi
}
setup_colors
no_color() { R=''; G=''; Y=''; C=''; W=''; DIM=''; BOLD=''; NC=''; }

# ── Scoring ───────────────────────────────────────────────────
SCORE=0; MAX_SCORE=0
verdict_pass() { SCORE=$((SCORE+2)); MAX_SCORE=$((MAX_SCORE+2)); printf "%b" "${G}✓${NC}"; }
verdict_warn() { SCORE=$((SCORE+1)); MAX_SCORE=$((MAX_SCORE+2)); printf "%b" "${Y}~${NC}"; }
verdict_fail() {                     MAX_SCORE=$((MAX_SCORE+2)); printf "%b" "${R}✗${NC}"; }
verdict_info() {                                                  printf "%b" "${C}•${NC}"; }

# ── Row printer ───────────────────────────────────────────────
# print_row <num> <label> <detail> <verdict: pass|warn|fail|info>
print_row() {
  local num="$1" label="$2" detail="$3" verdict="$4"
  printf "  ${DIM}[%2s]${NC}  ${W}%-22s${NC}  ${DIM}→${NC}  %-36s  " \
    "$num" "$label" "${detail:0:36}"
  case "$verdict" in
    pass) verdict_pass ;;
    warn) verdict_warn ;;
    fail) verdict_fail ;;
    info) verdict_info ;;
  esac
  echo
}

div()    { printf "  ${DIM}%s${NC}\n" "$(printf '─%.0s' {1..63})"; }
header() { printf "\n${C}  ══ %s ${DIM}%s${NC}\n" "$1" "$(printf '═%.0s' $(seq 1 $((55 - ${#1}))))"; }

# ── Banner ────────────────────────────────────────────────────
print_banner() {
  local host="$1" port="$2" proto="$3" ip="$4" asn="$5" sni="$6"
  echo
  local title="DPI Masquerade Inspector v${VERSION}"
  printf "${C}  ╔═══════════════════════════════════════════════════════════╗${NC}\n"
  printf "${C}  ║  ${NC}${BOLD}%-55s${NC}  ${C}║${NC}\n" "$title"
  printf "${C}  ╠═══════════════════════════════════════════════════════════╣${NC}\n"
  printf "${C}  ║  ${NC}${DIM}Target${NC}  ${BOLD}%-22s${NC}  ${DIM}Port${NC}  ${BOLD}%-7s${NC}         ${C}║${NC}\n" "$host" "$port"
  printf "${C}  ║  ${NC}${DIM}IP${NC}      %-22s  ${DIM}Mode${NC}  ${BOLD}%-13s${NC}  ${C}║${NC}\n" "$ip" "$proto"
  printf "${C}  ║  ${NC}${DIM}ASN${NC}     %-53s${C}║${NC}\n" "${asn:0:52} "
  [[ -n "$sni" && "$sni" != "$host" ]] && \
  printf "${C}  ║  ${NC}${DIM}SNI${NC}     %-53s${C}║${NC}\n" "$sni "
  printf "${C}  ╚═══════════════════════════════════════════════════════════╝${NC}\n"
  echo
}

# ── Summary ───────────────────────────────────────────────────
print_summary() {
  [[ $MAX_SCORE -eq 0 ]] && return
  local pct=$(( SCORE * 100 / MAX_SCORE ))
  local bar="" filled=$(( pct * 24 / 100 )) empty=$(( 24 - pct * 24 / 100 ))
  for ((i=0; i<filled; i++)); do bar+="█"; done
  for ((i=0; i<empty;  i++)); do bar+="░"; done

  local grade label
  if   [[ $pct -ge 90 ]]; then grade="${G}${BOLD}EXCELLENT${NC}"; label="passes DPI inspection"
  elif [[ $pct -ge 75 ]]; then grade="${G}GOOD${NC}";             label="minor fingerprint risks"
  elif [[ $pct -ge 55 ]]; then grade="${Y}AVERAGE${NC}";          label="several issues detected"
  else                         grade="${R}POOR${NC}";              label="high fingerprint risk"
  fi

  echo
  div
  printf "\n  ${BOLD}Masquerade Score:${NC} ${BOLD}%d%%${NC}  ${DIM}%s${NC}  %b\n" \
    "$pct" "$bar" "$grade"
  printf "  ${DIM}%d/%d pts — %s${NC}\n\n" "$SCORE" "$MAX_SCORE" "$label"
}

# ── URL parser ────────────────────────────────────────────────
# Sets: URL_SCHEME, URL_HOST, URL_PORT, URL_SNI
parse_vpn_url() {
  local url="$1"
  URL_SCHEME="${url%%://*}"
  local rest="${url#*://}"
  rest="${rest%%#*}"                       # strip fragment
  local hostpart="${rest%%\?*}"
  local params="${rest#*\?}"; [[ "$params" == "$rest" ]] && params=""
  local hostport="${hostpart##*@}"         # strip auth
  URL_HOST="${hostport%%:*}"
  URL_PORT="${hostport##*:}"; [[ "$URL_PORT" == "$URL_HOST" ]] && URL_PORT="443"
  URL_SNI=""
  if [[ -n "$params" ]]; then
    URL_SNI="$(echo "$params" | tr '&' '\n' | grep '^sni=' | cut -d= -f2 | head -1)"
    # url-decode basic %2F etc — skip for SNI, it's just a domain
  fi
}

# ── ASN lookup ────────────────────────────────────────────────
get_asn() {
  local ip="$1"
  local asn=""
  asn=$(curl -s --max-time 3 "https://ipinfo.io/${ip}/org" 2>/dev/null) || true
  [[ -z "$asn" || "$asn" == *"Whoa"* ]] && \
    asn=$(whois "$ip" 2>/dev/null | grep -iE "^(OrgName|org-name|netname):" | head -1 | sed 's/.*:\s*//' | xargs 2>/dev/null) || true
  echo "${asn:-unknown}"
}

# ── TCP/TLS checks ────────────────────────────────────────────
run_tcp() {
  local host="$1" port="$2" sni="$3"

  header "TCP / TLS CHECKS"
  echo

  # [1] Port scan
  local nmap_out nmap_line
  nmap_line=$(nmap -sV -p "$port" --open "$host" 2>/dev/null | grep "${port}/tcp") || nmap_line=""
  if [[ -n "$nmap_line" ]]; then
    nmap_out=$(echo "$nmap_line" | awk '{for(i=3;i<=NF;i++) printf "%s ", $i; print ""}' | sed 's/[[:space:]]*$//')
    print_row 1 "Port scan" "${nmap_out:-open}" pass
  elif timeout 2 bash -c "echo >/dev/tcp/${host}/${port}" 2>/dev/null; then
    print_row 1 "Port scan" "open (nmap inconclusive, TCP verified)" warn
  else
    print_row 1 "Port scan" "port closed / filtered" fail
  fi

  # [2] TLS certificate
  local cert_raw cn issuer_o not_after days_left=""
  cert_raw=$(echo | timeout "$TIMEOUT" openssl s_client \
    -connect "${host}:${port}" -servername "$sni" 2>/dev/null \
    | openssl x509 -noout -subject -issuer -dates 2>/dev/null) || cert_raw=""
  cn=$(echo "$cert_raw" | grep subject | sed 's/.*CN *= *//' | sed 's/[,\/].*//')
  issuer_o=$(echo "$cert_raw" | grep issuer | sed 's/.*O *= *//' | sed 's/[,\/].*//')
  not_after=$(echo "$cert_raw" | grep notAfter | cut -d= -f2-)
  if [[ -n "$not_after" ]]; then
    days_left=$(( ( $(date -d "$not_after" +%s 2>/dev/null || echo 0) - $(date +%s) ) / 86400 )) || days_left=0
  fi

  if [[ -n "$cn" ]]; then
    local cert_detail="CN=${cn}, ${days_left}d left"
    local cert_verdict="warn"
    if echo "$issuer_o" | grep -qiE "let.s encrypt|digicert|sectigo|globalsign|comodo|zerossl|google"; then
      cert_verdict="pass"
      cert_detail="CN=${cn} (${issuer_o:0:14}), ${days_left}d"
    elif echo "$cn" | grep -qiE "localhost|self|example"; then
      cert_verdict="fail"
    fi
    print_row 2 "TLS certificate" "$cert_detail" "$cert_verdict"
  else
    print_row 2 "TLS certificate" "no cert returned" fail
  fi

  # [3] TLS version & cipher
  local tls_raw tls_ver cipher alpn
  tls_raw=$(echo | timeout "$TIMEOUT" openssl s_client \
    -connect "${host}:${port}" -servername "$sni" -alpn "h2,http/1.1" 2>&1 \
    | tr -d '\000') || tls_raw=""
  tls_ver=$(echo "$tls_raw" | grep "New," | sed 's/.*New, //;s/,.*//')
  cipher=$(echo  "$tls_raw" | grep "Cipher is"   | sed 's/.*Cipher is //' | tr -d ' \r')
  alpn=$(echo    "$tls_raw" | grep "ALPN protocol" | sed 's/.*ALPN protocol: //' | tr -d ' \r')
  local tls_detail="${tls_ver:-?} / ${cipher:0:20}${alpn:+ / $alpn}"
  if   [[ "$tls_ver" == "TLSv1.3" ]]; then print_row 3 "TLS handshake" "$tls_detail" pass
  elif [[ "$tls_ver" == "TLSv1.2" ]]; then print_row 3 "TLS handshake" "$tls_detail" warn
  else                                      print_row 3 "TLS handshake" "${tls_detail:-failed}" fail
  fi

  # [4] HTTP fallback
  local http_status ct elapsed
  http_status=$(curl -sk -o /dev/null -w "%{http_code}" --max-time "$TIMEOUT" \
    "https://${host}:${port}/") || http_status="000"
  ct=$(curl -sk -o /dev/null -w "%{content_type}" --max-time "$TIMEOUT" \
    "https://${host}:${port}/" 2>/dev/null | cut -d';' -f1) || ct=""
  elapsed=$(curl -sk -o /dev/null -w "%{time_total}" --max-time "$TIMEOUT" \
    "https://${host}:${port}/" 2>/dev/null) || elapsed=""
  local fb_detail="HTTP ${http_status} ${ct} (${elapsed}s)"
  case "$http_status" in
    200)         print_row 4 "HTTP fallback" "$fb_detail" pass ;;
    301|302|307) print_row 4 "HTTP fallback" "$fb_detail" warn ;;
    404|403)     print_row 4 "HTTP fallback" "$fb_detail" warn ;;
    *)           print_row 4 "HTTP fallback" "no response (HTTP ${http_status})" fail ;;
  esac

  # [5] HTTP → HTTPS redirect
  local redir_code redir_url
  redir_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time "$TIMEOUT" \
    "http://${host}/" 2>/dev/null) || redir_code="000"
  redir_url=$(curl -s -o /dev/null -w "%{redirect_url}" --max-time "$TIMEOUT" \
    "http://${host}/" 2>/dev/null) || redir_url=""
  local redir_short="${redir_url:0:30}"; [[ -n "$redir_short" ]] && redir_short=" → ${redir_short}"
  case "$redir_code" in
    301|302) print_row 5 "HTTP→HTTPS redirect" "HTTP ${redir_code}${redir_short}" pass ;;
    200)     print_row 5 "HTTP→HTTPS redirect" "HTTP 200 (no redirect)" warn ;;
    *)       print_row 5 "HTTP→HTTPS redirect" "HTTP ${redir_code} (no redirect)" warn ;;
  esac

  # [6] Mismatched SNI
  local mis_cn
  mis_cn=$(echo | timeout "$TIMEOUT" openssl s_client \
    -connect "${host}:${port}" -servername "google.com" 2>/dev/null \
    | openssl x509 -noout -subject 2>/dev/null \
    | sed 's/.*CN *= *//' | sed 's/[,\/].*//') || mis_cn=""
  if [[ -n "$mis_cn" ]]; then
    local mis_detail="cert: CN=${mis_cn:0:28}"
    # Good if server returns its own cert consistently (not a foreign domain's cert)
    if echo "$mis_cn" | grep -qi "localhost\|self-signed\|example"; then
      print_row 6 "Mismatched SNI" "$mis_detail (self-signed!)" fail
    else
      print_row 6 "Mismatched SNI" "$mis_detail" pass
    fi
  else
    local mis_err
    mis_err=$(echo | timeout "$TIMEOUT" openssl s_client \
      -connect "${host}:${port}" -servername "google.com" 2>&1 \
      | grep -iE "refused|reset|handshake" | head -1) || mis_err="no response"
    print_row 6 "Mismatched SNI" "${mis_err:-connection closed}" warn
  fi

  # [7] No SNI
  local nosni_cn
  nosni_cn=$(echo | timeout "$TIMEOUT" openssl s_client \
    -connect "${host}:${port}" -noservername 2>/dev/null \
    | openssl x509 -noout -subject 2>/dev/null \
    | sed 's/.*CN *= *//' | sed 's/[,\/].*//') || nosni_cn=""
  if [[ -n "$nosni_cn" ]]; then
    if echo "$nosni_cn" | grep -qi "localhost\|self-signed"; then
      print_row 7 "No SNI probe" "cert: CN=${nosni_cn} (self-signed!)" fail
    else
      print_row 7 "No SNI probe" "cert: CN=${nosni_cn:0:30}" pass
    fi
  else
    print_row 7 "No SNI probe" "connection closed / no cert" warn
  fi

  # [8] Random path
  local rand_path rand_status
  rand_path="/$(cat /proc/sys/kernel/random/uuid 2>/dev/null | tr -d '-' | head -c 16 || echo "test404path99")"
  rand_status=$(curl -sk -o /dev/null -w "%{http_code}" --max-time "$TIMEOUT" \
    "https://${host}:${port}${rand_path}") || rand_status="000"
  case "$rand_status" in
    200|404|403) print_row 8 "Random path probe" "GET ${rand_path} → HTTP ${rand_status}" pass ;;
    000)         print_row 8 "Random path probe" "GET ${rand_path} → no response" fail ;;
    *)           print_row 8 "Random path probe" "GET ${rand_path} → HTTP ${rand_status}" warn ;;
  esac

  # [9] Raw TCP (non-TLS) probe
  local raw_resp
  raw_resp=$(printf "GET / HTTP/1.0\r\nHost: %s\r\n\r\n" "$host" \
    | timeout 3 nc "$host" "$port" 2>/dev/null | head -1 | tr -d '\r') || raw_resp=""
  if [[ -n "$raw_resp" ]]; then
    if echo "$raw_resp" | grep -q "400 Bad Request"; then
      print_row 9 "Raw TCP (non-TLS)" "${raw_resp:0:36}" pass
    elif echo "$raw_resp" | grep -qi "^HTTP"; then
      print_row 9 "Raw TCP (non-TLS)" "${raw_resp:0:36}" warn
    else
      print_row 9 "Raw TCP (non-TLS)" "${raw_resp:0:36}" fail
    fi
  else
    print_row 9 "Raw TCP (non-TLS)" "no response (connection reset)" warn
  fi

  # [10] Response headers
  local resp_headers srv_hdr hsts xframe
  resp_headers=$(curl -sk -I --max-time "$TIMEOUT" "https://${host}:${port}/" 2>/dev/null) || resp_headers=""
  srv_hdr=$(echo "$resp_headers" | grep -i "^Server:"       | awk '{print $2}' | tr -d '\r')
  hsts=$(echo    "$resp_headers" | grep -i "^Strict-Trans"  | grep -c "max-age" || true)
  xframe=$(echo  "$resp_headers" | grep -i "^X-Frame"       | awk '{print $2}' | tr -d '\r')
  local hdr_detail="Server: ${srv_hdr:-?}"
  [[ "$hsts" -gt 0 ]]   && hdr_detail+=", HSTS"
  [[ -n "$xframe" ]] && hdr_detail+=", X-Frame: ${xframe}"
  if [[ -n "$srv_hdr" && "$hsts" -gt 0 ]]; then
    print_row 10 "Response headers" "$hdr_detail" pass
  elif [[ -n "$srv_hdr" ]]; then
    print_row 10 "Response headers" "$hdr_detail" warn
  else
    print_row 10 "Response headers" "no Server header" fail
  fi

  # [11] WebSocket endpoint leak
  # A normal website never returns 101 Switching Protocols to a WS upgrade.
  # If any path does — the WS transport endpoint is exposed to DPI.
  local ws_paths=("/" "/ws" "/websocket" "/ray" "/v2ray" "/vless" "/vmess" "/api" "/grpc" "/stream")
  local ws_leaked="" ws_clean=0 ws_checked=0
  local ws_key="dGhlIHNhbXBsZSBub25jZQ=="  # base64("the sample nonce")
  for ws_path in "${ws_paths[@]}"; do
    local ws_code
    ws_code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 3 \
      -H "Connection: Upgrade" \
      -H "Upgrade: websocket" \
      -H "Sec-WebSocket-Key: ${ws_key}" \
      -H "Sec-WebSocket-Version: 13" \
      "https://${host}:${port}${ws_path}") || ws_code="000"
    ws_checked=$((ws_checked + 1))
    if [[ "$ws_code" == "101" ]]; then
      ws_leaked+="${ws_path}(101) "
    else
      ws_clean=$((ws_clean + 1))
    fi
  done
  if [[ -n "$ws_leaked" ]]; then
    print_row 11 "WebSocket leak" "WS endpoint exposed: ${ws_leaked:0:30}" fail
  else
    print_row 11 "WebSocket leak" "no WS upgrade on ${ws_checked} paths" pass
  fi

  # [12] gRPC endpoint leak
  # Normal servers return 415/404/400 to gRPC content-type.
  # An exposed gRPC transport returns 200 with grpc-status or trailers.
  local grpc_paths=("/" "/grpc" "/ray" "/vless" "/vmess" "/tun" "/api")
  local grpc_leaked="" grpc_clean=0
  for grpc_path in "${grpc_paths[@]}"; do
    local grpc_code grpc_ct
    grpc_code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 3 \
      -X POST \
      -H "Content-Type: application/grpc" \
      -H "TE: trailers" \
      "https://${host}:${port}${grpc_path}") || grpc_code="000"
    grpc_ct=$(curl -sk -D - -o /dev/null --max-time 3 \
      -X POST \
      -H "Content-Type: application/grpc" \
      -H "TE: trailers" \
      "https://${host}:${port}${grpc_path}" 2>/dev/null \
      | grep -i "content-type:" | grep -i "grpc" | head -1) || grpc_ct=""
    if [[ -n "$grpc_ct" || "$grpc_code" == "200" ]]; then
      grpc_leaked+="${grpc_path}(${grpc_code}) "
    else
      grpc_clean=$((grpc_clean + 1))
    fi
  done
  if [[ -n "$grpc_leaked" ]]; then
    print_row 12 "gRPC leak" "gRPC endpoint exposed: ${grpc_leaked:0:28}" fail
  else
    print_row 12 "gRPC leak" "no gRPC response on ${#grpc_paths[@]} paths" pass
  fi

  # [13] HTTP CONNECT probe
  # Proxies accept CONNECT method. A real web server rejects it with 405/400.
  local connect_code
  connect_code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 3 \
    -X CONNECT "https://${host}:${port}/") || connect_code="000"
  case "$connect_code" in
    200)         print_row 13 "HTTP CONNECT" "accepted (200) — proxy behavior!" fail ;;
    000)         print_row 13 "HTTP CONNECT" "connection reset / no response" warn ;;
    400|405|501) print_row 13 "HTTP CONNECT" "rejected (${connect_code}) — normal" pass ;;
    *)           print_row 13 "HTTP CONNECT" "HTTP ${connect_code}" warn ;;
  esac

  # [14] Path behavior consistency
  # A normal server responds identically to any unknown path.
  # Inconsistency (some paths 000, others 200) suggests selective routing.
  local paths_to_check=("/aaa111" "/bbb222" "/ccc333" "/ddd444" "/eee555")
  local codes=() unique_codes
  for chk_path in "${paths_to_check[@]}"; do
    local chk_code
    chk_code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 3 \
      "https://${host}:${port}${chk_path}") || chk_code="000"
    codes+=("$chk_code")
  done
  unique_codes=$(printf '%s\n' "${codes[@]}" | sort -u | tr '\n' ' ' | sed 's/ $//')
  local unique_count
  unique_count=$(printf '%s\n' "${codes[@]}" | sort -u | wc -l)
  if [[ "$unique_count" -eq 1 ]]; then
    print_row 14 "Path consistency" "all paths → ${unique_codes} (consistent)" pass
  elif [[ "$unique_count" -eq 2 ]]; then
    print_row 14 "Path consistency" "responses: ${unique_codes} (minor variance)" warn
  else
    print_row 14 "Path consistency" "inconsistent: ${unique_codes}" fail
  fi
}

# ── UDP/QUIC mode ─────────────────────────────────────────────
run_udp() {
  local host="$1" port="$2" sni="$3"
  if ! command -v python3 &>/dev/null; then
    printf "\n  ${R}Error:${NC} python3 required for UDP/QUIC mode\n"
    printf "  Install: ${DIM}apt install python3 && pip3 install aioquic${NC}\n\n"
    exit 1
  fi
  # Pass color flag to python prober
  local color_flag=""
  [[ -z "$NC" ]] && color_flag="--no-color"
  python3 "${SCRIPT_DIR}/quic_probe.py" "$host" "$port" "$sni" $color_flag
}

# ── Help ──────────────────────────────────────────────────────
usage() {
  cat <<EOF

${BOLD}dpi_check.sh${NC} v${VERSION} — DPI Masquerade Inspector

${BOLD}USAGE${NC}
  $(basename "$0") <target> [port] [options]

${BOLD}TARGET${NC}
  hostname / IP          example.com
  vless:// URL           vless://uuid@host:443?sni=github.com&...
  hysteria2:// URL       hysteria2://pass@host:443?sni=bing.com

${BOLD}OPTIONS${NC}
  -m, --mode  tcp|udp|auto   Protocol (default: auto-detect)
  -s, --sni   DOMAIN         Override SNI for TLS probes
  -t, --timeout N            Probe timeout in seconds (default: 5)
      --no-color             Plain output, no ANSI colors
  -h, --help                 Show this help

${BOLD}EXAMPLES${NC}
  $(basename "$0") example.com
  $(basename "$0") 1.2.3.4 443 --mode tcp --sni github.com
  $(basename "$0") vless://uuid@server.com:443?security=reality&sni=apple.com
  $(basename "$0") hysteria2://auth@server.com:443

${BOLD}SCORE LEGEND${NC}
  ${G}✓${NC} pass (2pts)   ${Y}~${NC} warn (1pt)   ${R}✗${NC} fail (0pts)   ${C}•${NC} info (no score)

${BOLD}REQUIREMENTS${NC}
  TCP mode : nmap, openssl, curl, nc
  UDP mode : python3, pip install aioquic

EOF
}

# ── Main ──────────────────────────────────────────────────────
main() {
  [[ $# -eq 0 ]] && { usage; exit 0; }
  [[ "$1" == "-h" || "$1" == "--help" ]] && { usage; exit 0; }

  local host="" port="443" mode="auto" sni=""

  # First arg — host or VPN URL
  local first="$1"; shift
  if echo "$first" | grep -qE "^(vless|hysteria2|trojan|ss)://"; then
    parse_vpn_url "$first"
    host="$URL_HOST"; port="$URL_PORT"; sni="${URL_SNI:-}"
    case "$URL_SCHEME" in
      hysteria2)     mode="udp" ;;
      vless|trojan)  mode="tcp" ;;
    esac
  else
    host="$first"
    [[ $# -gt 0 && "$1" =~ ^[0-9]+$ ]] && { port="$1"; shift; }
  fi

  # Remaining options
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -m|--mode)    mode="$2";    shift 2 ;;
      -s|--sni)     sni="$2";     shift 2 ;;
      -t|--timeout) TIMEOUT="$2"; shift 2 ;;
      --no-color)   no_color;     shift   ;;
      -h|--help)    usage; exit 0 ;;
      *) printf "Unknown option: %s\n" "$1"; usage; exit 1 ;;
    esac
  done

  [[ -z "$sni" ]] && sni="$host"

  # Resolve IP
  local ip=""
  ip=$(dig +short "$host" 2>/dev/null | grep -E '^[0-9]' | head -1) || true
  [[ -z "$ip" ]] && ip=$(getent hosts "$host" 2>/dev/null | awk '{print $1}') || true
  [[ -z "$ip" ]] && ip="$host"

  # ASN (best-effort, non-blocking)
  local asn=""
  asn=$(get_asn "$ip") || asn="unknown"

  # Auto-detect protocol
  if [[ "$mode" == "auto" ]]; then
    if timeout 2 bash -c "echo >/dev/tcp/${host}/${port}" 2>/dev/null; then
      mode="tcp"
    else
      mode="udp"
    fi
  fi

  local proto_label
  case "$mode" in
    tcp) proto_label="TCP / TLS" ;;
    udp) proto_label="UDP / QUIC" ;;
    *)   proto_label="$mode" ;;
  esac

  print_banner "$host" "$port" "$proto_label" "$ip" "$asn" "$sni"

  if [[ "$mode" == "tcp" ]]; then
    run_tcp "$host" "$port" "$sni"
    print_summary
  else
    run_udp "$host" "$port" "$sni"
  fi
}

main "$@"
