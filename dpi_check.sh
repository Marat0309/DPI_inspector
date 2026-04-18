#!/usr/bin/env bash
# DPI Masquerade Inspector v2.2.7
# TCP/TLS and UDP/QUIC active probing with family inference and hardening hints.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lang.sh"
VERSION="2.2.7"
TIMEOUT=5
OUTPUT_MODE="text"
LANG_MODE="en"
SNI_EXPLICIT=0
DEBUG_INFER=0
SHOW_HINTS=1
RECOMMEND_FIXES=0
NO_ASN=0

setup_colors() {
  if [[ -t 1 ]]; then
    R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'
    C='\033[0;36m'; W='\033[1;37m'; DIM='\033[2m'; BOLD='\033[1m'; NC='\033[0m'
  else
    R=''; G=''; Y=''; C=''; W=''; DIM=''; BOLD=''; NC=''
  fi
}
setup_colors
no_color() { R=''; G=''; Y=''; C=''; W=''; DIM=''; BOLD=''; NC=''; }

json_escape() {
  python3 - <<'PY' "$1"
import json,sys
print(json.dumps(sys.argv[1], ensure_ascii=False))
PY
}

findings_json=()
REACH_PTS=0; REACH_MAX=0
CAMO_PTS=0; CAMO_MAX=0
EXPO_PTS=0; EXPO_MAX=0

score_add() {
  local axis="$1" value="$2"
  case "$axis" in
    reachability) REACH_MAX=$((REACH_MAX+2)); REACH_PTS=$((REACH_PTS+value)) ;;
    camouflage)   CAMO_MAX=$((CAMO_MAX+2)); CAMO_PTS=$((CAMO_PTS+value)) ;;
    exposure)     EXPO_MAX=$((EXPO_MAX+2)); EXPO_PTS=$((EXPO_PTS+value)) ;;
  esac
}


classify_cert_relation() {
  local main_cn="$1" alt_cn="$2"
  if [[ -z "$alt_cn" ]]; then
    echo "none"
  elif [[ -n "$main_cn" && "${alt_cn,,}" == "${main_cn,,}" ]]; then
    echo "same-as-main"
  elif echo "${alt_cn,,}" | grep -qE 'default|localhost|example|dummy'; then
    echo "default-like"
  else
    echo "different-cert"
  fi
}

add_finding() {
  local id="$1" category="$2" title="$3" severity="$4" observed="$5" impact="$6" axis="$7" score="$8" extra_json="${9:-}"
  [[ -n "$axis" && -n "$score" ]] && score_add "$axis" "$score"
  local obj
  obj="{\"id\":$(json_escape "$id"),\"category\":$(json_escape "$category"),\"title\":$(json_escape "$title"),\"severity\":$(json_escape "$severity"),\"observed\":$(json_escape "$observed"),\"impact\":$(json_escape "$impact"),\"score_axis\":$(json_escape "$axis"),\"score_value\":$score"
  if [[ -n "$extra_json" ]]; then
    obj+=",${extra_json}"
  fi
  obj+="}"
  findings_json+=("$obj")
  if [[ "$OUTPUT_MODE" == "text" ]]; then
    local sym
    case "$severity" in
      ok) sym="${G}✓${NC}" ;;
      notice) sym="${Y}~${NC}" ;;
      risk) sym="${R}!${NC}" ;;
      *) sym="${C}•${NC}" ;;
    esac
    printf "  ${DIM}[%02d]${NC} ${W}%-22s${NC} ${DIM}→${NC} %-42s %b\n" "$(( ${#findings_json[@]} ))" "$title" "${observed:0:42}" "$sym"
    printf "       ${DIM}%s${NC}\n" "$impact"
  fi
}

pct() {
  local pts="$1" max="$2"
  if [[ "$max" -eq 0 ]]; then echo 0; else echo $(( pts * 100 / max )); fi
}

require_cmds() {
  local missing=()
  for cmd in "$@"; do command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd"); done
  if [[ ${#missing[@]} -gt 0 ]]; then
    echo "Missing required commands: ${missing[*]}" >&2
    exit 1
  fi
}

is_ipv4() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }
is_ipv6() { [[ "$1" == *:* ]]; }
is_ip_literal() { is_ipv4 "$1" || is_ipv6 "$1"; }

# Validate host: allows domain names, IPv4, and bracket-wrapped IPv6
validate_host() {
  local h="$1"
  if [[ -z "$h" ]]; then
    echo "Error: host must not be empty." >&2; exit 1
  fi
  # IPv6 in brackets [::1]
  if [[ "$h" =~ ^\[.*\]$ ]]; then return; fi
  # IPv4 or domain label characters only
  if [[ ! "$h" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]*$ ]]; then
    echo "Error: invalid host '$h' (unexpected characters)." >&2; exit 1
  fi
}

# Validate SNI: must be a plain domain name (no brackets, no bare IPs accepted
# as SNI since they are rejected by most TLS stacks anyway)
validate_sni() {
  local s="$1"
  [[ -z "$s" ]] && return
  if [[ ! "$s" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]*$ ]]; then
    echo "Error: invalid SNI '$s' (must contain only [a-zA-Z0-9._-])." >&2; exit 1
  fi
}

print_banner() {
  local host="$1" port="$2" mode="$3" ip="$4" asn="$5" sni="$6"
  [[ "$OUTPUT_MODE" != "text" ]] && return
  echo
  printf "${C}  ╔═══════════════════════════════════════════════════════════╗${NC}\n"
  printf "${C}  ║  ${NC}${BOLD}%-55s${NC}  ${C}║${NC}\n" "DPI Masquerade Inspector v${VERSION}"
  printf "${C}  ╠═══════════════════════════════════════════════════════════╣${NC}\n"
  printf "${C}  ║  ${NC}${DIM}Target${NC}  ${BOLD}%-22s${NC}  ${DIM}Port${NC}  ${BOLD}%-7s${NC}         ${C}║${NC}\n" "$host" "$port"
  printf "${C}  ║  ${NC}${DIM}IP${NC}      %-22s  ${DIM}Mode${NC}  ${BOLD}%-13s${NC}  ${C}║${NC}\n" "$ip" "$mode"
  printf "${C}  ║  ${NC}${DIM}ASN${NC}     %-53s${C}║${NC}\n" "${asn:0:52} "
  [[ -n "$sni" ]] && printf "${C}  ║  ${NC}${DIM}SNI${NC}     %-53s${C}║${NC}\n" "${sni:0:52} "
  printf "${C}  ╚═══════════════════════════════════════════════════════════╝${NC}\n\n"
}

parse_vpn_url() {
  local url="$1"
  URL_SCHEME="${url%%://*}"
  local rest="${url#*://}"
  rest="${rest%%#*}"
  local hostpart="${rest%%\?*}"
  local params="${rest#*\?}"; [[ "$params" == "$rest" ]] && params=""
  local hostport="${hostpart##*@}"
  if [[ "$hostport" =~ ^\[(.*)\]:(.*)$ ]]; then
    URL_HOST="${BASH_REMATCH[1]}"
    URL_PORT="${BASH_REMATCH[2]}"
  else
    URL_HOST="${hostport%%:*}"
    URL_PORT="${hostport##*:}"
    [[ "$URL_PORT" == "$URL_HOST" ]] && URL_PORT="443"
  fi
  URL_SNI=""
  if [[ -n "$params" ]]; then
    URL_SNI="$(echo "$params" | tr '&' '\n' | grep '^sni=' | cut -d= -f2- | head -1)"
  fi
}

get_asn() {
  local ip="$1"
  if [[ $NO_ASN -eq 1 ]]; then echo "(lookup disabled)"; return; fi
  local asn=""
  asn=$(curl -s --max-time 3 "https://ipinfo.io/${ip}/org" 2>/dev/null) || true
  [[ -z "$asn" || "$asn" == *"Whoa"* ]] && asn=$(whois "$ip" 2>/dev/null | grep -iE "^(OrgName|org-name|netname|origin):" | head -1 | sed 's/.*:\s*//' | xargs 2>/dev/null) || true
  echo "${asn:-unknown}"
}

compute_confidence() {
  local mode="$1" host="$2" sni="$3" cert_extracted="${4:-0}"
  local score=100
  local reasons=()
  if is_ip_literal "$host" && [[ $SNI_EXPLICIT -eq 0 ]]; then
    score=$((score-35))
    reasons+=("IP target without explicit --sni")
  fi
  if [[ "$mode" == "udp" ]] && is_ip_literal "$sni"; then
    score=$((score-15))
    reasons+=("QUIC tested with IP-like SNI")
  fi
  if [[ "$mode" == "udp" && "$cert_extracted" -eq 0 ]]; then
    score=$((score-15))
    reasons+=("certificate not extracted")
  fi
  (( score < 0 )) && score=0
  local label="high"
  if (( score < 85 )); then label="medium"; fi
  if (( score < 60 )); then label="low"; fi
  CONFIDENCE_SCORE="$score"
  CONFIDENCE_LABEL="$label"
  CONFIDENCE_REASONS="${reasons[*]}"
}

print_notes_and_confidence() {
  [[ "$OUTPUT_MODE" != "text" ]] && return
  if is_ip_literal "$host" && [[ $SNI_EXPLICIT -eq 0 ]]; then
    printf "  %b\n" "${Y}Note:${NC} target is an IP address and no explicit --sni was provided. SNI-sensitive findings may be less reliable."
  fi
  printf "  ${BOLD}%s${NC}    %3s%%  ${DIM}%s${NC}" "$(t confidence)" "$CONFIDENCE_SCORE" "$CONFIDENCE_LABEL"
  if [[ -n "${CONFIDENCE_REASONS:-}" ]]; then
    printf " ${DIM}(reasons: %s)${NC}" "$CONFIDENCE_REASONS"
  fi
  printf "\n\n"
}

run_tcp() {
  local host="$1" port="$2" sni="$3"
  [[ "$OUTPUT_MODE" == "text" ]] && printf "%b\n\n" "${C}  ══ TCP / TLS INSPECTION ${DIM}══════════════════════════════════${NC}"

  local nmap_line
  nmap_line=$(nmap -sV -p "$port" --open "$host" 2>/dev/null | grep "${port}/tcp") || nmap_line=""
  if [[ -n "$nmap_line" ]]; then
    add_finding "port_scan" "reachability" "Port scan" "ok" "${nmap_line:0:42}" "TCP service is reachable on the target port." "reachability" 2
  elif timeout 2 bash -c "echo >/dev/tcp/${host}/${port}" 2>/dev/null; then
    add_finding "port_scan" "reachability" "Port scan" "notice" "open via TCP fallback" "Port is reachable, but nmap fingerprint was inconclusive." "reachability" 1
  else
    add_finding "port_scan" "reachability" "Port scan" "risk" "port closed or filtered" "Target is not reachable over TCP on this port." "reachability" 0
  fi

  local tls_raw cert_raw cn issuer_o not_after days_left=0 tls_ver cipher alpn
  tls_raw=$(echo | timeout "$TIMEOUT" openssl s_client -connect "${host}:${port}" -servername "$sni" -alpn "h2,http/1.1" 2>&1 | tr -d '\000') || tls_raw=""
  cert_raw=$(echo "$tls_raw" | openssl x509 -noout -subject -issuer -dates 2>/dev/null) || cert_raw=""
  cn=$(echo "$cert_raw" | grep subject | sed 's/.*CN *= *//' | sed 's/[,\/].*//')
  issuer_o=$(echo "$cert_raw" | grep issuer | sed 's/.*O *= *//' | sed 's/[,\/].*//')
  not_after=$(echo "$cert_raw" | grep notAfter | cut -d= -f2-)
  [[ -n "$not_after" ]] && days_left=$(( ( $(date -d "$not_after" +%s 2>/dev/null || echo 0) - $(date +%s) ) / 86400 )) || true
  tls_ver=$(echo "$tls_raw" | grep "New," | sed 's/.*New, //;s/,.*//')
  cipher=$(echo "$tls_raw" | grep "Cipher is" | sed 's/.*Cipher is //' | tr -d ' \r')
  alpn=$(echo "$tls_raw" | grep "ALPN protocol" | sed 's/.*ALPN protocol: //' | tr -d ' \r')

  # Extract full cert text for SAN and key-algorithm analysis (reuse tls_raw, no extra roundtrip)
  local cert_text san_raw key_alg
  cert_text=$(echo "$tls_raw" | openssl x509 -noout -text 2>/dev/null) || cert_text=""
  san_raw=$(echo "$cert_text" | grep -A2 "Subject Alternative Name" | grep "DNS:" \
            | tr ',' '\n' | grep "DNS:" | sed 's/.*DNS:\s*//' | tr -d ' \r') || san_raw=""
  key_alg=$(echo "$cert_text" | grep "Public Key Algorithm:" \
            | sed 's/.*Public Key Algorithm:\s*//' | tr -d ' \r' | head -1) || key_alg=""

  if [[ -n "$cn" ]]; then
    local cert_detail="CN=${cn}, issuer=${issuer_o:-?}, ${days_left}d${key_alg:+, $key_alg}"
    if echo "$issuer_o" | grep -qiE "let.s encrypt|digicert|sectigo|globalsign|comodo|zerossl|google|entrust|trustwave|godaddy|buypass"; then
      add_finding "tls_cert" "camouflage" "TLS certificate" "ok" "$cert_detail" "Public CA certificate usually blends better with ordinary HTTPS services." "camouflage" 2
    else
      add_finding "tls_cert" "camouflage" "TLS certificate" "notice" "$cert_detail" "Certificate works, but trust/profile may look less typical." "camouflage" 1
    fi
  else
    add_finding "tls_cert" "camouflage" "TLS certificate" "risk" "no certificate returned" "Could not validate the TLS presentation." "camouflage" 0
  fi

  # SAN match: check whether the certificate explicitly covers the probed SNI.
  # Only meaningful for domain-name targets (not bare IPs).
  if ! is_ip_literal "$sni" && [[ -n "$cn" ]]; then
    local san_match=0
    # Direct match in SAN list
    if echo "$san_raw" | grep -qiF "$sni"; then
      san_match=1
    else
      # Wildcard match: *.example.com covers sub.example.com (one level only)
      local sni_parent="${sni#*.}"
      if [[ "$sni" != "$sni_parent" ]] && echo "$san_raw" | grep -qiF "*.$sni_parent"; then
        san_match=1
      fi
    fi
    # Fallback: old-style cert with CN only and no SANs
    if [[ $san_match -eq 0 && -z "$san_raw" ]]; then
      local cn_lower="${cn,,}" sni_lower="${sni,,}"
      if [[ "$cn_lower" == "$sni_lower" || "$cn_lower" == "*.${sni_lower#*.}" ]]; then
        san_match=1
      fi
    fi
    if [[ $san_match -eq 1 ]]; then
      add_finding "cert_san" "camouflage" "Cert SAN match" "ok" "SNI=${sni} covered by cert" "Certificate explicitly covers the target SNI — expected for a genuine web deployment." "camouflage" 2
    else
      add_finding "cert_san" "camouflage" "Cert SAN match" "notice" "SNI=${sni} not in cert (CN=${cn})" "Certificate does not cover the probed SNI — may indicate a shared, default, or fronted cert." "camouflage" 0
    fi
  fi

  local hs_detail="${tls_ver:-?} / ${cipher:0:20}${alpn:+ / $alpn}"
  if [[ "$tls_ver" == "TLSv1.3" ]]; then
    add_finding "tls_handshake" "reachability" "TLS handshake" "ok" "$hs_detail" "TLS endpoint completed a modern handshake successfully." "reachability" 2
    add_finding "tls_profile" "camouflage" "TLS profile" "ok" "TLSv1.3 / ${cipher:0:20}${alpn:+ / $alpn}" "Modern TLS profile blends better with current HTTPS services." "camouflage" 2
  elif [[ "$tls_ver" == "TLSv1.2" ]]; then
    add_finding "tls_handshake" "reachability" "TLS handshake" "ok" "$hs_detail" "TLS endpoint completed a usable handshake successfully." "reachability" 2
    add_finding "tls_profile" "camouflage" "TLS profile" "notice" "TLSv1.2 / ${cipher:0:20}${alpn:+ / $alpn}" "Service is reachable, but TLS profile is older than many current HTTPS deployments." "camouflage" 1
  else
    add_finding "tls_handshake" "reachability" "TLS handshake" "risk" "failed or unknown TLS version" "TLS endpoint did not complete a usable handshake." "reachability" 0
  fi

  local root_meta root_status root_ct root_elapsed root_headers root_size
  root_meta=$(curl -sk -D - -w '\n__TIME__:%{time_total}\n__CTYPE__:%{content_type}\n__SIZE__:%{size_download}\n' \
              --max-time "$TIMEOUT" "https://${host}:${port}/" -o /dev/null 2>/dev/null) || root_meta=""
  root_headers=$(printf "%s" "$root_meta" | sed '/^__TIME__:/,$d')
  root_status=$(printf "%s" "$root_headers" | head -1 | awk '{print $2}')
  root_elapsed=$(printf "%s" "$root_meta" | sed -n 's/^__TIME__://p' | head -1)
  root_ct=$(printf "%s" "$root_meta" | sed -n 's/^__CTYPE__://p' | head -1 | cut -d';' -f1)
  root_size=$(printf "%s" "$root_meta" | sed -n 's/^__SIZE__://p' | head -1)

  case "$root_status" in
    200)
      # Very small body on a 200 is suspicious — proxy stubs often return empty or
      # near-empty bodies, while real web pages are typically hundreds of bytes or more.
      if [[ -n "$root_size" && "$root_size" -lt 512 ]]; then
        add_finding "http_fallback" "camouflage" "HTTP fallback" "notice" \
          "HTTP 200 body=${root_size}B ${root_ct} (${root_elapsed}s)" \
          "200 with very small body (${root_size}B) may indicate a minimal proxy stub rather than a real page." "camouflage" 1
      else
        add_finding "http_fallback" "camouflage" "HTTP fallback" "ok" \
          "HTTP 200 ${root_ct} ${root_size:+${root_size}B }(${root_elapsed}s)" \
          "Looks like an ordinary HTTPS front page." "camouflage" 2
      fi
      ;;
    301|302|307|403|404)
      add_finding "http_fallback" "camouflage" "HTTP fallback" "notice" \
        "HTTP ${root_status} ${root_ct} (${root_elapsed}s)" \
        "Usable web behavior, though less convincing than a normal 200 page." "camouflage" 1
      ;;
    *)
      add_finding "http_fallback" "camouflage" "HTTP fallback" "risk" \
        "HTTP ${root_status:-000}" \
        "No credible HTTPS fallback page detected." "camouflage" 0
      ;;
  esac

  local redirect_meta redir_code redir_url
  redirect_meta=$(curl -s -o /dev/null -w '%{http_code}\n%{redirect_url}' --max-time "$TIMEOUT" "http://${host}/" 2>/dev/null) || redirect_meta=$'000\n'
  redir_code=$(printf "%s" "$redirect_meta" | sed -n '1p')
  redir_url=$(printf "%s" "$redirect_meta" | sed -n '2p')
  case "$redir_code" in
    301|302) add_finding "http_redirect" "camouflage" "HTTP→HTTPS redirect" "ok" "HTTP ${redir_code} → ${redir_url:0:24}" "Redirect from HTTP to HTTPS matches common site behavior." "camouflage" 2 ;;
    200|403|404) add_finding "http_redirect" "camouflage" "HTTP→HTTPS redirect" "notice" "HTTP ${redir_code}" "Not ideal, but still plausible web behavior." "camouflage" 1 ;;
    *) add_finding "http_redirect" "camouflage" "HTTP→HTTPS redirect" "notice" "HTTP ${redir_code}" "Inconclusive camouflage signal." "camouflage" 1 ;;
  esac

  # Foreign SNI probe uses test.invalid (RFC 2606 reserved — never legitimately hosted,
  # not subject to GeoIP/political filters that affect real domains like google.com).
  local mis_out mis_cn mis_relation
  mis_out=$(echo | timeout "$TIMEOUT" openssl s_client -connect "${host}:${port}" -servername "test.invalid" 2>/dev/null | openssl x509 -noout -subject 2>/dev/null) || mis_out=""
  mis_cn=$(echo "$mis_out" | sed 's/.*CN *= *//' | sed 's/[,\/].*//')
  mis_relation=$(classify_cert_relation "$cn" "$mis_cn")
  local mis_relation_json="$mis_relation"
  [[ "$mis_relation_json" == "none" || -z "$mis_relation_json" ]] && mis_relation_json="unknown"
  local mis_extra
  mis_extra="\"returned_cn\":$(json_escape "$mis_cn"),\"returned_relation\":$(json_escape "$mis_relation_json"),\"main_cn\":$(json_escape "$cn")"
  if [[ -n "$mis_cn" ]]; then
    add_finding "mismatched_sni" "exposure" "Foreign SNI behavior" "risk" "CN=${mis_cn} (${mis_relation})" "Responding cleanly to arbitrary SNI increases scan surface." "exposure" 0 "$mis_extra"
  else
    add_finding "mismatched_sni" "exposure" "Foreign SNI behavior" "ok" "connection closed or no cert" "Ignoring foreign SNI reduces generic probing surface." "exposure" 2 "$mis_extra"
  fi

  local nosni_out nosni_cn nosni_relation
  nosni_out=$(echo | timeout "$TIMEOUT" openssl s_client -connect "${host}:${port}" -noservername 2>/dev/null | openssl x509 -noout -subject 2>/dev/null) || nosni_out=""
  nosni_cn=$(echo "$nosni_out" | sed 's/.*CN *= *//' | sed 's/[,\/].*//')
  nosni_relation=$(classify_cert_relation "$cn" "$nosni_cn")
  local nosni_relation_json="$nosni_relation"
  [[ "$nosni_relation_json" == "none" || -z "$nosni_relation_json" ]] && nosni_relation_json="unknown"
  local nosni_extra
  nosni_extra="\"returned_cn\":$(json_escape "$nosni_cn"),\"returned_relation\":$(json_escape "$nosni_relation_json"),\"main_cn\":$(json_escape "$cn")"
  if [[ -n "$nosni_cn" ]]; then
    add_finding "no_sni" "exposure" "No-SNI behavior" "risk" "CN=${nosni_cn} (${nosni_relation})" "Serving no-SNI clients makes the endpoint easier to classify." "exposure" 0 "$nosni_extra"
  else
    add_finding "no_sni" "exposure" "No-SNI behavior" "ok" "connection closed or no cert" "Requiring SNI reduces generic scan surface." "exposure" 2 "$nosni_extra"
  fi

  local rand_path rand_status
  rand_path="/$(cat /proc/sys/kernel/random/uuid 2>/dev/null | tr -d '-' | head -c 16 || echo test404path99)"
  rand_status=$(curl -sk -o /dev/null -w "%{http_code}" --max-time "$TIMEOUT" "https://${host}:${port}${rand_path}" 2>/dev/null) || rand_status="000"
  case "$rand_status" in
    404|403|200) add_finding "random_path" "camouflage" "Random path probe" "ok" "GET ${rand_path} → HTTP ${rand_status}" "Unknown paths behave like a normal web app/site." "camouflage" 2 ;;
    000) add_finding "random_path" "camouflage" "Random path probe" "risk" "GET ${rand_path} → no response" "Selective handling of unknown paths may look unusual." "camouflage" 0 ;;
    *) add_finding "random_path" "camouflage" "Random path probe" "notice" "GET ${rand_path} → HTTP ${rand_status}" "Behavior is plausible but less typical." "camouflage" 1 ;;
  esac

  local resp_headers srv_hdr hsts
  resp_headers="$root_headers"
  srv_hdr=$(echo "$resp_headers" | grep -i '^Server:' | head -1 | awk '{print $2}' | tr -d '\r')
  hsts=$(echo "$resp_headers" | grep -ic '^Strict-Transport-Security:' || true)
  if [[ -n "$srv_hdr" && "$hsts" -gt 0 ]]; then
    add_finding "headers" "camouflage" "Response headers" "ok" "Server=${srv_hdr}, HSTS=yes" "Header profile looks more like an ordinary HTTPS deployment." "camouflage" 2
  elif [[ -n "$srv_hdr" ]]; then
    add_finding "headers" "camouflage" "Response headers" "notice" "Server=${srv_hdr}, HSTS=no" "Service exposes normal headers, but with a weaker web profile." "camouflage" 1
  else
    add_finding "headers" "camouflage" "Response headers" "notice" "no useful Server header" "Header profile is sparse; camouflage signal is limited." "camouflage" 1
  fi

  # ALPN probe: use the *negotiated* ALPN from the TLS handshake (already in $alpn)
  # as the primary signal. curl --http2 / --http1.1 are used only to verify that
  # HTTP actually works over each version, not to infer what was negotiated.
  local h2_code h1_code
  h2_code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 4 --http2 "https://${host}:${port}/" 2>/dev/null) || h2_code="000"
  h1_code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 4 --http1.1 "https://${host}:${port}/" 2>/dev/null) || h1_code="000"
  local h2_ok=0 h1_ok=0
  [[ "$h2_code" =~ ^(200|301|302|307|403|404)$ ]] && h2_ok=1
  [[ "$h1_code" =~ ^(200|301|302|307|403|404)$ ]] && h1_ok=1
  local alpn_detail="negotiated=${alpn:-none}, h2=${h2_code}, h1=${h1_code}"
  if [[ "$alpn" == "h2" && $h2_ok -eq 1 && $h1_ok -eq 1 ]]; then
    add_finding "alpn_profile" "camouflage" "ALPN profile" "ok" "$alpn_detail" "Server negotiated h2 and accepts both H2 and H1.1 — typical web-like profile." "camouflage" 2
  elif [[ "$alpn" == "h2" && $h2_ok -eq 1 ]]; then
    add_finding "alpn_profile" "camouflage" "ALPN profile" "notice" "$alpn_detail" "Server negotiated h2 but H1.1 path is not responsive; single-ALPN profile." "camouflage" 1
  elif [[ "$alpn" == "h2" ]]; then
    add_finding "alpn_profile" "camouflage" "ALPN profile" "notice" "$alpn_detail" "Server negotiated h2 in TLS but HTTP itself did not respond normally." "camouflage" 1
  elif [[ "$alpn" == "http/1.1" ]]; then
    add_finding "alpn_profile" "camouflage" "ALPN profile" "notice" "$alpn_detail" "Server only negotiated HTTP/1.1; no h2 support detected in TLS handshake." "camouflage" 1
  elif [[ -z "$alpn" && $h2_ok -eq 1 && $h1_ok -eq 1 ]]; then
    # ALPN not advertised in TLS but both HTTP versions respond — infer from behavior
    add_finding "alpn_profile" "camouflage" "ALPN profile" "ok" "$alpn_detail" "Both H2 and H1.1 respond normally; ALPN not captured from TLS handshake." "camouflage" 2
  elif [[ $h2_ok -eq 1 || $h1_ok -eq 1 ]]; then
    add_finding "alpn_profile" "camouflage" "ALPN profile" "notice" "$alpn_detail" "Only one HTTP version responds normally." "camouflage" 1
  else
    add_finding "alpn_profile" "camouflage" "ALPN profile" "risk" "$alpn_detail" "Neither H2 nor H1.1 returned a normal HTTP response." "camouflage" 0
  fi

  # WS paths: standard + common proxy configs + generic transport-sounding paths.
  # Non-standard paths (/proxy, /tunnel, /pipe, etc.) cover custom V2Ray/Xray configs.
  local ws_paths=("/" "/ws" "/wss" "/websocket" "/socket" "/sock"
                  "/ray" "/v2ray" "/xray" "/vless" "/vmess" "/trojan"
                  "/api" "/grpc" "/stream" "/proxy" "/tunnel"
                  "/connect" "/live" "/pipe" "/net" "/data")
  local ws_leaked="" ws_key="dGhlIHNhbXBsZSBub25jZQ=="
  for ws_path in "${ws_paths[@]}"; do
    local ws_code
    ws_code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 3 -H "Connection: Upgrade" -H "Upgrade: websocket" -H "Sec-WebSocket-Key: ${ws_key}" -H "Sec-WebSocket-Version: 13" "https://${host}:${port}${ws_path}" 2>/dev/null) || ws_code="000"
    [[ "$ws_code" == "101" ]] && ws_leaked+="${ws_path}(101) "
  done
  if [[ -n "$ws_leaked" ]]; then
    add_finding "ws_leak" "exposure" "WebSocket leak" "risk" "upgrade accepted on ${ws_leaked:0:26}" "Exposed WS transport paths are easy to fingerprint." "exposure" 0
  else
    add_finding "ws_leak" "exposure" "WebSocket leak" "ok" "no WS upgrade on common paths" "No obvious WS transport endpoint exposure found." "exposure" 2
  fi

  # gRPC paths: standard + common proxy configs + generic service-sounding paths.
  local grpc_paths=("/" "/grpc" "/ray" "/xray" "/vless" "/vmess" "/trojan"
                    "/tun" "/api" "/proxy" "/stream" "/service" "/net" "/data")
  local grpc_strong="" grpc_hint=""
  for grpc_path in "${grpc_paths[@]}"; do
    local grpc_dump grpc_code grpc_ct grpc_status grpc_msg
    grpc_dump=$(curl -sk -D - -o /dev/null --max-time 3 -X POST -H "Content-Type: application/grpc" -H "TE: trailers" "https://${host}:${port}${grpc_path}" 2>/dev/null) || grpc_dump=""
    grpc_code=$(printf "%s" "$grpc_dump" | head -1 | awk '{print $2}')
    grpc_ct=$(printf "%s" "$grpc_dump" | grep -i '^content-type:' | grep -i 'grpc' | head -1) || grpc_ct=""
    grpc_status=$(printf "%s" "$grpc_dump" | grep -i '^grpc-status:' | head -1) || grpc_status=""
    grpc_msg=$(printf "%s" "$grpc_dump" | grep -i '^grpc-message:' | head -1) || grpc_msg=""
    if [[ -n "$grpc_ct" || -n "$grpc_status" || -n "$grpc_msg" ]]; then
      grpc_strong+="${grpc_path}(${grpc_code:-000}) "
    elif [[ "$grpc_code" == "200" ]]; then
      grpc_hint+="${grpc_path}(200) "
    fi
  done
  if [[ -n "$grpc_strong" ]]; then
    add_finding "grpc_leak" "exposure" "gRPC leak" "risk" "strong gRPC semantics on ${grpc_strong:0:24}" "Exposed gRPC transport paths increase fingerprintability." "exposure" 0
  elif [[ -n "$grpc_hint" ]]; then
    add_finding "grpc_leak" "exposure" "gRPC leak" "notice" "weak gRPC hint on ${grpc_hint:0:26}" "A plain HTTP 200 to a gRPC-like POST is weak evidence by itself and may be a normal web app behavior." "exposure" 1
  else
    add_finding "grpc_leak" "exposure" "gRPC leak" "ok" "no gRPC response on common paths" "No obvious gRPC transport endpoint exposure found." "exposure" 2
  fi

  local grpc_strict_dump grpc_strict_code grpc_strict_ct grpc_strict_status grpc_strict_path="" grpc_strict_state="ok"
  for p in "/grpc" "/ray" "/xray" "/vless" "/vmess" "/trojan" "/proxy" "/stream" "/service"; do
    grpc_strict_dump=$(curl -sk --http2 -D - -o /dev/null --max-time 4 -X POST \
      -H "Content-Type: application/grpc" -H "TE: trailers" -H "grpc-timeout: 1S" \
      --data-binary $'\x00\x00\x00\x00\x00' "https://${host}:${port}${p}" 2>/dev/null) || grpc_strict_dump=""
    grpc_strict_code=$(printf "%s" "$grpc_strict_dump" | head -1 | awk '{print $2}')
    grpc_strict_ct=$(printf "%s" "$grpc_strict_dump" | grep -i '^content-type:' | grep -i 'application/grpc' | head -1) || grpc_strict_ct=""
    grpc_strict_status=$(printf "%s" "$grpc_strict_dump" | grep -i '^grpc-status:' | head -1) || grpc_strict_status=""
    if [[ "$grpc_strict_code" == "200" && -n "$grpc_strict_ct" && -n "$grpc_strict_status" ]]; then
      grpc_strict_state="risk"; grpc_strict_path="$p"; break
    elif [[ "$grpc_strict_code" == "200" && -n "$grpc_strict_ct" && "$grpc_strict_state" == "ok" ]]; then
      grpc_strict_state="notice"; grpc_strict_path="$p"
    fi
  done
  case "$grpc_strict_state" in
    risk)
      add_finding "grpc_strict_probe" "exposure" "gRPC strict probe" "risk" "HTTP/2 gRPC semantics on ${grpc_strict_path}" "Strict gRPC semantics under HTTP/2 strongly indicate an exposed transport endpoint." "exposure" 0
      ;;
    notice)
      add_finding "grpc_strict_probe" "exposure" "gRPC strict probe" "notice" "gRPC content-type on ${grpc_strict_path}" "Partial gRPC semantics seen under HTTP/2; suspicious but not conclusive." "exposure" 1
      ;;
    *)
      add_finding "grpc_strict_probe" "exposure" "gRPC strict probe" "ok" "no strict gRPC semantics found" "No strict HTTP/2 gRPC endpoint signature detected." "exposure" 2
      ;;
  esac

  local connect_code
  connect_code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 3 -X CONNECT "https://${host}:${port}/" 2>/dev/null) || connect_code="000"
  case "$connect_code" in
    200) add_finding "http_connect" "exposure" "HTTP CONNECT" "risk" "CONNECT accepted (200)" "Accepting CONNECT resembles proxy behavior." "exposure" 0 ;;
    400|405|501) add_finding "http_connect" "exposure" "HTTP CONNECT" "ok" "CONNECT rejected (${connect_code})" "Rejecting CONNECT matches ordinary web server behavior." "exposure" 2 ;;
    *) add_finding "http_connect" "exposure" "HTTP CONNECT" "notice" "CONNECT returned ${connect_code}" "Behavior is not clearly proxy-like, but not strongly normal either." "exposure" 1 ;;
  esac

  probe_h2_settings "$host" "$port" "$sni"
}

# Optional HTTP/2 SETTINGS fingerprint via nghttp (from package nghttp2-client).
# Known MAX_CONCURRENT_STREAMS baselines: nginx=128, Apache=100, Caddy=250.
# Proxy/relay implementations (Xray, V2Ray) often use 1000 or unlimited (0).
# Skipped silently when nghttp is not installed.
probe_h2_settings() {
  local host="$1" port="$2" sni="$3"
  command -v nghttp >/dev/null 2>&1 || return

  local h2_raw
  h2_raw=$(timeout 5 nghttp -nv --no-verify-peer "https://${host}:${port}/" 2>&1) || h2_raw=""
  [[ -z "$h2_raw" ]] && return

  # Parse SETTINGS values from nghttp verbose output
  local max_streams initial_window enable_push
  max_streams=$(echo "$h2_raw" \
    | grep -oE "SETTINGS_MAX_CONCURRENT_STREAMS\([^)]*\):[0-9]+" \
    | grep -oE "[0-9]+$" | head -1) || max_streams=""
  initial_window=$(echo "$h2_raw" \
    | grep -oE "SETTINGS_INITIAL_WINDOW_SIZE\([^)]*\):[0-9]+" \
    | grep -oE "[0-9]+$" | head -1) || initial_window=""
  enable_push=$(echo "$h2_raw" \
    | grep -oE "SETTINGS_ENABLE_PUSH\([^)]*\):[0-9]+" \
    | grep -oE "[0-9]+$" | head -1) || enable_push=""

  [[ -z "$max_streams$initial_window$enable_push" ]] && return

  local detail="MAX_STREAMS=${max_streams:-?} WIN=${initial_window:-?} PUSH=${enable_push:-?}"
  local verdict="ok"
  local impact="HTTP/2 settings match a typical web-server profile."

  # Very high or unlimited MAX_CONCURRENT_STREAMS is outside standard web-server range
  if [[ -n "$max_streams" ]] && { (( max_streams > 500 )) || (( max_streams == 0 )); }; then
    verdict="notice"
    impact="MAX_CONCURRENT_STREAMS=${max_streams} is outside the normal range for nginx/Apache/Caddy — more typical of relay/proxy implementations."
  fi

  local score_val=2; [[ "$verdict" == "notice" ]] && score_val=1
  add_finding "h2_settings" "camouflage" "HTTP/2 settings" "$verdict" "$detail" "$impact" "camouflage" "$score_val"
}

run_udp() {
  local host="$1" port="$2" sni="$3"
  local extra_flags=()
  is_ip_literal "$host" && extra_flags+=(--host-is-ip)
  [[ $SNI_EXPLICIT -eq 1 ]] && extra_flags+=(--sni-explicit)
  [[ $DEBUG_INFER -eq 1 ]] && extra_flags+=(--debug)
  require_cmds python3
  local color_flag=""
  [[ -z "$NC" ]] && color_flag="--no-color"
  if [[ "$OUTPUT_MODE" == "json" ]]; then
    python3 "${SCRIPT_DIR}/quic_probe.py" "$host" "$port" "$sni" $color_flag --timeout "$TIMEOUT" --json "${extra_flags[@]}"
  else
    python3 "${SCRIPT_DIR}/quic_probe.py" "$host" "$port" "$sni" $color_flag --timeout "$TIMEOUT" "${extra_flags[@]}"
  fi
}

build_payload_json() {
  local host="$1" port="$2" mode="$3" ip="$4" asn="$5" sni="$6" cert_extracted="${7:-0}"
  compute_confidence "$mode" "$host" "$sni" "$cert_extracted"
  local findings_joined=""
  local first=1
  for item in "${findings_json[@]}"; do
    if [[ $first -eq 1 ]]; then findings_joined+="$item"; first=0; else findings_joined+=",$item"; fi
  done
  cat <<EOF
{
  "target": {
    "host": $(json_escape "$host"),
    "port": $port,
    "mode": $(json_escape "$mode"),
    "ip": $(json_escape "$ip"),
    "asn": $(json_escape "$asn"),
    "sni": $(json_escape "$sni"),
    "recommend_fixes": ${RECOMMEND_FIXES}
  },
  "confidence": {
    "score": $CONFIDENCE_SCORE,
    "label": $(json_escape "$CONFIDENCE_LABEL"),
    "reasons": $(json_escape "$CONFIDENCE_REASONS")
  },
  "scores": {
    "reachability": {"pts": $REACH_PTS, "max": $REACH_MAX, "pct": $(pct "$REACH_PTS" "$REACH_MAX")},
    "camouflage": {"pts": $CAMO_PTS, "max": $CAMO_MAX, "pct": $(pct "$CAMO_PTS" "$CAMO_MAX")},
    "exposure": {"pts": $EXPO_PTS, "max": $EXPO_MAX, "pct": $(pct "$EXPO_PTS" "$EXPO_MAX")}
  },
  "findings": [${findings_joined}]
}
EOF
}

emit_json() {
  local host="$1" port="$2" mode="$3" ip="$4" asn="$5" sni="$6" cert_extracted="${7:-0}"
  local payload
  payload=$(build_payload_json "$host" "$port" "$mode" "$ip" "$asn" "$sni" "$cert_extracted")
  payload=$(echo "$payload" | jq --arg lang "$LANG_MODE" '. + {lang: $lang}')
  echo "$payload" | python3 "${SCRIPT_DIR}/protocol_infer.py" --enrich
}

print_inference_text() {
  [[ "$OUTPUT_MODE" != "text" ]] && return
  local cert_extracted=0
  [[ -n "${cn:-}" ]] && cert_extracted=1
  local args=(--text)
  [[ $DEBUG_INFER -eq 1 ]] && args+=(--debug)
  local payload
  payload=$(build_payload_json "$host" "$port" "tcp" "$ip" "$asn" "$sni" "$cert_extracted")
  payload=$(echo "$payload" | jq --arg lang "$LANG_MODE" '. + {lang: $lang}')
  echo "$payload" | python3 "${SCRIPT_DIR}/protocol_infer.py" "${args[@]}"
}

print_summary() {
  [[ "$OUTPUT_MODE" != "text" ]] && return
  local cert_extracted=0
  [[ -n "${cn:-}" ]] && cert_extracted=1
  compute_confidence "tcp" "$host" "$sni" "$cert_extracted"
  echo
  printf "  ${BOLD}%s${NC}  %3s%%  ${DIM}%s/%s pts${NC}\n" "$(t reachability)" "$(pct "$REACH_PTS" "$REACH_MAX")" "$REACH_PTS" "$REACH_MAX"
  printf "  ${BOLD}%s${NC}    %3s%%  ${DIM}%s/%s pts${NC}\n" "$(t camouflage)" "$(pct "$CAMO_PTS" "$CAMO_MAX")" "$CAMO_PTS" "$CAMO_MAX"
  printf "  ${BOLD}%s${NC}      %3s%%  ${DIM}%s/%s pts${NC}\n" "$(t exposure)" "$(pct "$EXPO_PTS" "$EXPO_MAX")" "$EXPO_PTS" "$EXPO_MAX"
  print_notes_and_confidence
}

usage() {
  printf "%b" "
${BOLD}dpi_check.sh${NC} v${VERSION} — DPI Masquerade Inspector + protocol inference

${BOLD}USAGE${NC}
  $(basename "$0") <target> [port] [options]

${BOLD}OPTIONS${NC}
  -m, --mode  tcp|udp|auto   Protocol (default: auto-detect)
  -s, --sni   DOMAIN         Override SNI for probes
  -t, --timeout N            Probe timeout in seconds (default: 5)
      --json                 Emit machine-readable JSON
      --debug-infer          Show inference internals and ranked hypotheses
      --hardening-hints      Show hardening hints in the text output (default on)
      --recommend-fixes      Alias for --hardening-hints
      --lang=ru|en           Output language for interpretation layer (default: en)
      --no-asn               Skip external ASN lookup (ipinfo.io) for privacy
      --no-color             Plain output, no ANSI colors
  -h, --help                 Show this help

"
}

main() {
  [[ $# -eq 0 ]] && { usage; exit 0; }
  [[ "$1" == "-h" || "$1" == "--help" ]] && { usage; exit 0; }

  local host="" port="443" mode="auto" sni=""
  local first="$1"; shift
  if echo "$first" | grep -qE '^(vless|hysteria2|trojan|ss)://'; then
    parse_vpn_url "$first"
    host="$URL_HOST"; port="$URL_PORT"; sni="${URL_SNI:-}"
    [[ -n "$sni" ]] && SNI_EXPLICIT=1
    case "$URL_SCHEME" in
      hysteria2) mode="udp" ;;
      vless|trojan) mode="tcp" ;;
    esac
  else
    host="$first"
    [[ $# -gt 0 && "$1" =~ ^[0-9]+$ ]] && { port="$1"; shift; }
  fi

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -m|--mode) mode="$2"; shift 2 ;;
      -s|--sni) sni="$2"; SNI_EXPLICIT=1; shift 2 ;;
      -t|--timeout) TIMEOUT="$2"; shift 2 ;;
      --json) OUTPUT_MODE="json"; shift ;;
      --debug-infer) DEBUG_INFER=1; shift ;;
      --hardening-hints) SHOW_HINTS=1; shift ;;
      --recommend-fixes) SHOW_HINTS=1; RECOMMEND_FIXES=1; shift ;;
      --lang=ru) LANG_MODE="ru"; shift ;;
      --lang=en) LANG_MODE="en"; shift ;;
      --no-asn) NO_ASN=1; shift ;;
      --no-color) no_color; shift ;;
      -h|--help) usage; exit 0 ;;
      *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
  done

  # Validate port range
  if [[ ! "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
    echo "Error: invalid port '$port' (must be 1–65535)." >&2; exit 1
  fi

  validate_host "$host"

  [[ -z "$sni" ]] && sni="$host"
  validate_sni "$sni"

  local ip=""
  ip=$(dig +short "$host" 2>/dev/null | grep -E '^[0-9]' | head -1) || true
  [[ -z "$ip" ]] && ip=$(getent hosts "$host" 2>/dev/null | awk '{print $1}' | head -1) || true
  [[ -z "$ip" ]] && ip="$host"
  local asn=""
  asn=$(get_asn "$ip") || asn="unknown"

  if [[ "$mode" == "auto" ]]; then
    if timeout 2 bash -c "echo >/dev/tcp/${host}/${port}" 2>/dev/null; then
      mode="tcp"
    else
      # TCP is unreachable; assume UDP/QUIC.
      # Note: UDP open/filtered states are indistinguishable without an actual
      # QUIC handshake — quic_probe.py will perform that check and report
      # if the port turns out to be unresponsive.
      mode="udp"
    fi
  fi

  if [[ "$mode" == "udp" ]]; then
    print_banner "$host" "$port" "UDP / QUIC" "$ip" "$asn" "$sni"
    run_udp "$host" "$port" "$sni"
    exit 0
  fi

  require_cmds nmap openssl curl nc dig getent python3 jq
  print_banner "$host" "$port" "TCP / TLS" "$ip" "$asn" "$sni"
  run_tcp "$host" "$port" "$sni"

  if [[ "$OUTPUT_MODE" == "json" ]]; then
    local cert_extracted=0
    [[ -n "${cn:-}" ]] && cert_extracted=1
    emit_json "$host" "$port" "tcp" "$ip" "$asn" "$sni" "$cert_extracted"
  else
    print_summary
    print_inference_text
  fi
}

main "$@"
