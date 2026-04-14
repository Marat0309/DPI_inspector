#!/usr/bin/env bash
# ┌─────────────────────────────────────────────────────────────┐
# │  harden_nginx.sh — Nginx masquerade hardening               │
# │  Fixes: HTTP redirect, HSTS, default SNI drop               │
# └─────────────────────────────────────────────────────────────┘
#
# Usage: ./harden_nginx.sh <domain> [--dry-run] [--yes]
#
# What it fixes:
#   1. Port 80 returns 200 instead of 301 redirect to HTTPS
#   2. Missing HSTS header (Strict-Transport-Security)
#   3. Default server returns cert on foreign/no SNI instead of dropping

set -uo pipefail

DOMAIN="${1:-}"
DRY_RUN=0
AUTO_YES=0

for arg in "${@:2}"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --yes|-y)  AUTO_YES=1 ;;
  esac
done

# ── Colors ────────────────────────────────────────────────────
if [[ -t 1 ]]; then
  R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m'
  C='\033[0;36m' W='\033[1;37m' DIM='\033[2m' BOLD='\033[1m' NC='\033[0m'
else
  R='' G='' Y='' C='' W='' DIM='' BOLD='' NC=''
fi

info()  { printf "  ${C}•${NC} %s\n" "$1"; }
ok()    { printf "  ${G}✓${NC} %s\n" "$1"; }
warn()  { printf "  ${Y}~${NC} %s\n" "$1"; }
err()   { printf "  ${R}✗${NC} %s\n" "$1"; }
fix()   { printf "  ${Y}▸${NC} ${BOLD}FIX:${NC} %s\n" "$1"; }

div() { printf "  ${DIM}%s${NC}\n" "$(printf '─%.0s' {1..60})"; }

usage() {
  echo
  echo "  Usage: $(basename "$0") <domain> [--dry-run] [--yes]"
  echo
  echo "  Options:"
  echo "    --dry-run   Show what would be changed, don't apply"
  echo "    --yes, -y   Apply without confirmation prompt"
  echo
  echo "  Examples:"
  echo "    $(basename "$0") ru.guardx.online"
  echo "    $(basename "$0") example.com --dry-run"
  echo "    $(basename "$0") example.com --yes"
  echo
}

[[ -z "$DOMAIN" ]] && { usage; exit 1; }

# ── Detect nginx setup ────────────────────────────────────────
detect_nginx() {
  # Docker container named *nginx*
  if command -v docker &>/dev/null; then
    NGINX_CONTAINER=$(docker ps --format '{{.Names}}' 2>/dev/null \
      | grep -i nginx | head -1) || NGINX_CONTAINER=""
  else
    NGINX_CONTAINER=""
  fi

  if [[ -n "$NGINX_CONTAINER" ]]; then
    NGINX_MODE="docker"
    # Find host mount for conf.d
    CONF_D=$(docker inspect "$NGINX_CONTAINER" 2>/dev/null \
      | python3 -c "
import sys,json
mounts=json.load(sys.stdin)[0]['Mounts']
for m in mounts:
    if 'conf.d' in m.get('Destination',''):
        print(m['Source']); break
" 2>/dev/null) || CONF_D=""
    NGINX_CONF=$(docker inspect "$NGINX_CONTAINER" 2>/dev/null \
      | python3 -c "
import sys,json
mounts=json.load(sys.stdin)[0]['Mounts']
for m in mounts:
    src=m.get('Source',''); dst=m.get('Destination','')
    if dst=='/etc/nginx/nginx.conf':
        print(src); break
" 2>/dev/null) || NGINX_CONF=""
  elif command -v nginx &>/dev/null; then
    NGINX_MODE="native"
    CONF_D=$(nginx -T 2>/dev/null | grep "conf.d" | head -1 | awk '{print $NF}' \
      | xargs dirname 2>/dev/null) || CONF_D="/etc/nginx/conf.d"
    NGINX_CONF="/etc/nginx/nginx.conf"
  else
    err "nginx not found (neither native nor Docker)"
    exit 1
  fi
}

# ── Reload nginx ──────────────────────────────────────────────
reload_nginx() {
  if [[ "$NGINX_MODE" == "docker" ]]; then
    docker exec "$NGINX_CONTAINER" nginx -t 2>&1 | grep -E "ok|error"
    docker kill -s HUP "$NGINX_CONTAINER" &>/dev/null
  else
    nginx -t 2>&1 | grep -E "ok|error"
    systemctl reload nginx 2>/dev/null || nginx -s reload
  fi
}

# ── Test nginx config inside container ───────────────────────
test_nginx() {
  if [[ "$NGINX_MODE" == "docker" ]]; then
    docker exec "$NGINX_CONTAINER" nginx -t 2>&1
  else
    nginx -t 2>&1
  fi
}

# ── In-place edit inside nginx container ─────────────────────
# Usage: inplace_edit <file> <old_pattern> <new_text>
inplace_sed_docker() {
  local file="$1" old="$2" new="$3"
  docker exec "$NGINX_CONTAINER" sh -c "
    awk 'BEGIN{found=0} /${old}/{if(!found){print \"${new}\"; found=1}; next} {print}' \
      \"${file}\" > /tmp/_harden_tmp && cat /tmp/_harden_tmp > \"${file}\"
  "
}

# ── Write to a file (host or in docker) ──────────────────────
write_to() {
  local target="$1"
  if [[ "$NGINX_MODE" == "docker" ]]; then
    # Write via container stdin redirect
    docker exec -i "$NGINX_CONTAINER" sh -c "cat > ${target}"
  else
    cat > "$target"
  fi
}

# ── Read file content ─────────────────────────────────────────
read_file() {
  local f="$1"
  if [[ "$NGINX_MODE" == "docker" ]]; then
    docker exec "$NGINX_CONTAINER" cat "$f" 2>/dev/null
  else
    cat "$f" 2>/dev/null
  fi
}

# ── Find domain config file ───────────────────────────────────
find_domain_conf() {
  local domain="$1"
  # Search host conf.d directory
  if [[ -n "$CONF_D" ]]; then
    local found
    found=$(grep -rl "server_name\s*${domain}" "$CONF_D" 2>/dev/null | head -1) || found=""
    [[ -n "$found" ]] && { echo "$found"; return; }
    # Fallback: any conf file mentioning domain
    found=$(grep -rl "$domain" "$CONF_D" 2>/dev/null | grep '\.conf$' | head -1) || found=""
    [[ -n "$found" ]] && { echo "$found"; return; }
  fi
  echo ""
}

# ── Check 1: HTTP port 80 redirect ───────────────────────────
check_http_redirect() {
  local conf_file="$1"
  local content
  content=$(cat "$conf_file" 2>/dev/null) || content=""

  # Look for port 80 server block for our domain
  local has_redirect
  has_redirect=$(echo "$content" | grep -c "return 301.*https" || true)

  if [[ "$has_redirect" -gt 0 ]]; then
    ok "Port 80 already redirects to HTTPS"
    return 0
  fi

  warn "Port 80 does not redirect to HTTPS"
  fix "Add 'return 301 https://\$host\$request_uri;' to port 80 server block"
  FIXES+=("http_redirect:$conf_file")
  return 1
}

# ── Check 2: HSTS ─────────────────────────────────────────────
check_hsts() {
  local conf_file="$1"
  local content
  content=$(cat "$conf_file" 2>/dev/null) || content=""

  if echo "$content" | grep -q "Strict-Transport-Security"; then
    ok "HSTS header already present"
    return 0
  fi

  warn "HSTS header missing on HTTPS server block"
  fix "Add Strict-Transport-Security header to port 443/10444 server block"
  FIXES+=("hsts:$conf_file")
  return 1
}

# ── Check 3: Default server SNI drop ─────────────────────────
check_default_sni() {
  # Look in nginx.conf for the catch-all default server
  local nginx_conf_content
  if [[ -n "$NGINX_CONF" && -f "$NGINX_CONF" ]]; then
    nginx_conf_content=$(cat "$NGINX_CONF" 2>/dev/null) || nginx_conf_content=""
  else
    nginx_conf_content=""
  fi

  # Check for default_server with return 444 or similar drop
  local has_drop
  has_drop=$(echo "$nginx_conf_content" | grep -c "return 444\|return 400\|deny all" || true)

  if [[ "$has_drop" -gt 0 ]]; then
    ok "Default server already drops unknown SNI connections"
    return 0
  fi

  # Check what the default server does
  local has_default
  has_default=$(echo "$nginx_conf_content" | grep -c "server_name _\|default_server" || true)

  if [[ "$has_default" -gt 0 ]]; then
    warn "Default server block found but does NOT drop connections"
    fix "Change default server block to 'return 444' (silent drop)"
    FIXES+=("default_sni_drop:${NGINX_CONF}")
  else
    warn "No explicit default server block found — unknown SNI handling unclear"
    fix "Add default server block with 'return 444' to nginx.conf"
    FIXES+=("default_sni_add:${NGINX_CONF}")
  fi
  return 1
}

# ── Apply: HTTP redirect ──────────────────────────────────────
apply_http_redirect() {
  local conf_file="$1"
  info "Patching port 80 server block in $conf_file"

  # Read current content
  local content
  content=$(cat "$conf_file")

  # Find the port 80 block for our domain and add return 301
  # Strategy: add return 301 before the closing brace of the location / block
  # or replace existing fallback location
  local new_content
  new_content=$(echo "$content" | awk -v domain="$DOMAIN" '
    /listen 80/ { in_http=1 }
    in_http && /location \/ \{/ { in_loc=1 }
    in_http && in_loc && /return/ { $0="        return 301 https://$host$request_uri;" }
    in_http && in_loc && /proxy_pass|try_files/ {
      # Replace the action with a redirect
      print "        return 301 https://$host$request_uri;"
      while (getline > 0 && !/\}/) {}
      in_loc=0
      next
    }
    { print }
  ')

  # Simpler approach: just ensure the location / in port 80 block has redirect
  # Patch: find "location / {" inside port-80 server block and add redirect
  python3 - "$conf_file" "$DOMAIN" <<'PYEOF'
import sys, re

conf_file = sys.argv[1]
domain = sys.argv[2]

with open(conf_file) as f:
    content = f.read()

# Find port 80 server block and patch location /
# Add return 301 after the opening brace of location /
# in the server block that has "listen 80"
def patch_http_block(text):
    lines = text.split('\n')
    in_80_block = False
    brace_depth = 0
    result = []
    i = 0
    patched = False
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if not in_80_block:
            # Detect start of server block with listen 80
            if stripped.startswith('server') and '{' in line:
                # Look ahead for listen 80
                j = i + 1
                depth = 1
                block_lines = [line]
                while j < len(lines) and depth > 0:
                    block_lines.append(lines[j])
                    depth += lines[j].count('{') - lines[j].count('}')
                    if re.search(r'listen\s+80\b', lines[j]) and re.search(r'server_name\s+' + re.escape(domain), '\n'.join(block_lines)):
                        in_80_block = True
                        brace_depth = 1
                        break
                    j += 1
                if not in_80_block:
                    result.append(line)
                    i += 1
                    continue
            else:
                result.append(line)
                i += 1
                continue

        # Inside port 80 server block
        brace_depth += line.count('{') - line.count('}')
        if brace_depth <= 0:
            in_80_block = False

        # Replace location / content with redirect
        if re.match(r'\s*location\s+/\s*\{', line) and not patched:
            indent = len(line) - len(line.lstrip())
            result.append(line)
            i += 1
            # Skip until closing brace of this location block
            depth = 1
            while i < len(lines) and depth > 0:
                depth += lines[i].count('{') - lines[i].count('}')
                if depth > 0:
                    i += 1
                    continue
                # This is the closing brace
                result.append(' ' * (indent + 4) + 'return 301 https://$host$request_uri;')
                result.append(lines[i])  # closing }
                patched = True
                i += 1
                break
            continue

        result.append(line)
        i += 1
    return '\n'.join(result), patched

new_content, patched = patch_http_block(content)
if patched:
    with open(conf_file, 'w') as f:
        f.write(new_content)
    print(f"  patched: location / now redirects to HTTPS")
else:
    # Fallback: add return 301 to the location / block manually
    print(f"  WARNING: could not auto-patch, please add manually:")
    print(f"    In the 'listen 80; server_name {domain}' block:")
    print(f"    location / {{ return 301 https://$host$request_uri; }}")
PYEOF
}

# ── Apply: HSTS ───────────────────────────────────────────────
apply_hsts() {
  local conf_file="$1"
  info "Adding HSTS header to HTTPS server block in $conf_file"

  python3 - "$conf_file" "$DOMAIN" <<'PYEOF'
import sys, re

conf_file = sys.argv[1]
domain = sys.argv[2]
hsts_line = '    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;'

with open(conf_file) as f:
    content = f.read()

# Find HTTPS server block (listen 443 or 10444) for domain and add HSTS after ssl_dhparam or ssl_certificate_key
def add_hsts(text):
    lines = text.split('\n')
    result = []
    in_https = False
    added = False
    brace_depth = 0

    for i, line in enumerate(lines):
        # Detect HTTPS server block
        if not in_https:
            if re.match(r'\s*server\s*\{', line):
                # Check if next ~10 lines have listen 443/10444 and our domain
                ahead = '\n'.join(lines[i:i+20])
                if re.search(r'listen\s+(443|10444)\s*ssl', ahead) and domain in ahead:
                    in_https = True
                    brace_depth = 1
                    result.append(line)
                    continue

        if in_https:
            brace_depth += line.count('{') - line.count('}')
            if brace_depth <= 0:
                in_https = False
                added = False

            # Add HSTS after ssl_dhparam or ssl_certificate_key line
            result.append(line)
            if not added and re.search(r'ssl_dhparam|ssl_certificate_key', line):
                result.append(hsts_line)
                added = True
            continue

        result.append(line)

    return '\n'.join(result)

new_content = add_hsts(content)
if hsts_line.strip() in new_content:
    with open(conf_file, 'w') as f:
        f.write(new_content)
    print("  added HSTS header to HTTPS server block")
else:
    print("  WARNING: could not auto-add HSTS, please add manually:")
    print(f'    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;')
PYEOF
}

# ── Apply: Default SNI drop ───────────────────────────────────
apply_default_sni_drop() {
  local nginx_conf="$1"
  local action="$2"  # "drop" or "add"
  info "Patching default server in $nginx_conf"

  python3 - "$nginx_conf" "$action" <<'PYEOF'
import sys, re

nginx_conf = sys.argv[1]
action = sys.argv[2]

with open(nginx_conf) as f:
    content = f.read()

cert_path = None
key_path  = None
# Grab first ssl_certificate paths seen in file (reuse for default block)
m = re.search(r'ssl_certificate\s+([^;]+);', content)
if m: cert_path = m.group(1).strip()
m = re.search(r'ssl_certificate_key\s+([^;]+);', content)
if m: key_path = m.group(1).strip()

if action == "drop":
    # Replace content of default server block (server_name _;) with return 444
    def replace_default_block(text):
        lines = text.split('\n')
        result = []
        in_default = False
        brace_depth = 0
        replaced = False
        i = 0
        while i < len(lines):
            line = lines[i]
            if not in_default:
                if re.match(r'\s*server\s*\{', line):
                    ahead = '\n'.join(lines[i:i+15])
                    if re.search(r'server_name\s+_', ahead):
                        in_default = True
                        brace_depth = 1
                        result.append(line)
                        i += 1
                        continue
            if in_default:
                brace_depth += line.count('{') - line.count('}')
                if brace_depth <= 0:
                    in_default = False
                    replaced = True
                    result.append(line)
                    i += 1
                    continue
                # Skip old content, inject new
                if brace_depth == 1 and not replaced:
                    stripped = line.strip()
                    if stripped.startswith('listen') or stripped.startswith('server_name'):
                        result.append(line)
                    elif stripped.startswith('ssl_certificate') or stripped.startswith('include') or stripped.startswith('ssl_dhparam'):
                        result.append(line)
                    elif stripped == '' or stripped.startswith('#'):
                        result.append(line)
                    else:
                        pass  # drop old directives (add_header, return old code)
                    i += 1
                    continue
            result.append(line)
            i += 1
        return '\n'.join(result), replaced

    new_content, ok = replace_default_block(content)
    # Now add return 444 in the default server block
    new_content = re.sub(
        r'(server_name\s+_;)',
        r'\1\n    return 444;',
        new_content, count=1
    )
    # Remove duplicate return lines
    new_content = re.sub(r'(\s*return 444;\s*)+', '\n    return 444;\n', new_content)

elif action == "add":
    # Append a new default server block at the end of http {} section
    cert = cert_path or '/etc/letsencrypt/live/default/fullchain.pem'
    key  = key_path  or '/etc/letsencrypt/live/default/privkey.pem'
    block = f"""
    # Default server — drop connections with unknown/foreign SNI
    server {{
        listen 10444 ssl default_server;
        server_name _;
        ssl_certificate     {cert};
        ssl_certificate_key {key};
        return 444;
    }}
"""
    # Insert before last closing brace of http block
    new_content = re.sub(r'(\n\})\s*$', block + r'\n}', content, count=1)

with open(nginx_conf, 'w') as f:
    f.write(new_content)
print("  default server block now drops unknown SNI (return 444)")
PYEOF
}

# ── Confirm prompt ────────────────────────────────────────────
confirm() {
  local msg="$1"
  [[ "$AUTO_YES" -eq 1 ]] && return 0
  printf "\n  ${Y}Apply these fixes?${NC} [y/N] "
  read -r ans
  [[ "$ans" =~ ^[Yy]$ ]]
}

# ══════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════
echo
printf "${C}  ╔═══════════════════════════════════════════════════════╗${NC}\n"
printf "${C}  ║${NC}  ${BOLD}Nginx Masquerade Hardener${NC}                            ${C}║${NC}\n"
printf "${C}  ║${NC}  Domain: ${BOLD}%-43s${NC}  ${C}║${NC}\n" "$DOMAIN"
[[ "$DRY_RUN" -eq 1 ]] && \
printf "${C}  ║${NC}  ${Y}DRY RUN — no changes will be made${NC}                   ${C}║${NC}\n"
printf "${C}  ╚═══════════════════════════════════════════════════════╝${NC}\n"
echo

# Detect nginx
detect_nginx
info "Nginx mode: ${BOLD}${NGINX_MODE}${NC}${NGINX_CONTAINER:+ (container: $NGINX_CONTAINER)}"
info "conf.d path: ${CONF_D:-not found}"
info "nginx.conf:  ${NGINX_CONF:-not found}"
echo

# Find domain config
DOMAIN_CONF=$(find_domain_conf "$DOMAIN")
if [[ -z "$DOMAIN_CONF" ]]; then
  warn "Could not find a .conf file for domain '$DOMAIN' in ${CONF_D}"
  info "Checked: $CONF_D"
  info "You may need to specify the config file manually"
  DOMAIN_CONF=""
fi

[[ -n "$DOMAIN_CONF" ]] && info "Domain config: ${BOLD}${DOMAIN_CONF}${NC}"
echo

# Run checks
FIXES=()
div
printf "  ${BOLD}Checking...${NC}\n"
div
echo

[[ -n "$DOMAIN_CONF" ]] && check_http_redirect "$DOMAIN_CONF"
[[ -n "$DOMAIN_CONF" ]] && check_hsts "$DOMAIN_CONF"
check_default_sni
echo

# Report
if [[ ${#FIXES[@]} -eq 0 ]]; then
  ok "Nothing to fix — server already hardened"
  echo
  exit 0
fi

printf "  ${Y}Found %d issue(s) to fix.${NC}\n" "${#FIXES[@]}"

[[ "$DRY_RUN" -eq 1 ]] && {
  echo
  warn "Dry run — exiting without changes"
  echo
  exit 0
}

confirm "Apply fixes?" || { echo; info "Aborted."; echo; exit 0; }

echo
div
printf "  ${BOLD}Applying fixes...${NC}\n"
div
echo

for fix_item in "${FIXES[@]}"; do
  fix_type="${fix_item%%:*}"
  fix_target="${fix_item##*:}"
  case "$fix_type" in
    http_redirect)   apply_http_redirect "$fix_target" ;;
    hsts)            apply_hsts "$fix_target" ;;
    default_sni_drop) apply_default_sni_drop "$fix_target" "drop" ;;
    default_sni_add)  apply_default_sni_drop "$fix_target" "add" ;;
  esac
done

echo
div
printf "  ${BOLD}Testing nginx config...${NC}\n"
div
echo

test_result=$(test_nginx 2>&1)
if echo "$test_result" | grep -q "successful"; then
  ok "nginx config test passed"
  echo
  info "Reloading nginx..."
  reload_nginx && ok "nginx reloaded" || err "reload failed — check manually"
else
  err "nginx config test FAILED — changes NOT applied to live server"
  printf "%s\n" "$test_result"
  echo
  warn "Fix the config manually, then reload nginx"
fi

echo
printf "  ${G}Done.${NC} Run ${BOLD}dpi_check.sh ${DOMAIN}${NC} to verify improvements.\n"
echo
