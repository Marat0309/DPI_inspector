# dpi-check

A shell tool that measures **how well a server's masquerade holds up against DPI inspection**.

It does not try to detect which VPN protocol is running. It probes the server the way a DPI system or a censor would — and scores how closely it resembles a normal web server.

Supports both **TCP/TLS** servers (VLESS+Reality, Trojan, NaiveProxy, V2Ray WS/gRPC/H2, XTLS Vision) and **UDP/QUIC** servers (Hysteria2, TUIC, V2Ray QUIC).

---

## What it checks

### TCP / TLS mode — 14 checks

| # | Check | What it catches |
|---|-------|-----------------|
| 1 | Port scan | Service fingerprint visible to scanners |
| 2 | TLS certificate | Self-signed vs trusted CA, expiry |
| 3 | TLS handshake | Version (1.3/1.2), cipher, ALPN |
| 4 | HTTP fallback | Does the server serve a real page? |
| 5 | HTTP→HTTPS redirect | Does port 80 redirect properly? |
| 6 | Mismatched SNI | Certificate served with foreign SNI |
| 7 | No SNI | Certificate served without SNI |
| 8 | Random path | Consistent response to unknown paths |
| 9 | Raw TCP (non-TLS) | Proper rejection of plaintext |
| 10 | Response headers | Server header, HSTS, X-Frame-Options |
| 11 | **WebSocket leak** | Exposed WS endpoint on common paths |
| 12 | **gRPC leak** | Exposed gRPC endpoint on common paths |
| 13 | **HTTP CONNECT** | Server accepts CONNECT (proxy behavior) |
| 14 | **Path consistency** | Different paths return inconsistent codes |

### UDP / QUIC mode — 8 checks

| # | Check | What it catches |
|---|-------|-----------------|
| 1 | UDP port scan | Port reachability |
| 2 | Raw UDP junk | Server responds to invalid QUIC packets |
| 3 | QUIC handshake | TLS handshake success / failure |
| 4 | TLS certificate | Certificate quality |
| 5 | Mismatched SNI | Server accepts any SNI |
| 6 | No SNI | Server behavior without SNI |
| 7 | HTTP/3 fallback | H3 response to GET / |
| 8 | Port hopping range | Spot-check of hopping port range |

---

## Score

Each check returns **pass** (2 pts), **warn** (1 pt), **fail** (0 pts), or **info** (no score).

```
96%  ███████████████████████░  EXCELLENT — passes DPI inspection
75%  ██████████████████░░░░░░  GOOD      — minor fingerprint risks
55%  █████████████░░░░░░░░░░░  AVERAGE   — several issues detected
 <55%  ████░░░░░░░░░░░░░░░░░░░░  POOR      — high fingerprint risk
```

---

## Install

```bash
git clone https://github.com/your-username/dpi-check
cd dpi-check
chmod +x dpi_check.sh

# UDP/QUIC mode only:
pip install -r requirements.txt
```

### Dependencies

| Tool | Purpose | Install |
|------|---------|---------|
| `nmap` | Port scanning | `apt install nmap` |
| `openssl` | TLS probing | usually pre-installed |
| `curl` | HTTP probing | usually pre-installed |
| `nc` | Raw TCP probe | `apt install netcat-openbsd` |
| `python3` + `aioquic` | UDP/QUIC probing | `pip install aioquic` |

---

## Usage

```bash
./dpi_check.sh <target> [port] [options]
```

**Target** can be a hostname, IP address, or a VPN config URL:

```bash
# Hostname (auto-detects TCP/UDP)
./dpi_check.sh example.com

# IP + port + forced TCP mode with custom SNI
./dpi_check.sh 1.2.3.4 443 --mode tcp --sni github.com

# Parse vless:// URL directly — extracts host, port, SNI automatically
./dpi_check.sh "vless://uuid@server.com:443?security=reality&sni=apple.com"

# Parse hysteria2:// URL directly
./dpi_check.sh "hysteria2://password@server.com:443"
```

### Options

```
-m, --mode  tcp|udp|auto    Protocol mode (default: auto-detect)
-s, --sni   DOMAIN          Override SNI for TLS probes
-t, --timeout N             Seconds per probe (default: 5)
    --no-color              Plain output without ANSI colors
-h, --help                  Show help
```

---

## Example output

```
  ╔═══════════════════════════════════════════════════════════╗
  ║  DPI Masquerade Inspector v2.0.0                          ║
  ╠═══════════════════════════════════════════════════════════╣
  ║  Target  example.com             Port  443             ║
  ║  IP      1.2.3.4                 Mode  TCP / TLS      ║
  ║  ASN     AS12345 Example Hosting Ltd                        ║
  ╚═══════════════════════════════════════════════════════════╝

  ══ TCP / TLS CHECKS ═══════════════════════════════════════

  [ 1]  Port scan               →  ssl/http nginx                        ✓
  [ 2]  TLS certificate         →  CN=example.com (Let's Encrypt), 89d   ✓
  [ 3]  TLS handshake           →  TLSv1.3 / TLS_AES_256_GCM_SHA384 / h2 ✓
  [ 4]  HTTP fallback           →  HTTP 200 text/html (0.012s)           ✓
  [ 5]  HTTP→HTTPS redirect     →  HTTP 301 → https://example.com/       ✓
  [ 6]  Mismatched SNI          →  cert: CN=example.com                  ✓
  [ 7]  No SNI probe            →  cert: CN=example.com                  ✓
  [ 8]  Random path probe       →  GET /a3f9c2d1 → HTTP 200              ✓
  [ 9]  Raw TCP (non-TLS)       →  HTTP/1.1 400 Bad Request              ✓
  [10]  Response headers        →  Server: nginx, HSTS, X-Frame: DENY    ✓
  [11]  WebSocket leak          →  no WS upgrade on 10 paths             ✓
  [12]  gRPC leak               →  no gRPC response on 7 paths           ✓
  [13]  HTTP CONNECT            →  rejected (405) — normal               ✓
  [14]  Path consistency        →  all paths → 200 (consistent)          ✓

  ───────────────────────────────────────────────────────────────

  Masquerade Score: 96%  ███████████████████████░  EXCELLENT
  27/28 pts — passes DPI inspection
```

---

## Protocol support

| Protocol | Mode | Coverage |
|----------|------|----------|
| VLESS + Reality / XTLS Vision | TCP | Full |
| Trojan / Trojan-Go | TCP | Full |
| NaiveProxy | TCP | Full |
| V2Ray WebSocket + TLS | TCP | Full (incl. WS leak check) |
| V2Ray gRPC + TLS | TCP | Full (incl. gRPC leak check) |
| V2Ray HTTP/2 | TCP | Full |
| Hysteria2 | UDP | Full |
| TUIC v5 | UDP | Partial |
| V2Ray QUIC | UDP | Partial |
| Hysteria v1 | UDP | Partial |
| mKCP | — | Not supported |

---

## License

MIT
