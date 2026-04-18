# DPI Masquerade Inspector

Active TLS/TCP/UDP surface analysis tool. Probes a target host, classifies its network behaviour into a protocol-family hypothesis, and reports how convincingly it presents as an ordinary HTTPS web front.

> **Also available in Russian:** [README.ru.md](README.ru.md)

---

## What it does

`dpi_check.sh` performs heuristic analysis of the network surface and produces a structured verdict:

- TLS certificate inspection (CN, issuer, SAN coverage, key algorithm, expiry)
- ALPN negotiation check (actual TLS-negotiated ALPN vs HTTP response profile)
- SNI behaviour: matched, foreign (`test.invalid`), and no-SNI probes
- HTTP surface: random path, redirect, body size, header profile
- Transport exposure: WebSocket (21 paths) and gRPC (14 paths + 9 strict-mode paths)
- CONNECT-proxy acceptance check
- Optional H2 SETTINGS frame fingerprint via `nghttp` (MAX\_CONCURRENT\_STREAMS)
- QUIC/UDP mode via `quic_probe.py` (`aioquic`)
- VPN share-link parsing (`vless://`, `hysteria2://`, `trojan://`, `ss://`)
- Protocol-family inference with confidence scoring across **10 families**
- Hardening hints for self-hosted nginx/Caddy setups
- Machine-readable JSON output (`--json`)
- Russian or English interpretation layer (`--lang=ru`)

## What it does NOT do

- Does not guarantee detection of VPN or proxy
- Does not determine the exact protocol with 100% certainty
- All verdicts are heuristic estimates

---

## Installation

### Required dependencies

| Tool | Purpose |
|------|---------|
| `bash` | Shell runtime |
| `curl` | HTTP probing |
| `openssl` | TLS handshake and certificate extraction |
| `jq` | JSON assembly |
| `python3` ≥ 3.9 | Protocol inference (`protocol_infer.py`) |
| `nmap` | Port scan and service fingerprint |
| `nc` (netcat) | TCP fallback check |
| `dig` / `getent` | DNS resolution |

### Optional dependencies

| Tool | Purpose |
|------|---------|
| `nghttp` (`nghttp2-client`) | H2 SETTINGS frame inspection (MAX\_CONCURRENT\_STREAMS) |
| `aioquic` Python package | QUIC/UDP probing (`quic_probe.py`) |
| `cryptography` Python package | Certificate extraction in QUIC mode |

Install optional Python packages:

```bash
pip install aioquic cryptography
```

Install `nghttp2-client` on Debian/Ubuntu:

```bash
apt install nghttp2-client
```

### Clone and run

```bash
git clone <repo-url>
cd dpi-check
chmod +x dpi_check.sh validate.sh
bash dpi_check.sh example.com
```

---

## Usage

```
dpi_check.sh <target> [port] [options]
```

### Options

| Flag | Description |
|------|-------------|
| `-m, --mode tcp\|udp\|auto` | Protocol mode (default: auto-detect via TCP probe) |
| `-s, --sni DOMAIN` | Override SNI for all TLS probes |
| `-t, --timeout N` | Probe timeout in seconds (default: 5) |
| `--json` | Emit machine-readable JSON (includes enriched inference) |
| `--debug-infer` | Show inference internals and ranked scoring table |
| `--hardening-hints` | Show hardening hints in text output (on by default) |
| `--recommend-fixes` | Alias for `--hardening-hints` |
| `--lang=ru\|en` | Output language for interpretation layer (default: en) |
| `--no-asn` | Skip external ASN lookup (ipinfo.io) |
| `--no-color` | Plain output, no ANSI colours |
| `-h, --help` | Show help |

### Examples

```bash
# Basic TCP/TLS inspection
bash dpi_check.sh example.com

# Specify port and override SNI
bash dpi_check.sh example.com 443 --sni front.example.net

# Force UDP/QUIC mode
bash dpi_check.sh example.com 443 --mode udp

# Parse VPN share link directly
bash dpi_check.sh "vless://uuid@host:443?sni=front.com"
bash dpi_check.sh "hysteria2://pw@host:443?sni=front.com"

# JSON output for machine processing
bash dpi_check.sh example.com --json | jq .inference

# Russian output
bash dpi_check.sh example.com --lang=ru

# Debug inference scoring
bash dpi_check.sh example.com --debug-infer

# Skip ASN lookup (privacy)
bash dpi_check.sh example.com --no-asn
```

---

## Output fields

### Summary scores

| Field | Description |
|-------|-------------|
| **Reachability** | TCP/UDP port is open and TLS handshake succeeds |
| **Camouflage** | How closely the surface matches an ordinary HTTPS website |
| **Exposure** | How visible unusual or service-layer signals are |
| **Confidence** | Overall confidence in the verdict (penalised for IP targets without `--sni`, failed cert extraction, etc.) |

### Inference block

| Field | Description |
|-------|-------------|
| **TLS surface class** | Classified SNI/cert routing profile (see below) |
| **Cert routing profile** | Behaviour when probed with foreign SNI and no SNI |
| **Surface risk** | Integrated risk level: `low` / `medium` / `elevated` / `high` |
| **Protocol hypotheses** | Ranked list of likely protocol families with confidence scores |
| **Overall assessment** | Practical human-readable verdict |
| **Hardening hints** | Actionable suggestions for nginx/Caddy (if applicable) |

### TLS surface classes

| Class | Meaning |
|-------|---------|
| `strict_sni_front` | Server rejects or closes on foreign/no-SNI — tightest surface |
| `same_cert_broad_front` | Foreign/no-SNI accepted with the **same** certificate — broader surface |
| `default_cert_broad_front` | Foreign/no-SNI returns a **different** (default) certificate — strongest anomaly |

### Individual findings

| ID | Category | What it checks |
|----|----------|----------------|
| `port_scan` | reachability | TCP open via nmap or fallback |
| `tls_cert` | camouflage | Public CA, CN, expiry, key algorithm |
| `tls_version` | camouflage | TLSv1.3 / TLSv1.2 / older |
| `http_response` | camouflage | HTTP 200, redirect, body size (<512 B notice) |
| `http_headers` | camouflage | `Server`, `HSTS`, `Content-Type` profile |
| `alpn_profile` | camouflage | Negotiated ALPN (`h2`, `http/1.1`, none) |
| `cert_san` | camouflage | SAN coverage of the probed SNI (wildcard-aware) |
| `mismatched_sni` | exposure | Cert/behaviour on `test.invalid` foreign SNI |
| `no_sni` | exposure | Cert/behaviour when SNI is omitted |
| `random_path` | exposure | Response to random 32-char hex path |
| `connect_probe` | exposure | Whether HTTP CONNECT is accepted |
| `ws_transport` | exposure | WebSocket upgrade on 21 common paths |
| `grpc_transport` | exposure | gRPC on 14 paths; strict HTTP/2 on 9 paths |
| `h2_settings` | exposure | MAX\_CONCURRENT\_STREAMS via nghttp (optional) |

---

## Protocol families

The inference engine ranks the target against **10 protocol families**:

| Family | Description |
|--------|-------------|
| `ordinary_web_front` | Behaves like a normal public HTTPS website |
| `broad_tls_front` | Accepts many SNIs / no-SNI but otherwise web-like |
| `cdn_or_reverse_proxy_front` | Edge/CDN headers (`via`, `cf-ray`, `x-cache`, etc.) |
| `tls_camouflage_relay` | TLS front with tunnel behind; minimal exposure signals |
| `default_cert_tls_front` | Default-cert fallback on foreign SNI — common Nginx/Caddy misconfiguration or intentional catch-all |
| `exposed_v2ray_transport` | WS or gRPC transport visibly accessible on well-known paths |
| `http_tunneling_front` | HTTP CONNECT accepted — explicit tunneling proxy |
| `quic_relay` | QUIC handshake succeeds; likely QUIC-based relay (Hysteria2 etc.) |
| `direct_http_proxy` | CONNECT accepted on plaintext HTTP port |
| `no_clear_tunnel_evidence` | No strong indicators for any tunnel family; likely an ordinary site |

---

## Interpretation guide

| Verdict | Practical meaning |
|---------|-------------------|
| `Ordinary web front` | Surface is indistinguishable from a normal website |
| `Camouflage is broad but detectable` | Server accepts foreign SNI with same cert — scannable but weak |
| `Front behavior looks less typical` | Default-cert fallback on foreign SNI — detectable pattern |
| `Transport signals detectable` | WS or gRPC endpoints visible on common paths |
| `CONNECT proxy detected` | Server accepts HTTP CONNECT tunneling |

---

## JSON output format

```bash
bash dpi_check.sh example.com --json
```

Top-level fields:

```json
{
  "host": "example.com",
  "port": 443,
  "mode": "tcp",
  "ip": "93.184.216.34",
  "asn": "AS15133 ...",
  "sni": "example.com",
  "scores": {
    "reachability": {"pts": 4, "max": 4, "pct": 100},
    "camouflage":   {"pts": 8, "max": 10, "pct": 80},
    "exposure":     {"pts": 2, "max": 6, "pct": 33}
  },
  "findings": [...],
  "inference": {
    "tls_surface_class": "strict_sni_front",
    "cert_routing_profile": "strict",
    "surface_risk": "low",
    "hypotheses": [
      {"family": "ordinary_web_front", "confidence": 0.87, "rank": 1}
    ],
    "overall_assessment": "Ordinary web front",
    "hardening_hints": []
  }
}
```

---

## Confidence score

The confidence percentage reflects how reliable the verdict is likely to be:

- **High (≥ 85 %)** — full TCP mode with SNI and certificate extracted
- **Medium (60–84 %)** — IP target without `--sni`, or partial data
- **Low (< 60 %)** — QUIC mode without certificate, or IP-only target

---

## Related files

| File | Purpose |
|------|---------|
| `dpi_check.sh` | Main inspector script |
| `protocol_infer.py` | Scoring engine and text renderer |
| `quic_probe.py` | QUIC/UDP handshake probe |
| `lang.sh` | Localisation helper |
| `harden_nginx.sh` | Nginx TLS surface hardening helper |
| `validate.sh` | Self-test suite |

---

## Validation

```bash
bash validate.sh
```

Runs the built-in self-test suite. For Python unit tests:

```bash
python3 -m pytest tests/ -v
# or directly:
python3 -c "from tests.test_protocol_infer import *; test_ordinary_web(); test_exposed_transport(); test_default_cert()"
```

---

## License

MIT
