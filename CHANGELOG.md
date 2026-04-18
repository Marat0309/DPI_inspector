# Changelog

## v2.2.7

### Inference engine (`protocol_infer.py`)

- Removed global `LANG` variable; language is now passed explicitly through all functions (thread-safe)
- Extracted all scoring weights into a named `_W` dict — every confidence increment is documented and auditable
- Split monolithic `infer_payload()` into 10 focused scorer functions (one per protocol family)
- Removed dead `foreign_sni` finding alias — all probes now use `mismatched_sni`
- Added `cert_san_match` / `cert_san_mismatch` scoring signals across all 10 families
- Added `h2_settings_normal` / `h2_settings_unusual` scoring signals (optional, requires `nghttp`)
- `tls_camouflage_relay` and `default_cert_tls_front` now correctly boost on cert-SAN mismatch

### Probes (`dpi_check.sh`)

- Added `--no-asn` flag to skip external ASN lookup (ipinfo.io) for privacy
- Added `validate_host()` and `validate_sni()` input guards with regex validation
- Added port range check (1–65535)
- Fixed ALPN probe: uses actual TLS-negotiated ALPN as primary signal (not HTTP-guessed); 7 distinct result branches
- Changed foreign-SNI probe host from `google.com` to `test.invalid` (RFC 2606 — never legitimately hosted, no GeoIP filtering)
- Added `cert_san` finding: SAN extraction from cert text, wildcard-aware matching, CN-only fallback
- Added `probe_h2_settings()`: inspects MAX\_CONCURRENT\_STREAMS via `nghttp`; skipped silently when `nghttp` is absent
- Expanded CA whitelist: added `entrust`, `trustwave`, `godaddy`, `buypass`
- Added `root_size` body-size tracking: HTTP 200 with body < 512 bytes now reported as `notice`
- Expanded WebSocket path list: 10 → 21 paths (added `/wss`, `/socket`, `/sock`, `/xray`, `/trojan`, `/proxy`, `/tunnel`, `/connect`, `/live`, `/pipe`, `/net`, `/data`)
- Expanded gRPC path list: 7 → 14 paths; strict gRPC paths: 4 → 9 paths

### QUIC probe (`quic_probe.py`)

- Added `from __future__ import annotations` for Python 3.9 compatibility
- Fixed 3 bare `except Exception: pass` blocks — now log at `DEBUG` level
- Changed mismatched-SNI probe host from `google.com` to `test.invalid` (RFC 2606)
- Added SNI-verdict inversion comment explaining why `warn` maps to `fail` for SNI probes

### Documentation

- Rewrote `README.md` (English) — covers all flags, findings, families, JSON format, confidence scoring
- Added `README.ru.md` — full Russian translation
- Expanded `CHANGELOG.md`
