#!/usr/bin/env python3
from __future__ import annotations
import argparse
import json
import sys
from typing import Any


# ── Scoring weights ───────────────────────────────────────────
# All fractional confidence increments used by each protocol-family scorer.
# Positive values support the hypothesis; negative values argue against it.
# Keeping them here makes tuning and auditing straightforward.
_W: dict[str, dict[str, float]] = {
    "ordinary_web_front": {
        "web_ok":             0.24,   # HTTP 200 fallback page
        "public_cert":        0.16,   # Public CA certificate
        "cert_non_public":   -0.08,   # Non-public / unusual cert profile
        "modern_tls":         0.10,   # TLSv1.3 stack
        "usable_tls":         0.06,   # TLSv1.2 stack
        "headers_strong":     0.12,   # Full header profile (Server + HSTS)
        "headers_some":       0.06,   # Partial header profile
        "alpn_ok":            0.06,   # h2+h1 ALPN web profile
        "alpn_weak":          0.02,   # Partial ALPN web profile
        "strong_web":         0.12,   # Normal random-path behavior
        "connect_rejected":   0.10,   # CONNECT rejected like a plain web server
        "no_ws":              0.07,   # No WS transport exposure
        "no_grpc":            0.07,   # No gRPC transport exposure
        "combined_normal":    0.24,   # Bonus: path + CONNECT + transport all normal
        "same_cert_broad":   -0.06,   # Same-cert broadness widens scan surface
        "diff_cert_broad":   -0.22,   # Different/default cert on foreign/no-SNI
        "strict_sni":         0.05,   # Strict SNI common for ordinary web fronts
        "foreign_diff_cert": -0.10,   # Foreign SNI returns different cert
        "nosni_diff_cert":   -0.10,   # no-SNI returns different cert
        "both_broad_diff":   -0.12,   # Both foreign+no-SNI broad with different cert
        "ws_exposed":        -0.18,   # WS transport visible
        "grpc_exposed":      -0.22,   # gRPC transport visible
        "grpc_strict":       -0.30,   # Strict HTTP/2 gRPC semantics — strong tunnel signal
        "connect_accepted":  -0.22,   # CONNECT accepted like a proxy
        "random_path_risk":  -0.10,   # Selective/unusual random-path behavior
        # cert_san signals (from SAN-match probe)
        "cert_san_match":     0.10,   # Cert explicitly covers the probed SNI
        "cert_san_mismatch": -0.14,   # Cert does not cover the probed SNI
        # h2_settings signals (optional — only present if nghttp is installed)
        "h2_settings_normal": 0.04,   # Standard web-server H2 settings profile
        "h2_settings_unusual":-0.06,  # Unusual MAX_CONCURRENT_STREAMS etc.
    },
    "broad_tls_front": {
        "public_cert":        0.12,
        "usable_tls":         0.06,
        "strong_web":         0.04,
        "same_cert_broad":    0.10,
        "diff_cert_broad":    0.22,
        "strict_sni":        -0.10,
        "cert_non_public":    0.04,
        "connect_rejected":   0.03,
        "no_transport":       0.03,
        "very_normal_web":   -0.08,
        "no_indicators":     -0.08,
    },
    "cdn_or_reverse_proxy_front": {
        "edge_like":          0.24,
        "edge_banner":        0.16,
        "strict_sni":         0.12,
        "headers_some":       0.08,
        "redirect_ok":        0.06,
        "transport_exposed": -0.12,
    },
    "tls_camouflage_relay": {
        "public_cert":        0.10,
        "modern_tls":         0.08,
        "web_ok":             0.06,
        "same_cert_broad":    0.08,
        "diff_cert_broad":    0.14,
        "cert_non_public":    0.08,
        "no_ws_grpc":         0.05,
        "strong_web":        -0.06,
        "headers_strong":    -0.04,
        "connect_rejected":  -0.04,
        "no_indicators":     -0.06,
        "cert_san_match":    -0.06,   # SNI-covered cert matches legitimate deployment, not camouflage
        "cert_san_mismatch":  0.08,   # SNI mismatch is a mild signal toward shared/default cert behaviour
        "h2_settings_unusual":0.04,   # Unusual H2 settings are a mild proxy signal
    },
    "default_cert_tls_front": {
        "foreign_diff":       0.30,
        "nosni_diff":         0.24,
        "diff_cert_broad":    0.18,
        "headers_weak":       0.06,
        "grpc_hints_x2":      0.06,
        "grpc_hint_combo":    0.03,
        "redirect_weak":      0.04,
        "clean_web":         -0.08,
        "same_cert_soft":    -0.10,
        "cert_san_mismatch":  0.10,   # Cert not covering SNI — consistent with default/shared cert routing
    },
    "exposed_v2ray_transport": {
        "ws_exposed":         0.62,
        "grpc_exposed":       0.58,
        "grpc_hint":          0.14,
        "grpc_strict":        0.46,
        "grpc_strict_hint":   0.16,
        "h2_grpc":            0.10,
        "connect_accepted":   0.10,
    },
    "http_tunneling_front": {
        "h2":                 0.14,
        "web_public_cert":    0.12,
        "connect_accepted":   0.34,
        "hidden_possible":    0.04,
        "clean_fallback":     0.04,
        "transport_exposed": -0.08,
        "no_indicators":     -0.06,
    },
    "quic_relay": {
        "quic_ok":            0.34,
        "udp_junk_silent":    0.14,
        "public_cert":        0.08,
        "foreign_open":       0.08,
        "nosni_open":         0.06,
        "h3":                 0.06,
    },
    "direct_http_proxy": {
        "connect_accepted":   0.70,
        "h2_connect":         0.10,
    },
    "no_clear_tunnel_evidence": {
        "normal_web":         0.34,
        "public_cert":        0.08,
        "connect_rejected":   0.06,
        "strong_web":         0.06,
        "headers_some":       0.06,
        "foreign_open":      -0.05,
        "nosni_open":        -0.04,
        "diff_cert_broad":   -0.08,
        "cert_san_match":     0.08,   # Cert explicitly covers SNI — consistent with a genuine web deployment
        "cert_san_mismatch": -0.10,   # Cert mismatch weakens "ordinary site" reading
    },
}


# ── Translation helpers ───────────────────────────────────────

def tr(en: str, ru: str, lang: str = "en") -> str:
    return ru if lang == "ru" else en


def _translate_reason(text: str, lang: str = "en") -> str:
    if lang != "ru":
        return text
    mapping = {
        "ordinary HTTPS fallback page": "обычная HTTPS фолбэк-страница",
        "public CA certificate": "сертификат от публичного УЦ",
        "non-public or unusual certificate profile": "непубличный или нетипичный профиль сертификата",
        "modern TLS stack": "современный стек TLS",
        "usable TLS stack": "рабочий стек TLS",
        "strong normal header profile": "сильный стандартный профиль заголовков",
        "some normal header profile": "частично стандартный профиль заголовков",
        "ALPN profile looks web-like (h2+h1)": "профиль ALPN выглядит как у веб-фронта (h2+h1)",
        "partial ALPN web profile": "частично веб-профиль ALPN",
        "plausible behavior on random paths": "правдоподобное поведение на случайных путях",
        "CONNECT rejected like a normal web server": "CONNECT отклоняется как на обычном веб-сервере",
        "no obvious WS transport exposure": "нет явной экспозиции WS-транспорта",
        "no obvious gRPC transport exposure": "нет явной экспозиции gRPC-транспорта",
        "combined normal-web behavior across path, CONNECT, and transport checks": "совокупно обычное веб-поведение по путям, CONNECT и транспортным проверкам",
        "same-cert foreign/no-SNI broadness still widens scan surface": "широкий прием foreign/no-SNI с тем же сертификатом все равно расширяет поверхность сканирования",
        "different/default cert on foreign/no-SNI is a stronger anomaly": "другой/дефолтный сертификат на foreign/no-SNI — более сильная аномалия",
        "strict SNI behavior is common for ordinary web fronting": "строгое поведение SNI типично для обычного веб-фронта",
        "foreign SNI receives a different/default certificate": "на foreign SNI возвращается другой/дефолтный сертификат",
        "no-SNI receives a different/default certificate": "на no-SNI возвращается другой/дефолтный сертификат",
        "combined broad-SNI behavior with alternate cert substantially increases surface": "комбинация широкого SNI и альтернативного сертификата заметно увеличивает поверхность",
        "WS transport appears exposed": "WS-транспорт выглядит открытым",
        "gRPC transport appears exposed": "gRPC-транспорт выглядит открытым",
        "strict HTTP/2 gRPC semantics exposed": "обнаружена строгая gRPC-семантика HTTP/2",
        "CONNECT accepted like a proxy": "CONNECT принимается как у прокси",
        "random-path behavior looks selective/unusual": "поведение на случайных путях выглядит избирательным/нетипичным",
        "broad SNI acceptance weakens 'ordinary front' confidence": "широкое принятие SNI снижает уверенность в версии «обычный фронт»",
        "strict SNI handling narrows generic TLS scan surface": "строгая обработка SNI сужает общую TLS-поверхность сканирования",
        "broad SNI/no-SNI accepted with same certificate": "широкий прием SNI/no-SNI с тем же сертификатом",
        "broad SNI/no-SNI accepted with different/default certificate": "широкий прием SNI/no-SNI с другим/default-сертификатом",
        "answers to foreign SNI": "отвечает на foreign SNI",
        "answers without SNI": "отвечает без SNI",
        "WS transport endpoint exposed": "WS транспортный endpoint открыт",
        "strong gRPC transport semantics exposed": "обнаружена выраженная gRPC транспортная семантика",
        "weaker HTTPS header profile": "более слабый профиль HTTPS-заголовков",
        "HTTP redirect behavior not ideal": "поведение HTTP-редиректа неидеально",
        "older TLS profile": "устаревший профиль TLS",
        "repeated weak gRPC hints": "повторяющиеся слабые признаки gRPC",
        "weak gRPC hint combined with other anomalies": "слабый признак gRPC в сочетании с другими аномалиями",
        "combined foreign-SNI + no-SNI acceptance widens surface": "комбинация foreign-SNI + no-SNI расширяет поверхность",
        "broad SNI behavior appears alongside transport or web-profile anomalies": "широкое SNI-поведение наблюдается вместе с транспортными или веб-профильными аномалиями",
    }
    return mapping.get(text, text)


# ── Low-level finding accessors ───────────────────────────────

def _sev(findings: dict[str, dict[str, Any]], *ids: str) -> str:
    for fid in ids:
        if fid in findings:
            return findings[fid].get("severity", "")
    return ""


def _obs(findings: dict[str, dict[str, Any]], *ids: str) -> str:
    for fid in ids:
        if fid in findings:
            return findings[fid].get("observed", "")
    return ""


def _field(findings: dict[str, dict[str, Any]], field: str, *ids: str) -> Any:
    for fid in ids:
        if fid in findings and field in findings[fid]:
            return findings[fid].get(field)
    return None


# ── TLS surface classification ────────────────────────────────

def _tls_surface_class(findings: dict[str, dict[str, Any]]) -> tuple[str, list[str]]:
    foreign_open = _sev(findings, "mismatched_sni") == "risk"
    nosni_open = _sev(findings, "no_sni") == "risk"
    if not foreign_open and not nosni_open:
        return "strict_sni_front", ["foreign/no-SNI probes do not receive a certificate"]

    relations: list[str] = []
    if foreign_open:
        relations.append(str(_field(findings, "returned_relation", "mismatched_sni") or "unknown"))
    if nosni_open:
        relations.append(str(_field(findings, "returned_relation", "no_sni") or "unknown"))

    if relations and all(r == "same-as-main" for r in relations):
        return "same_cert_broad_front", ["foreign/no-SNI return the same certificate as main SNI"]
    return "default_cert_broad_front", ["foreign/no-SNI return a different/default/unknown certificate"]


def _cert_routing_profile(tls_surface: str) -> str:
    if tls_surface == "strict_sni_front":
        return "strict_sni"
    if tls_surface == "same_cert_broad_front":
        return "same_cert_broad"
    return "default_cert_broad"


# ── Score accumulator ─────────────────────────────────────────

def _add(
    bucket: dict[str, dict[str, Any]],
    key: str,
    pts: float,
    support: str | None = None,
    against: str | None = None,
    lang: str = "en",
) -> None:
    bucket.setdefault(key, {"score": 0.0, "supports": [], "against": []})
    bucket[key]["score"] += pts
    if support:
        bucket[key]["supports"].append(_translate_reason(support, lang))
    if against:
        bucket[key]["against"].append(_translate_reason(against, lang))


def _reason_factor(conf: int, supports: int, against: int) -> float:
    factor = 0.58 + min(0.20, supports * 0.04) + min(0.12, conf / 800)
    factor -= min(0.10, against * 0.02)
    return max(0.38, factor)


# ── Surface risk ──────────────────────────────────────────────

def _surface_risk(findings: dict[str, dict[str, Any]], lang: str = "en") -> dict[str, Any]:
    score = 0
    reasons: list[str] = []
    tls_surface, _ = _tls_surface_class(findings)
    foreign_open = _sev(findings, "mismatched_sni") == "risk"
    nosni_open = _sev(findings, "no_sni") == "risk"
    if tls_surface == "strict_sni_front":
        score = max(0, score - 1)
        reasons.append("strict SNI handling narrows generic TLS scan surface")
    elif tls_surface == "same_cert_broad_front":
        score += 2
        reasons.append("broad SNI/no-SNI accepted with same certificate")
    elif tls_surface == "default_cert_broad_front":
        score += 4
        reasons.append("broad SNI/no-SNI accepted with different/default certificate")
    elif foreign_open:
        score += 1
        reasons.append("answers to foreign SNI")
    elif nosni_open:
        score += 1
        reasons.append("answers without SNI")
    if _sev(findings, "ws_leak") == "risk":
        score += 3
        reasons.append("WS transport endpoint exposed")
    weak_grpc_count = 0
    if _sev(findings, "grpc_leak") == "risk":
        score += 3
        reasons.append("strong gRPC transport semantics exposed")
    elif _sev(findings, "grpc_leak") == "notice":
        weak_grpc_count += 1
    if _sev(findings, "grpc_strict_probe") == "risk":
        score += 4
        reasons.append("strict HTTP/2 gRPC semantics exposed")
    elif _sev(findings, "grpc_strict_probe") == "notice":
        weak_grpc_count += 1
    if _sev(findings, "http_connect") == "risk":
        score += 3
        reasons.append("CONNECT accepted like a proxy")
    if _sev(findings, "headers") == "notice":
        score += 1
        reasons.append("weaker HTTPS header profile")
    if _sev(findings, "http_redirect") == "notice":
        score += 1
        reasons.append("HTTP redirect behavior not ideal")
    if _sev(findings, "tls_profile") == "notice":
        score += 1
        reasons.append("older TLS profile")
    suspicious_combo = (
        _sev(findings, "http_redirect") == "notice"
        or _sev(findings, "headers") == "notice"
        or _sev(findings, "ws_leak") == "risk"
        or _sev(findings, "http_connect") == "risk"
    )
    if weak_grpc_count >= 2:
        score += 2
        reasons.append("repeated weak gRPC hints")
    elif weak_grpc_count == 1 and suspicious_combo:
        score += 1
        reasons.append("weak gRPC hint combined with other anomalies")
    if foreign_open and nosni_open and tls_surface != "strict_sni_front":
        score += 1
        reasons.append("combined foreign-SNI + no-SNI acceptance widens surface")
    suspicious_combo = suspicious_combo or weak_grpc_count > 0 or _sev(findings, "grpc_leak") == "risk" or _sev(findings, "grpc_strict_probe") == "risk"
    if foreign_open and nosni_open and suspicious_combo and tls_surface != "strict_sni_front":
        score += 2
        reasons.append("broad SNI behavior appears alongside transport or web-profile anomalies")
    label = "low"
    if score >= 6:
        label = "high"
    elif score >= 3:
        label = "medium"
    return {"score": score, "label": label, "reasons": [_translate_reason(x, lang) for x in reasons[:5]]}


# ── Hardening hints ───────────────────────────────────────────

def _hardening_hints(
    payload: dict[str, Any],
    findings: dict[str, dict[str, Any]],
    lang: str = "en",
) -> list[str]:
    hints: list[str] = []
    target = payload.get("target", {})
    host = str(target.get("host", ""))
    is_domain = host and not host.replace(".", "").isdigit() and ":" not in host
    recommend_fixes = bool(target.get("recommend_fixes", False))
    banner = _obs(findings, "headers").lower()
    redirect_obs = _obs(findings, "http_redirect").lower()
    edge_like = (
        "cloudflare" in banner
        or "fastly" in banner
        or "akamai" in banner
        or "cdn" in banner
        or "cache" in banner
        or "http 301" in redirect_obs
        or "http 302" in redirect_obs
    )

    if _sev(findings, "http_redirect") == "notice":
        hints.append(tr("Port 80 does not cleanly redirect to HTTPS; add a 301 redirect.", "Порт 80 не делает чистый редирект на HTTPS; добавьте 301 редирект.", lang))
    if _sev(findings, "headers") == "notice":
        hints.append(tr("Add HSTS on the HTTPS server block to strengthen the web profile.", "Добавьте HSTS в HTTPS server block, чтобы усилить веб-профиль.", lang))
    tls_surface, _ = _tls_surface_class(findings)
    if tls_surface == "same_cert_broad_front":
        hints.append(tr("Same cert is served on foreign/no-SNI; tighten unknown-SNI/default vhost handling to reduce broad scan surface.", "На foreign/no-SNI отдается тот же сертификат; ужесточите обработку unknown-SNI/default vhost, чтобы сузить поверхность.", lang))
    elif tls_surface == "default_cert_broad_front":
        hints.append(tr("Foreign/no-SNI returns another cert; review default certificate and default-server routing first.", "На foreign/no-SNI возвращается другой сертификат; сначала проверьте default-сертификат и маршрутизацию default-server.", lang))
    elif _sev(findings, "mismatched_sni") == "risk" or _sev(findings, "no_sni") == "risk":
        hints.append(tr("Tighten the default server / unknown-SNI handling, ideally dropping unmatched SNI.", "Ужесточите обработку default server / unknown-SNI, в идеале отбрасывайте несовпавший SNI.", lang))
    if is_domain and hints and (recommend_fixes or ("nginx" in banner and not edge_like)):
        hints.append(tr(f"For nginx targets, review harden_nginx.sh {host} --dry-run before applying changes.", f"Для nginx-целей проверьте harden_nginx.sh {host} --dry-run перед применением изменений.", lang))
    return hints[:4]


# ── Main inference ────────────────────────────────────────────

def infer_payload(payload: dict[str, Any]) -> dict[str, Any]:
    lang = str(payload.get("lang", "en"))
    findings_list = payload.get("findings", [])
    findings = {f.get("id", f.get("title", str(i))): f for i, f in enumerate(findings_list)}
    mode = payload.get("target", {}).get("mode", "")
    conf = int(payload.get("confidence", {}).get("score", 100))
    scores: dict[str, dict[str, Any]] = {}

    # ── Local helpers that capture lang ──────────────────────
    def add(bucket: dict, key: str, pts: float, support: str | None = None, against: str | None = None) -> None:
        _add(bucket, key, pts, support, against, lang)

    def t(en: str, ru: str) -> str:
        return tr(en, ru, lang)

    # ── Extract probe state ───────────────────────────────────
    modern_tls = "TLSv1.3" in _obs(findings, "tls_handshake", "quic_handshake")
    usable_tls = modern_tls or "TLSv1.2" in _obs(findings, "tls_handshake", "quic_handshake")
    h2 = "/ h2" in _obs(findings, "tls_handshake")
    h3 = mode == "udp" or "HTTP/3" in _obs(findings, "http3")
    public_cert = _sev(findings, "tls_cert", "quic_cert") == "ok"
    cert_non_public = _sev(findings, "tls_cert", "quic_cert") == "notice"
    web_ok = _sev(findings, "http_fallback") in {"ok", "notice"}
    strong_web = _sev(findings, "http_fallback") == "ok" and _sev(findings, "random_path") == "ok"
    random_path_risk = _sev(findings, "random_path") == "risk"
    headers_strong = _sev(findings, "headers") == "ok"
    headers_some = _sev(findings, "headers") in {"ok", "notice"}
    alpn_ok = _sev(findings, "alpn_profile") == "ok"
    alpn_weak = _sev(findings, "alpn_profile") == "notice"
    ws_exposed = _sev(findings, "ws_leak") == "risk"
    grpc_exposed = _sev(findings, "grpc_leak") == "risk"
    grpc_hint = _sev(findings, "grpc_leak") == "notice"
    grpc_strict_exposed = _sev(findings, "grpc_strict_probe") == "risk"
    grpc_strict_hint = _sev(findings, "grpc_strict_probe") == "notice"
    weak_grpc_hints = int(grpc_hint) + int(grpc_strict_hint)
    connect_accepted = _sev(findings, "http_connect") == "risk" and "accepted" in _obs(findings, "http_connect").lower()
    connect_rejected = _sev(findings, "http_connect") == "ok"
    foreign_open = _sev(findings, "mismatched_sni") == "risk"
    nosni_open = _sev(findings, "no_sni") == "risk"
    tls_surface, tls_surface_reasons = _tls_surface_class(findings)
    quic_ok = _sev(findings, "quic_handshake") == "ok"
    udp_junk_silent = _sev(findings, "raw_udp") == "ok"

    # cert_san: present only for domain targets when openssl SAN extraction succeeded
    cert_san_match = _sev(findings, "cert_san") == "ok"
    cert_san_mismatch = _sev(findings, "cert_san") == "notice"

    # h2_settings: present only when nghttp is installed and probe ran
    h2_settings_normal = _sev(findings, "h2_settings") == "ok"
    h2_settings_unusual = _sev(findings, "h2_settings") == "notice"

    strong_negative = sum([
        connect_rejected,
        not ws_exposed,
        not grpc_exposed and not grpc_strict_exposed,
        strong_web,
        headers_some,
        public_cert,
    ])

    # ── Per-family scoring functions ──────────────────────────

    def _score_ordinary_web_front() -> None:
        W = _W["ordinary_web_front"]
        if web_ok:
            add(scores, "ordinary_web_front", W["web_ok"], "ordinary HTTPS fallback page")
        if public_cert:
            add(scores, "ordinary_web_front", W["public_cert"], "public CA certificate")
        elif cert_non_public:
            add(scores, "ordinary_web_front", W["cert_non_public"], against="non-public or unusual certificate profile")
        if modern_tls:
            add(scores, "ordinary_web_front", W["modern_tls"], "modern TLS stack")
        elif usable_tls:
            add(scores, "ordinary_web_front", W["usable_tls"], "usable TLS stack")
        if headers_strong:
            add(scores, "ordinary_web_front", W["headers_strong"], "strong normal header profile")
        elif headers_some:
            add(scores, "ordinary_web_front", W["headers_some"], "some normal header profile")
        if alpn_ok:
            add(scores, "ordinary_web_front", W["alpn_ok"], "ALPN profile looks web-like (h2+h1)")
        elif alpn_weak:
            add(scores, "ordinary_web_front", W["alpn_weak"], "partial ALPN web profile")
        if strong_web:
            add(scores, "ordinary_web_front", W["strong_web"], "plausible behavior on random paths")
        if connect_rejected:
            add(scores, "ordinary_web_front", W["connect_rejected"], "CONNECT rejected like a normal web server")
        if not ws_exposed:
            add(scores, "ordinary_web_front", W["no_ws"], "no obvious WS transport exposure")
        if not grpc_exposed and not grpc_strict_exposed:
            add(scores, "ordinary_web_front", W["no_grpc"], "no obvious gRPC transport exposure")
        if strong_web and connect_rejected and not ws_exposed and not grpc_exposed and public_cert:
            add(scores, "ordinary_web_front", W["combined_normal"], "combined normal-web behavior across path, CONNECT, and transport checks")
        if tls_surface == "same_cert_broad_front":
            add(scores, "ordinary_web_front", W["same_cert_broad"], against="same-cert foreign/no-SNI broadness still widens scan surface")
        elif tls_surface == "default_cert_broad_front":
            add(scores, "ordinary_web_front", W["diff_cert_broad"], against="different/default cert on foreign/no-SNI is a stronger anomaly")
        elif tls_surface == "strict_sni_front":
            add(scores, "ordinary_web_front", W["strict_sni"], "strict SNI behavior is common for ordinary web fronting")
        if foreign_open and _field(findings, "returned_relation", "mismatched_sni") == "different-cert":
            add(scores, "ordinary_web_front", W["foreign_diff_cert"], against="foreign SNI receives a different/default certificate")
        if nosni_open and _field(findings, "returned_relation", "no_sni") == "different-cert":
            add(scores, "ordinary_web_front", W["nosni_diff_cert"], against="no-SNI receives a different/default certificate")
        if foreign_open and nosni_open and tls_surface == "default_cert_broad_front":
            add(scores, "ordinary_web_front", W["both_broad_diff"], against="combined broad-SNI behavior with alternate cert substantially increases surface")
        if ws_exposed:
            add(scores, "ordinary_web_front", W["ws_exposed"], against="WS transport appears exposed")
        if grpc_exposed:
            add(scores, "ordinary_web_front", W["grpc_exposed"], against="gRPC transport appears exposed")
        if grpc_strict_exposed:
            add(scores, "ordinary_web_front", W["grpc_strict"], against="strict HTTP/2 gRPC semantics exposed")
        if connect_accepted:
            add(scores, "ordinary_web_front", W["connect_accepted"], against="CONNECT accepted like a proxy")
        if random_path_risk:
            add(scores, "ordinary_web_front", W["random_path_risk"], against="random-path behavior looks selective/unusual")
        if cert_san_match:
            add(scores, "ordinary_web_front", W["cert_san_match"], "certificate explicitly covers the probed SNI")
        if cert_san_mismatch:
            add(scores, "ordinary_web_front", W["cert_san_mismatch"], against="certificate does not cover the probed SNI")
        if h2_settings_normal:
            add(scores, "ordinary_web_front", W["h2_settings_normal"], "standard HTTP/2 settings profile")
        if h2_settings_unusual:
            add(scores, "ordinary_web_front", W["h2_settings_unusual"], against="unusual HTTP/2 settings — atypical for standard web servers")

    def _score_broad_tls_front() -> None:
        if not (mode == "tcp" and web_ok and public_cert):
            return
        W = _W["broad_tls_front"]
        add(scores, "broad_tls_front", W["public_cert"], "credible public certificate")
        if usable_tls:
            add(scores, "broad_tls_front", W["usable_tls"], "usable TLS profile")
        if strong_web:
            add(scores, "broad_tls_front", W["strong_web"], "web-like fallback front")
        if tls_surface == "same_cert_broad_front":
            add(scores, "broad_tls_front", W["same_cert_broad"], "accepts foreign/no-SNI while keeping same cert")
        elif tls_surface == "default_cert_broad_front":
            add(scores, "broad_tls_front", W["diff_cert_broad"], "accepts foreign/no-SNI and serves alternate/default cert")
        elif tls_surface == "strict_sni_front":
            add(scores, "broad_tls_front", W["strict_sni"], against="strict SNI behavior is opposite of broad TLS fronting")
        if cert_non_public:
            add(scores, "broad_tls_front", W["cert_non_public"], "certificate profile is less typical for mainstream web")
        if connect_rejected:
            add(scores, "broad_tls_front", W["connect_rejected"], "still behaves like a normal web server on CONNECT")
        if not ws_exposed and not grpc_exposed and not grpc_strict_exposed:
            add(scores, "broad_tls_front", W["no_transport"], "no obvious transport endpoints exposed")
        if strong_web and headers_strong:
            add(scores, "broad_tls_front", W["very_normal_web"], against="very normal web profile overall")
        if strong_negative >= 5:
            add(scores, "broad_tls_front", W["no_indicators"], against="lack of direct tunnel indicators")

    def _score_cdn_front() -> None:
        edge_banner = _obs(findings, "headers").lower()
        redirect_ok = _sev(findings, "http_redirect") == "ok" and _obs(findings, "http_redirect").startswith("HTTP 30")
        strict_sni = tls_surface == "strict_sni_front"
        edge_like = any(x in edge_banner for x in ("cloudflare", "fastly", "akamai", "cdn", "edge"))
        if not (mode == "tcp" and web_ok and (edge_like or (strict_sni and headers_some and redirect_ok))):
            return
        W = _W["cdn_or_reverse_proxy_front"]
        add(scores, "cdn_or_reverse_proxy_front", W["edge_like"], "edge-like front behavior")
        if edge_like:
            add(scores, "cdn_or_reverse_proxy_front", W["edge_banner"], "server/header banner looks CDN or reverse-proxy-like")
        if strict_sni:
            add(scores, "cdn_or_reverse_proxy_front", W["strict_sni"], "strict foreign-SNI/no-SNI handling")
        if headers_some:
            add(scores, "cdn_or_reverse_proxy_front", W["headers_some"], "usable edge/web header profile")
        if redirect_ok:
            add(scores, "cdn_or_reverse_proxy_front", W["redirect_ok"], "redirect-heavy edge-like entry behavior")
        if ws_exposed or grpc_exposed or grpc_strict_exposed or connect_accepted:
            add(scores, "cdn_or_reverse_proxy_front", W["transport_exposed"], against="transport/proxy exposure is less typical for a plain CDN edge")

    def _score_tls_camouflage_relay() -> None:
        if mode != "tcp":
            return
        W = _W["tls_camouflage_relay"]
        if public_cert:
            add(scores, "tls_camouflage_relay", W["public_cert"], "credible public certificate")
        if modern_tls:
            add(scores, "tls_camouflage_relay", W["modern_tls"], "modern TLS profile")
        if web_ok:
            add(scores, "tls_camouflage_relay", W["web_ok"], "web-like fallback front")
        if tls_surface == "same_cert_broad_front":
            add(scores, "tls_camouflage_relay", W["same_cert_broad"], "same-cert foreign/no-SNI acceptance")
        elif tls_surface == "default_cert_broad_front":
            add(scores, "tls_camouflage_relay", W["diff_cert_broad"], "alternate/default cert under foreign/no-SNI")
        if cert_non_public:
            add(scores, "tls_camouflage_relay", W["cert_non_public"], "non-public or unusual certificate profile")
        if not ws_exposed and not grpc_exposed:
            add(scores, "tls_camouflage_relay", W["no_ws_grpc"], "no exposed WS/gRPC transport paths")
        if strong_web:
            add(scores, "tls_camouflage_relay", W["strong_web"], against="very ordinary web-path behavior")
        if headers_strong:
            add(scores, "tls_camouflage_relay", W["headers_strong"], against="strongly normal HTTPS header profile")
        if connect_rejected:
            add(scores, "tls_camouflage_relay", W["connect_rejected"], against="CONNECT rejected like a plain web server")
        if strong_negative >= 5:
            add(scores, "tls_camouflage_relay", W["no_indicators"], against="multiple signs of an ordinary site")
        if cert_san_match:
            add(scores, "tls_camouflage_relay", W["cert_san_match"], against="certificate explicitly covers the probed SNI — consistent with genuine deployment")
        if cert_san_mismatch:
            add(scores, "tls_camouflage_relay", W["cert_san_mismatch"], "certificate does not cover the probed SNI — possible shared/default cert")
        if h2_settings_unusual:
            add(scores, "tls_camouflage_relay", W["h2_settings_unusual"], "unusual HTTP/2 settings profile")

    def _score_default_cert_tls_front() -> None:
        if not (mode == "tcp" and web_ok and (foreign_open or nosni_open)):
            return
        W = _W["default_cert_tls_front"]
        foreign_diff = foreign_open and _field(findings, "returned_relation", "mismatched_sni") == "different-cert"
        nosni_diff = nosni_open and _field(findings, "returned_relation", "no_sni") == "different-cert"
        if foreign_diff:
            add(scores, "default_cert_tls_front", W["foreign_diff"], "foreign SNI is accepted with a different/default certificate")
        if nosni_diff:
            add(scores, "default_cert_tls_front", W["nosni_diff"], "no-SNI is accepted with a different/default certificate")
        if tls_surface == "default_cert_broad_front":
            add(scores, "default_cert_tls_front", W["diff_cert_broad"], "default-cert broad routing profile")
        if _sev(findings, "headers") == "notice":
            add(scores, "default_cert_tls_front", W["headers_weak"], "weaker header profile")
        if weak_grpc_hints >= 2:
            add(scores, "default_cert_tls_front", W["grpc_hints_x2"], "repeated weak gRPC hints")
        elif weak_grpc_hints == 1 and (_sev(findings, "headers") == "notice" or _sev(findings, "http_redirect") == "notice"):
            add(scores, "default_cert_tls_front", W["grpc_hint_combo"], "weak gRPC hint appears with other anomalies")
        if _sev(findings, "http_redirect") == "notice":
            add(scores, "default_cert_tls_front", W["redirect_weak"], "HTTP redirect profile is weaker than expected")
        if strong_web and headers_strong:
            add(scores, "default_cert_tls_front", W["clean_web"], against="clean web profile lowers default-cert front suspicion")
        if tls_surface == "same_cert_broad_front":
            add(scores, "default_cert_tls_front", W["same_cert_soft"], against="same-cert broadness is softer than default-cert routing")
        if cert_san_mismatch:
            add(scores, "default_cert_tls_front", W["cert_san_mismatch"], "certificate does not cover the probed SNI — consistent with default/shared cert routing")

    def _score_exposed_v2ray_transport() -> None:
        W = _W["exposed_v2ray_transport"]
        if ws_exposed:
            add(scores, "exposed_v2ray_transport", W["ws_exposed"], "WS upgrade succeeds on common paths")
        if grpc_exposed:
            add(scores, "exposed_v2ray_transport", W["grpc_exposed"], "strong gRPC semantics surfaced")
        elif grpc_hint:
            add(scores, "exposed_v2ray_transport", W["grpc_hint"], "weak gRPC hint surfaced")
        if grpc_strict_exposed:
            add(scores, "exposed_v2ray_transport", W["grpc_strict"], "strict HTTP/2 gRPC semantics surfaced")
        elif grpc_strict_hint:
            add(scores, "exposed_v2ray_transport", W["grpc_strict_hint"], "partial strict gRPC hint")
        if h2 and grpc_exposed:
            add(scores, "exposed_v2ray_transport", W["h2_grpc"], "HTTP/2 + gRPC combination")
        if connect_accepted:
            add(scores, "exposed_v2ray_transport", W["connect_accepted"], "proxy-like CONNECT behavior")

    def _score_http_tunneling_front() -> None:
        if mode != "tcp":
            return
        W = _W["http_tunneling_front"]
        if h2:
            add(scores, "http_tunneling_front", W["h2"], "ALPN negotiated h2")
        if web_ok and public_cert:
            add(scores, "http_tunneling_front", W["web_public_cert"], "credible browser-like HTTPS front")
        if connect_accepted:
            add(scores, "http_tunneling_front", W["connect_accepted"], "CONNECT accepted")
        elif connect_rejected and h2 and web_ok:
            add(scores, "http_tunneling_front", W["hidden_possible"], "hidden tunnel front is still possible")
        if _sev(findings, "http_fallback") == "ok":
            add(scores, "http_tunneling_front", W["clean_fallback"], "clean fallback site")
        if ws_exposed or grpc_exposed:
            add(scores, "http_tunneling_front", W["transport_exposed"], against="more like an exposed transport than a hidden tunnel front")
        if strong_negative >= 5 and not connect_accepted:
            add(scores, "http_tunneling_front", W["no_indicators"], against="multiple signs of ordinary site behavior")

    def _score_quic_relay() -> None:
        if mode != "udp":
            return
        W = _W["quic_relay"]
        if quic_ok:
            add(scores, "quic_relay", W["quic_ok"], "successful QUIC handshake")
        if udp_junk_silent:
            add(scores, "quic_relay", W["udp_junk_silent"], "silent drop on junk UDP")
        if public_cert:
            add(scores, "quic_relay", W["public_cert"], "public certificate over QUIC")
        if foreign_open:
            add(scores, "quic_relay", W["foreign_open"], "answers to foreign SNI over QUIC")
        if nosni_open:
            add(scores, "quic_relay", W["nosni_open"], "answers without SNI over QUIC")
        if h3:
            add(scores, "quic_relay", W["h3"], "QUIC / H3 style transport surface")

    def _score_direct_http_proxy() -> None:
        if not connect_accepted:
            return
        W = _W["direct_http_proxy"]
        add(scores, "direct_http_proxy", W["connect_accepted"], "CONNECT explicitly accepted")
        if h2:
            add(scores, "direct_http_proxy", W["h2_connect"], "HTTP/2 present alongside CONNECT")

    def _score_no_clear_tunnel_evidence() -> None:
        if not (mode == "tcp" and strong_negative >= 5 and not connect_accepted and not ws_exposed and not grpc_exposed and not grpc_strict_exposed):
            return
        W = _W["no_clear_tunnel_evidence"]
        add(scores, "no_clear_tunnel_evidence", W["normal_web"], "normal web behavior with no exposed tunnel endpoints")
        if public_cert:
            add(scores, "no_clear_tunnel_evidence", W["public_cert"], "credible public certificate")
        if connect_rejected:
            add(scores, "no_clear_tunnel_evidence", W["connect_rejected"], "CONNECT rejected")
        if strong_web:
            add(scores, "no_clear_tunnel_evidence", W["strong_web"], "random-path behavior looks like a normal site")
        if headers_some:
            add(scores, "no_clear_tunnel_evidence", W["headers_some"], "normal HTTPS header surface")
        if foreign_open:
            add(scores, "no_clear_tunnel_evidence", W["foreign_open"], against="still answers broadly on foreign SNI")
        if nosni_open:
            add(scores, "no_clear_tunnel_evidence", W["nosni_open"], against="still answers without SNI")
        if tls_surface == "default_cert_broad_front":
            add(scores, "no_clear_tunnel_evidence", W["diff_cert_broad"], against="default/alternate cert broadness is a suspicious TLS surface")
        if cert_san_match:
            add(scores, "no_clear_tunnel_evidence", W["cert_san_match"], "certificate explicitly covers the probed SNI")
        if cert_san_mismatch:
            add(scores, "no_clear_tunnel_evidence", W["cert_san_mismatch"], against="certificate does not cover the probed SNI")

    # ── Run all scorers ───────────────────────────────────────
    _score_ordinary_web_front()
    _score_broad_tls_front()
    _score_cdn_front()
    _score_tls_camouflage_relay()
    _score_default_cert_tls_front()
    _score_exposed_v2ray_transport()
    _score_http_tunneling_front()
    _score_quic_relay()
    _score_direct_http_proxy()
    _score_no_clear_tunnel_evidence()

    # ── Build hypothesis labels ───────────────────────────────
    labels = {
        "ordinary_web_front": {"label": t("Ordinary web front", "Обычный веб-фронт"), "examples": [t("nginx/apache/caddy style HTTPS site", "HTTPS-сайт в стиле nginx/apache/caddy")]},
        "default_cert_tls_front": {"label": "Default/shared-cert TLS front", "examples": ["default nginx vhost", "shared caddy cert front"]},
        "broad_tls_front": {"label": "Broad TLS front", "examples": ["wide-SNI TLS front", "generic HTTPS terminator"]},
        "tls_camouflage_relay": {"label": t("TLS camouflage relay", "TLS-ретранслятор с маскировкой"), "examples": ["Reality-like", "ShadowTLS-like", "Trojan-like"]},
        "exposed_v2ray_transport": {"label": "Exposed V2Ray-style transport", "examples": ["WS transport", "gRPC transport", "HTTP/2 transport"]},
        "http_tunneling_front": {"label": "HTTP tunneling / browser-like front", "examples": ["NaiveProxy-like", "WebTunnel-like", "MASQUE-like"]},
        "cdn_or_reverse_proxy_front": {"label": "CDN / reverse-proxy-like front", "examples": ["Cloudflare-like edge", "reverse-proxy edge front"]},
        "quic_relay": {"label": "QUIC relay family", "examples": ["Hysteria2-like", "TUIC-like", "QUIC transport"]},
        "direct_http_proxy": {"label": "Direct HTTP proxy semantics", "examples": ["CONNECT proxy"]},
        "no_clear_tunnel_evidence": {"label": t("Ordinary web service with no clear tunnel evidence", "Обычный веб-сервис без явных признаков туннеля"), "examples": [t("normal site / web app", "обычный сайт / веб-приложение")]},
    }

    # ── Rank hypotheses ───────────────────────────────────────
    hypotheses: list[dict[str, Any]] = []
    for key, item in scores.items():
        raw = max(0.0, min(1.0, item["score"]))
        supports = len(item["supports"])
        against = len(item["against"])
        final = round(raw * _reason_factor(conf, supports, against), 3)
        if final < 0.18:
            continue
        level = "high" if final >= 0.65 else "medium" if final >= 0.40 else "low"
        hypotheses.append({
            "family": key,
            "label": labels[key]["label"],
            "examples": labels[key]["examples"],
            "score": final,
            "confidence": level,
            "supports": item["supports"][:5],
            "against": item["against"][:5],
        })

    hypotheses.sort(key=lambda x: x["score"], reverse=True)

    if tls_surface == "default_cert_broad_front" and foreign_open and nosni_open:
        for h in hypotheses:
            if h["family"] == "ordinary_web_front":
                h["score"] = round(max(0.0, h["score"] * 0.85), 3)
                if h["confidence"] == "high":
                    h["confidence"] = "medium"
                h["against"] = (h.get("against", []) + [_translate_reason("broad SNI acceptance weakens 'ordinary front' confidence", lang)])[:5]
                break
        hypotheses.sort(key=lambda x: x["score"], reverse=True)

    top = hypotheses[0] if hypotheses else None

    # ── Overall assessment ────────────────────────────────────
    overall = None
    if top:
        if top["family"] in {"ordinary_web_front", "no_clear_tunnel_evidence"} and top["score"] >= 0.60 and not ws_exposed and not grpc_exposed and not grpc_strict_exposed and not connect_accepted and tls_surface == "strict_sni_front":
            conf_label = top["confidence"]
            if foreign_open and nosni_open and conf_label == "high":
                conf_label = "medium"
            overall = {
                "label": t("Looks like an ordinary web service with no clear tunnel evidence", "Похоже на обычный веб-сервис без явных признаков туннеля"),
                "confidence": conf_label,
                "caution": t("This does not prove the absence of VPN/proxy use; it only means current probes did not surface clear tunnel indicators.", "Это не доказывает отсутствие VPN/прокси; текущие пробы просто не выявили явных индикаторов туннеля."),
            }
        elif top["family"] in {"ordinary_web_front", "no_clear_tunnel_evidence"}:
            ordinary_label = t("Looks like an ordinary web service with no clear tunnel evidence", "Похоже на обычный веб-сервис без явных признаков туннеля")
            ordinary_caution = t("Current probes mostly match regular HTTPS behavior; this is still a family-level inference.", "Текущие пробы в основном соответствуют обычному HTTPS-поведению; это все еще вывод на уровне семейства.")
            if tls_surface == "same_cert_broad_front":
                ordinary_label = t("Ordinary web front with same-cert broad TLS surface", "Обычный веб-фронт с широкой TLS-поверхностью и тем же сертификатом")
                ordinary_caution = t("Same-cert broadness widens probe surface, but is softer than default-cert broadness.", "Широкая поверхность с тем же сертификатом расширяет поверхность проб, но мягче, чем вариант с default-сертификатом.")
            elif tls_surface == "default_cert_broad_front":
                ordinary_label = t("Ordinary web front with default-cert broad TLS surface", "Обычный веб-фронт с широкой TLS-поверхностью и default-сертификатом")
                ordinary_caution = t("Default/alternate cert behavior is a stronger TLS-surface anomaly and should be reviewed.", "Поведение с default/альтернативным сертификатом — более сильная аномалия TLS-поверхности и требует проверки.")
            elif tls_surface == "strict_sni_front":
                ordinary_label = t("Ordinary web front with strict SNI handling", "Обычный веб-фронт со строгой обработкой SNI")
                ordinary_caution = t("Strict SNI handling generally reduces generic scan surface.", "Строгая обработка SNI обычно снижает общую поверхность сканирования.")
            overall = {
                "label": ordinary_label,
                "confidence": top["confidence"],
                "caution": ordinary_caution,
            }
        elif top["family"] in {"broad_tls_front", "default_cert_tls_front"}:
            broad_label = t("Ordinary web front with broad TLS surface", "Обычный веб-фронт с широкой TLS-поверхностью")
            broad_caution = t("Broad SNI acceptance increases scan surface but is not, by itself, proof of relay usage.", "Широкое принятие SNI увеличивает поверхность сканирования, но само по себе не доказывает использование релея.")
            if tls_surface == "same_cert_broad_front":
                broad_label = t("Ordinary web front with same-cert broad TLS surface", "Обычный веб-фронт с широкой TLS-поверхностью и тем же сертификатом")
                broad_caution = t("Same-cert broadness is softer than default-cert broadness, but still widens probe surface.", "Вариант с тем же сертификатом мягче default-cert сценария, но все равно расширяет поверхность проб.")
            elif tls_surface == "default_cert_broad_front":
                broad_label = t("Ordinary web front with default-cert broad TLS surface", "Обычный веб-фронт с широкой TLS-поверхностью и default-сертификатом")
                broad_caution = t("Default/alternate cert behavior under foreign/no-SNI is a stronger suspicious surface signal.", "Поведение default/альтернативного сертификата под foreign/no-SNI — более сильный подозрительный сигнал поверхности.")
            elif tls_surface == "strict_sni_front":
                broad_label = t("Ordinary web front with strict SNI handling", "Обычный веб-фронт со строгой обработкой SNI")
                broad_caution = t("Strict SNI handling reduces generic TLS scan surface.", "Строгая обработка SNI снижает общую TLS-поверхность сканирования.")
            overall = {
                "label": broad_label,
                "confidence": top["confidence"],
                "caution": broad_caution,
            }
        elif top["family"] == "cdn_or_reverse_proxy_front":
            overall = {
                "label": t("Looks like a CDN or reverse-proxy-style web edge", "Похоже на веб-edge в стиле CDN или reverse-proxy"),
                "confidence": top["confidence"],
                "caution": t("Edge-like web behavior can be normal for third-party fronting and is not tunnel evidence by itself.", "Веб-поведение в стиле edge может быть нормальным для стороннего фронтирования и само по себе не является признаком туннеля."),
            }
        elif top["family"] == "tls_camouflage_relay":
            overall = {
                "label": t("Plausible TLS-camouflaged relay/front", "Вероятный TLS-замаскированный релей/фронт"),
                "confidence": top["confidence"],
                "caution": t("This remains a family-level hypothesis, not a product-level identification.", "Это остается гипотезой на уровне семейства, а не идентификацией конкретного продукта."),
            }
        elif top["family"] in {"exposed_v2ray_transport", "direct_http_proxy", "quic_relay"}:
            overall = {
                "label": t("Tunnel/proxy-like surface characteristics are present", "Присутствуют характеристики поверхности, похожие на туннель/прокси"),
                "confidence": top["confidence"],
                "caution": t("Interpretation depends on how specific the exposed semantics are.", "Интерпретация зависит от того, насколько специфична обнаруженная семантика."),
            }

    return {
        "hypotheses": hypotheses[:5],
        "top_family": top["family"] if top else None,
        "top_label": top["label"] if top else None,
        "overall_assessment": overall,
        "tls_surface_class": {"id": tls_surface, "reasons": tls_surface_reasons[:2]},
        "cert_routing_profile": _cert_routing_profile(tls_surface),
        "surface_risk": _surface_risk(findings, lang),
        "hardening_hints": _hardening_hints(payload, findings, lang),
    }


# ── Text renderers ────────────────────────────────────────────

def render_text(inference: dict[str, Any], lang: str = "en") -> str:
    def t(en: str, ru: str) -> str:
        return tr(en, ru, lang)

    hyps = inference.get("hypotheses", [])
    if not hyps:
        return ""
    top = hyps[0]
    pct = int(round(top["score"] * 100))
    lines = [f"  {t('Protocol hypotheses', 'Гипотезы протоколов')}", f"  Top: {top['label']} ({pct}% / {top['confidence']})"]
    examples = ", ".join(top.get("examples", [])[:3])
    if examples:
        lines.append(f"  Examples: {examples}")
    if top.get("supports"):
        lines.append(f"  {t('Supports', 'Поддерживают')}:")
        for reason in top["supports"][:4]:
            lines.append(f"    - {reason}")
    if top.get("against"):
        lines.append(f"  {t('Against', 'Против')}:")
        for reason in top["against"][:3]:
            lines.append(f"    - {reason}")
    others = hyps[1:3]
    if others:
        lines.append(f"  {t('Other plausible families', 'Другие правдоподобные семейства')}:")
        for h in others:
            lines.append(f"    - {h['label']}: {int(round(h['score'] * 100))}% ({h['confidence']})")
    surface = inference.get("surface_risk")
    tls_surface = inference.get("tls_surface_class")
    if tls_surface:
        lines.append(f"  {t('TLS surface class', 'Класс TLS-поверхности')}:")
        lines.append(f"    {tls_surface.get('id')}")
    cert_profile = inference.get("cert_routing_profile")
    if cert_profile:
        lines.append(f"  {t('Cert routing profile', 'Профиль маршрутизации сертификата')}:")
        lines.append(f"    {cert_profile}")
    if surface:
        lines.append(f"  {t('Surface risk', 'Риск поверхности')}:")
        lines.append(f"    {surface['label']} (score {surface['score']})")
        if surface.get("reasons"):
            lines.append(f"    {t('because', 'потому что')}: {', '.join(surface['reasons'][:3])}")
    overall = inference.get("overall_assessment")
    if overall:
        lines.append(f"  {t('Overall assessment', 'Общая оценка')}:")
        lines.append(f"    {overall['label']} ({overall['confidence']})")
        if overall.get("caution"):
            lines.append(f"    {t('note', 'примечание')}: {overall['caution']}")
    hints = inference.get("hardening_hints") or []
    if hints:
        lines.append(f"  {t('Hardening hints', 'Рекомендации по защите')}:")
        for hint in hints[:4]:
            lines.append(f"    - {hint}")
    return "\n".join(lines)


def render_debug_text(payload: dict[str, Any], inference: dict[str, Any]) -> str:
    lines = ["  Inference debug", "  Findings used:"]
    for f in payload.get("findings", []):
        lines.append(f"    - {f.get('id')}: {f.get('severity')} | {f.get('observed')}")
    lines.append("  Ranked hypotheses:")
    for h in inference.get("hypotheses", []):
        lines.append(f"    - {h['family']}: {int(round(h['score'] * 100))}% ({h['confidence']})")
        for r in h.get("supports", [])[:5]:
            lines.append(f"      + {r}")
        for r in h.get("against", [])[:3]:
            lines.append(f"      - {r}")
    surface = inference.get("surface_risk")
    tls_surface = inference.get("tls_surface_class")
    if tls_surface:
        lines.append(f"  TLS surface class: {tls_surface.get('id')}")
    cert_profile = inference.get("cert_routing_profile")
    if cert_profile:
        lines.append(f"  Cert routing profile: {cert_profile}")
    if surface:
        lines.append(f"  Surface risk: {surface['label']} (score {surface['score']})")
    overall = inference.get("overall_assessment")
    if overall:
        lines.append(f"  Overall: {overall['label']} ({overall['confidence']})")
    hints = inference.get("hardening_hints") or []
    if hints:
        lines.append("  Hardening hints:")
        for hint in hints:
            lines.append(f"    - {hint}")
    return "\n".join(lines)


# ── CLI entry point ───────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--text", action="store_true")
    ap.add_argument("--debug", action="store_true")
    ap.add_argument("--enrich", action="store_true")
    args = ap.parse_args()

    payload = json.load(sys.stdin)
    lang = str(payload.get("lang", "en"))
    inf = infer_payload(payload)
    if args.text:
        txt = render_text(inf, lang)
        if txt:
            print(txt)
        if args.debug:
            print(render_debug_text(payload, inf))
    elif args.enrich:
        payload["protocol_inference"] = inf
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(json.dumps(inf, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
