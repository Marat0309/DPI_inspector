#!/usr/bin/env python3
from __future__ import annotations
import argparse
import json
import sys
from typing import Any

LANG = "en"


def tr(en: str, ru: str) -> str:
    return ru if LANG == "ru" else en


def _translate_reason(text: str) -> str:
    if LANG != "ru":
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
        "CONNECT accepted like a proxy": "CONNECT принимается как у прокси",
        "weaker HTTPS header profile": "более слабый профиль HTTPS-заголовков",
        "HTTP redirect behavior not ideal": "поведение HTTP-редиректа неидеально",
        "older TLS profile": "устаревший профиль TLS",
        "repeated weak gRPC hints": "повторяющиеся слабые признаки gRPC",
        "weak gRPC hint combined with other anomalies": "слабый признак gRPC в сочетании с другими аномалиями",
        "combined foreign-SNI + no-SNI acceptance widens surface": "комбинация foreign-SNI + no-SNI расширяет поверхность",
        "broad SNI behavior appears alongside transport or web-profile anomalies": "широкое SNI-поведение наблюдается вместе с транспортными или веб-профильными аномалиями",
    }
    return mapping.get(text, text)


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


def _tls_surface_class(findings: dict[str, dict[str, Any]]) -> tuple[str, list[str]]:
    foreign_open = _sev(findings, "foreign_sni", "mismatched_sni") == "risk"
    nosni_open = _sev(findings, "no_sni") == "risk"
    if not foreign_open and not nosni_open:
        return "strict_sni_front", ["foreign/no-SNI probes do not receive a certificate"]

    relations: list[str] = []
    if foreign_open:
        relations.append(str(_field(findings, "returned_relation", "foreign_sni", "mismatched_sni") or "unknown"))
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


def _add(bucket: dict[str, dict[str, Any]], key: str, pts: float, support: str | None = None, against: str | None = None) -> None:
    bucket.setdefault(key, {"score": 0.0, "supports": [], "against": []})
    bucket[key]["score"] += pts
    if support:
        bucket[key]["supports"].append(_translate_reason(support))
    if against:
        bucket[key]["against"].append(_translate_reason(against))


def _reason_factor(conf: int, supports: int, against: int) -> float:
    factor = 0.58 + min(0.20, supports * 0.04) + min(0.12, conf / 800)
    factor -= min(0.10, against * 0.02)
    return max(0.38, factor)


def _surface_risk(findings: dict[str, dict[str, Any]]) -> dict[str, Any]:
    score = 0
    reasons: list[str] = []
    tls_surface, _ = _tls_surface_class(findings)
    foreign_open = _sev(findings, "foreign_sni", "mismatched_sni") == "risk"
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
    return {"score": score, "label": label, "reasons": [_translate_reason(x) for x in reasons[:5]]}


def _hardening_hints(payload: dict[str, Any], findings: dict[str, dict[str, Any]]) -> list[str]:
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
        hints.append(tr("Port 80 does not cleanly redirect to HTTPS; add a 301 redirect.", "Порт 80 не делает чистый редирект на HTTPS; добавьте 301 редирект."))
    if _sev(findings, "headers") == "notice":
        hints.append(tr("Add HSTS on the HTTPS server block to strengthen the web profile.", "Добавьте HSTS в HTTPS server block, чтобы усилить веб-профиль."))
    tls_surface, _ = _tls_surface_class(findings)
    if tls_surface == "same_cert_broad_front":
        hints.append(tr("Same cert is served on foreign/no-SNI; tighten unknown-SNI/default vhost handling to reduce broad scan surface.", "На foreign/no-SNI отдается тот же сертификат; ужесточите обработку unknown-SNI/default vhost, чтобы сузить поверхность."))
    elif tls_surface == "default_cert_broad_front":
        hints.append(tr("Foreign/no-SNI returns another cert; review default certificate and default-server routing first.", "На foreign/no-SNI возвращается другой сертификат; сначала проверьте default-сертификат и маршрутизацию default-server."))
    elif _sev(findings, "foreign_sni", "mismatched_sni") == "risk" or _sev(findings, "no_sni") == "risk":
        hints.append(tr("Tighten the default server / unknown-SNI handling, ideally dropping unmatched SNI.", "Ужесточите обработку default server / unknown-SNI, в идеале отбрасывайте несовпавший SNI."))
    if is_domain and hints and (recommend_fixes or ("nginx" in banner and not edge_like)):
        hints.append(tr(f"For nginx targets, review harden_nginx.sh {host} --dry-run before applying changes.", f"Для nginx-целей проверьте harden_nginx.sh {host} --dry-run перед применением изменений."))
    return hints[:4]


def infer_payload(payload: dict[str, Any]) -> dict[str, Any]:
    global LANG
    LANG = str(payload.get("lang", "en"))
    findings_list = payload.get("findings", [])
    findings = {f.get("id", f.get("title", str(i))): f for i, f in enumerate(findings_list)}
    mode = payload.get("target", {}).get("mode", "")
    conf = int(payload.get("confidence", {}).get("score", 100))
    scores: dict[str, dict[str, Any]] = {}

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
    foreign_open = _sev(findings, "foreign_sni", "mismatched_sni") == "risk"
    nosni_open = _sev(findings, "no_sni") == "risk"
    tls_surface, tls_surface_reasons = _tls_surface_class(findings)
    quic_ok = _sev(findings, "quic_handshake") == "ok"
    udp_junk_silent = _sev(findings, "raw_udp") == "ok"

    strong_negative = 0
    if connect_rejected:
        strong_negative += 1
    if not ws_exposed:
        strong_negative += 1
    if not grpc_exposed and not grpc_strict_exposed:
        strong_negative += 1
    if strong_web:
        strong_negative += 1
    if headers_some:
        strong_negative += 1
    if public_cert:
        strong_negative += 1

    # Ordinary web front
    if web_ok:
        _add(scores, "ordinary_web_front", 0.24, "ordinary HTTPS fallback page")
    if public_cert:
        _add(scores, "ordinary_web_front", 0.16, "public CA certificate")
    elif cert_non_public:
        _add(scores, "ordinary_web_front", -0.08, against="non-public or unusual certificate profile")
    if modern_tls:
        _add(scores, "ordinary_web_front", 0.10, "modern TLS stack")
    elif usable_tls:
        _add(scores, "ordinary_web_front", 0.06, "usable TLS stack")
    if headers_strong:
        _add(scores, "ordinary_web_front", 0.12, "strong normal header profile")
    elif headers_some:
        _add(scores, "ordinary_web_front", 0.06, "some normal header profile")
    if alpn_ok:
        _add(scores, "ordinary_web_front", 0.06, "ALPN profile looks web-like (h2+h1)")
    elif alpn_weak:
        _add(scores, "ordinary_web_front", 0.02, "partial ALPN web profile")
    if strong_web:
        _add(scores, "ordinary_web_front", 0.12, "plausible behavior on random paths")
    if connect_rejected:
        _add(scores, "ordinary_web_front", 0.10, "CONNECT rejected like a normal web server")
    if not ws_exposed:
        _add(scores, "ordinary_web_front", 0.07, "no obvious WS transport exposure")
    if not grpc_exposed and not grpc_strict_exposed:
        _add(scores, "ordinary_web_front", 0.07, "no obvious gRPC transport exposure")
    if strong_web and connect_rejected and not ws_exposed and not grpc_exposed and public_cert:
        _add(scores, "ordinary_web_front", 0.24, "combined normal-web behavior across path, CONNECT, and transport checks")
    if tls_surface == "same_cert_broad_front":
        _add(scores, "ordinary_web_front", -0.06, against="same-cert foreign/no-SNI broadness still widens scan surface")
    elif tls_surface == "default_cert_broad_front":
        _add(scores, "ordinary_web_front", -0.22, against="different/default cert on foreign/no-SNI is a stronger anomaly")
    elif tls_surface == "strict_sni_front":
        _add(scores, "ordinary_web_front", 0.05, "strict SNI behavior is common for ordinary web fronting")
    if foreign_open and _field(findings, "returned_relation", "foreign_sni", "mismatched_sni") == "different-cert":
        _add(scores, "ordinary_web_front", -0.10, against="foreign SNI receives a different/default certificate")
    if nosni_open and _field(findings, "returned_relation", "no_sni") == "different-cert":
        _add(scores, "ordinary_web_front", -0.10, against="no-SNI receives a different/default certificate")
    if foreign_open and nosni_open and tls_surface == "default_cert_broad_front":
        _add(scores, "ordinary_web_front", -0.12, against="combined broad-SNI behavior with alternate cert substantially increases surface")
    if ws_exposed:
        _add(scores, "ordinary_web_front", -0.18, against="WS transport appears exposed")
    if grpc_exposed:
        _add(scores, "ordinary_web_front", -0.22, against="gRPC transport appears exposed")
    if grpc_strict_exposed:
        _add(scores, "ordinary_web_front", -0.30, against="strict HTTP/2 gRPC semantics exposed")
    if connect_accepted:
        _add(scores, "ordinary_web_front", -0.22, against="CONNECT accepted like a proxy")
    if random_path_risk:
        _add(scores, "ordinary_web_front", -0.10, against="random-path behavior looks selective/unusual")

    # Broad TLS front
    if mode == "tcp" and web_ok and public_cert:
        _add(scores, "broad_tls_front", 0.12, "credible public certificate")
        if usable_tls:
            _add(scores, "broad_tls_front", 0.06, "usable TLS profile")
        if strong_web:
            _add(scores, "broad_tls_front", 0.04, "web-like fallback front")
        if tls_surface == "same_cert_broad_front":
            _add(scores, "broad_tls_front", 0.10, "accepts foreign/no-SNI while keeping same cert")
        elif tls_surface == "default_cert_broad_front":
            _add(scores, "broad_tls_front", 0.22, "accepts foreign/no-SNI and serves alternate/default cert")
        elif tls_surface == "strict_sni_front":
            _add(scores, "broad_tls_front", -0.10, against="strict SNI behavior is opposite of broad TLS fronting")
        if cert_non_public:
            _add(scores, "broad_tls_front", 0.04, "certificate profile is less typical for mainstream web")
        if connect_rejected:
            _add(scores, "broad_tls_front", 0.03, "still behaves like a normal web server on CONNECT")
        if not ws_exposed and not grpc_exposed and not grpc_strict_exposed:
            _add(scores, "broad_tls_front", 0.03, "no obvious transport endpoints exposed")
        if strong_web and headers_strong:
            _add(scores, "broad_tls_front", -0.08, against="very normal web profile overall")
        if strong_negative >= 5:
            _add(scores, "broad_tls_front", -0.08, against="lack of direct tunnel indicators")

    # CDN / reverse-proxy-like edge front
    edge_banner = _obs(findings, "headers").lower()
    redirect_ok = _sev(findings, "http_redirect") == "ok" and _obs(findings, "http_redirect").startswith("HTTP 30")
    strict_sni = tls_surface == "strict_sni_front"
    edge_like = any(x in edge_banner for x in ("cloudflare", "fastly", "akamai", "cdn", "edge"))
    if mode == "tcp" and web_ok and (edge_like or (strict_sni and headers_some and redirect_ok)):
        _add(scores, "cdn_or_reverse_proxy_front", 0.24, "edge-like front behavior")
        if edge_like:
            _add(scores, "cdn_or_reverse_proxy_front", 0.16, "server/header banner looks CDN or reverse-proxy-like")
        if strict_sni:
            _add(scores, "cdn_or_reverse_proxy_front", 0.12, "strict foreign-SNI/no-SNI handling")
        if headers_some:
            _add(scores, "cdn_or_reverse_proxy_front", 0.08, "usable edge/web header profile")
        if redirect_ok:
            _add(scores, "cdn_or_reverse_proxy_front", 0.06, "redirect-heavy edge-like entry behavior")
        if ws_exposed or grpc_exposed or grpc_strict_exposed or connect_accepted:
            _add(scores, "cdn_or_reverse_proxy_front", -0.12, against="transport/proxy exposure is less typical for a plain CDN edge")

    # TLS camouflage relay
    if mode == "tcp":
        if public_cert:
            _add(scores, "tls_camouflage_relay", 0.10, "credible public certificate")
        if modern_tls:
            _add(scores, "tls_camouflage_relay", 0.08, "modern TLS profile")
        if web_ok:
            _add(scores, "tls_camouflage_relay", 0.06, "web-like fallback front")
        if tls_surface == "same_cert_broad_front":
            _add(scores, "tls_camouflage_relay", 0.08, "same-cert foreign/no-SNI acceptance")
        elif tls_surface == "default_cert_broad_front":
            _add(scores, "tls_camouflage_relay", 0.14, "alternate/default cert under foreign/no-SNI")
        if cert_non_public:
            _add(scores, "tls_camouflage_relay", 0.08, "non-public or unusual certificate profile")
        if not ws_exposed and not grpc_exposed:
            _add(scores, "tls_camouflage_relay", 0.05, "no exposed WS/gRPC transport paths")
        if strong_web:
            _add(scores, "tls_camouflage_relay", -0.06, against="very ordinary web-path behavior")
        if headers_strong:
            _add(scores, "tls_camouflage_relay", -0.04, against="strongly normal HTTPS header profile")
        if connect_rejected:
            _add(scores, "tls_camouflage_relay", -0.04, against="CONNECT rejected like a plain web server")
        if strong_negative >= 5:
            _add(scores, "tls_camouflage_relay", -0.06, against="multiple signs of an ordinary site")

    # Default/shared certificate TLS front
    if mode == "tcp" and web_ok and (foreign_open or nosni_open):
        foreign_diff = foreign_open and _field(findings, "returned_relation", "foreign_sni", "mismatched_sni") == "different-cert"
        nosni_diff = nosni_open and _field(findings, "returned_relation", "no_sni") == "different-cert"
        if foreign_diff:
            _add(scores, "default_cert_tls_front", 0.30, "foreign SNI is accepted with a different/default certificate")
        if nosni_diff:
            _add(scores, "default_cert_tls_front", 0.24, "no-SNI is accepted with a different/default certificate")
        if tls_surface == "default_cert_broad_front":
            _add(scores, "default_cert_tls_front", 0.18, "default-cert broad routing profile")
        if _sev(findings, "headers") == "notice":
            _add(scores, "default_cert_tls_front", 0.06, "weaker header profile")
        if weak_grpc_hints >= 2:
            _add(scores, "default_cert_tls_front", 0.06, "repeated weak gRPC hints")
        elif weak_grpc_hints == 1 and (_sev(findings, "headers") == "notice" or _sev(findings, "http_redirect") == "notice"):
            _add(scores, "default_cert_tls_front", 0.03, "weak gRPC hint appears with other anomalies")
        if _sev(findings, "http_redirect") == "notice":
            _add(scores, "default_cert_tls_front", 0.04, "HTTP redirect profile is weaker than expected")
        if strong_web and headers_strong:
            _add(scores, "default_cert_tls_front", -0.08, against="clean web profile lowers default-cert front suspicion")
        if tls_surface == "same_cert_broad_front":
            _add(scores, "default_cert_tls_front", -0.10, against="same-cert broadness is softer than default-cert routing")

    # Exposed V2Ray-style transport
    if ws_exposed:
        _add(scores, "exposed_v2ray_transport", 0.62, "WS upgrade succeeds on common paths")
    if grpc_exposed:
        _add(scores, "exposed_v2ray_transport", 0.58, "strong gRPC semantics surfaced")
    elif grpc_hint:
        _add(scores, "exposed_v2ray_transport", 0.14, "weak gRPC hint surfaced")
    if grpc_strict_exposed:
        _add(scores, "exposed_v2ray_transport", 0.46, "strict HTTP/2 gRPC semantics surfaced")
    elif grpc_strict_hint:
        _add(scores, "exposed_v2ray_transport", 0.16, "partial strict gRPC hint")
    if h2 and grpc_exposed:
        _add(scores, "exposed_v2ray_transport", 0.10, "HTTP/2 + gRPC combination")
    if connect_accepted:
        _add(scores, "exposed_v2ray_transport", 0.10, "proxy-like CONNECT behavior")

    # HTTP tunneling / browser-like front
    if mode == "tcp":
        if h2:
            _add(scores, "http_tunneling_front", 0.14, "ALPN negotiated h2")
        if web_ok and public_cert:
            _add(scores, "http_tunneling_front", 0.12, "credible browser-like HTTPS front")
        if connect_accepted:
            _add(scores, "http_tunneling_front", 0.34, "CONNECT accepted")
        elif connect_rejected and h2 and web_ok:
            _add(scores, "http_tunneling_front", 0.04, "hidden tunnel front is still possible")
        if _sev(findings, "http_fallback") == "ok":
            _add(scores, "http_tunneling_front", 0.04, "clean fallback site")
        if ws_exposed or grpc_exposed:
            _add(scores, "http_tunneling_front", -0.08, against="more like an exposed transport than a hidden tunnel front")
        if strong_negative >= 5 and not connect_accepted:
            _add(scores, "http_tunneling_front", -0.06, against="multiple signs of ordinary site behavior")

    # QUIC relay family
    if mode == "udp":
        if quic_ok:
            _add(scores, "quic_relay", 0.34, "successful QUIC handshake")
        if udp_junk_silent:
            _add(scores, "quic_relay", 0.14, "silent drop on junk UDP")
        if public_cert:
            _add(scores, "quic_relay", 0.08, "public certificate over QUIC")
        if foreign_open:
            _add(scores, "quic_relay", 0.08, "answers to foreign SNI over QUIC")
        if nosni_open:
            _add(scores, "quic_relay", 0.06, "answers without SNI over QUIC")
        if h3:
            _add(scores, "quic_relay", 0.06, "QUIC / H3 style transport surface")

    if connect_accepted:
        _add(scores, "direct_http_proxy", 0.70, "CONNECT explicitly accepted")
        if h2:
            _add(scores, "direct_http_proxy", 0.10, "HTTP/2 present alongside CONNECT")

    # Ordinary site with no clear tunnel evidence
    if mode == "tcp" and strong_negative >= 5 and not connect_accepted and not ws_exposed and not grpc_exposed and not grpc_strict_exposed:
        _add(scores, "no_clear_tunnel_evidence", 0.34, "normal web behavior with no exposed tunnel endpoints")
        if public_cert:
            _add(scores, "no_clear_tunnel_evidence", 0.08, "credible public certificate")
        if connect_rejected:
            _add(scores, "no_clear_tunnel_evidence", 0.06, "CONNECT rejected")
        if strong_web:
            _add(scores, "no_clear_tunnel_evidence", 0.06, "random-path behavior looks like a normal site")
        if headers_some:
            _add(scores, "no_clear_tunnel_evidence", 0.06, "normal HTTPS header surface")
        if foreign_open:
            _add(scores, "no_clear_tunnel_evidence", -0.05, against="still answers broadly on foreign SNI")
        if nosni_open:
            _add(scores, "no_clear_tunnel_evidence", -0.04, against="still answers without SNI")
        if tls_surface == "default_cert_broad_front":
            _add(scores, "no_clear_tunnel_evidence", -0.08, against="default/alternate cert broadness is a suspicious TLS surface")

    labels = {
        "ordinary_web_front": {"label": tr("Ordinary web front", "Обычный веб-фронт"), "examples": [tr("nginx/apache/caddy style HTTPS site", "HTTPS-сайт в стиле nginx/apache/caddy")]},
        "default_cert_tls_front": {"label": "Default/shared-cert TLS front", "examples": ["default nginx vhost", "shared caddy cert front"]},
        "broad_tls_front": {"label": "Broad TLS front", "examples": ["wide-SNI TLS front", "generic HTTPS terminator"]},
        "tls_camouflage_relay": {"label": tr("TLS camouflage relay", "TLS-ретранслятор с маскировкой"), "examples": ["Reality-like", "ShadowTLS-like", "Trojan-like"]},
        "exposed_v2ray_transport": {"label": "Exposed V2Ray-style transport", "examples": ["WS transport", "gRPC transport", "HTTP/2 transport"]},
        "http_tunneling_front": {"label": "HTTP tunneling / browser-like front", "examples": ["NaiveProxy-like", "WebTunnel-like", "MASQUE-like"]},
        "cdn_or_reverse_proxy_front": {"label": "CDN / reverse-proxy-like front", "examples": ["Cloudflare-like edge", "reverse-proxy edge front"]},
        "quic_relay": {"label": "QUIC relay family", "examples": ["Hysteria2-like", "TUIC-like", "QUIC transport"]},
        "direct_http_proxy": {"label": "Direct HTTP proxy semantics", "examples": ["CONNECT proxy"]},
        "no_clear_tunnel_evidence": {"label": tr("Ordinary web service with no clear tunnel evidence", "Обычный веб-сервис без явных признаков туннеля"), "examples": [tr("normal site / web app", "обычный сайт / веб-приложение")]},
    }

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
                h["against"] = (h.get("against", []) + [_translate_reason("broad SNI acceptance weakens 'ordinary front' confidence")])[:5]
                break
        hypotheses.sort(key=lambda x: x["score"], reverse=True)

    top = hypotheses[0] if hypotheses else None

    overall = None
    if top:
        if top["family"] in {"ordinary_web_front", "no_clear_tunnel_evidence"} and top["score"] >= 0.60 and not ws_exposed and not grpc_exposed and not grpc_strict_exposed and not connect_accepted and tls_surface == "strict_sni_front":
            conf_label = top["confidence"]
            if foreign_open and nosni_open and conf_label == "high":
                conf_label = "medium"
            overall = {
                "label": tr("Looks like an ordinary web service with no clear tunnel evidence", "Похоже на обычный веб-сервис без явных признаков туннеля"),
                "confidence": conf_label,
                "caution": tr("This does not prove the absence of VPN/proxy use; it only means current probes did not surface clear tunnel indicators.", "Это не доказывает отсутствие VPN/прокси; текущие пробы просто не выявили явных индикаторов туннеля."),
            }
        elif top["family"] in {"ordinary_web_front", "no_clear_tunnel_evidence"}:
            ordinary_label = tr("Looks like an ordinary web service with no clear tunnel evidence", "Похоже на обычный веб-сервис без явных признаков туннеля")
            ordinary_caution = tr("Current probes mostly match regular HTTPS behavior; this is still a family-level inference.", "Текущие пробы в основном соответствуют обычному HTTPS-поведению; это все еще вывод на уровне семейства.")
            if tls_surface == "same_cert_broad_front":
                ordinary_label = tr("Ordinary web front with same-cert broad TLS surface", "Обычный веб-фронт с широкой TLS-поверхностью и тем же сертификатом")
                ordinary_caution = tr("Same-cert broadness widens probe surface, but is softer than default-cert broadness.", "Широкая поверхность с тем же сертификатом расширяет поверхность проб, но мягче, чем вариант с default-сертификатом.")
            elif tls_surface == "default_cert_broad_front":
                ordinary_label = tr("Ordinary web front with default-cert broad TLS surface", "Обычный веб-фронт с широкой TLS-поверхностью и default-сертификатом")
                ordinary_caution = tr("Default/alternate cert behavior is a stronger TLS-surface anomaly and should be reviewed.", "Поведение с default/альтернативным сертификатом — более сильная аномалия TLS-поверхности и требует проверки.")
            elif tls_surface == "strict_sni_front":
                ordinary_label = tr("Ordinary web front with strict SNI handling", "Обычный веб-фронт со строгой обработкой SNI")
                ordinary_caution = tr("Strict SNI handling generally reduces generic scan surface.", "Строгая обработка SNI обычно снижает общую поверхность сканирования.")
            overall = {
                "label": ordinary_label,
                "confidence": top["confidence"],
                "caution": ordinary_caution,
            }
        elif top["family"] in {"broad_tls_front", "default_cert_tls_front"}:
            broad_label = tr("Ordinary web front with broad TLS surface", "Обычный веб-фронт с широкой TLS-поверхностью")
            broad_caution = tr("Broad SNI acceptance increases scan surface but is not, by itself, proof of relay usage.", "Широкое принятие SNI увеличивает поверхность сканирования, но само по себе не доказывает использование релея.")
            if tls_surface == "same_cert_broad_front":
                broad_label = tr("Ordinary web front with same-cert broad TLS surface", "Обычный веб-фронт с широкой TLS-поверхностью и тем же сертификатом")
                broad_caution = tr("Same-cert broadness is softer than default-cert broadness, but still widens probe surface.", "Вариант с тем же сертификатом мягче default-cert сценария, но все равно расширяет поверхность проб.")
            elif tls_surface == "default_cert_broad_front":
                broad_label = tr("Ordinary web front with default-cert broad TLS surface", "Обычный веб-фронт с широкой TLS-поверхностью и default-сертификатом")
                broad_caution = tr("Default/alternate cert behavior under foreign/no-SNI is a stronger suspicious surface signal.", "Поведение default/альтернативного сертификата под foreign/no-SNI — более сильный подозрительный сигнал поверхности.")
            elif tls_surface == "strict_sni_front":
                broad_label = tr("Ordinary web front with strict SNI handling", "Обычный веб-фронт со строгой обработкой SNI")
                broad_caution = tr("Strict SNI handling reduces generic TLS scan surface.", "Строгая обработка SNI снижает общую TLS-поверхность сканирования.")
            overall = {
                "label": broad_label,
                "confidence": top["confidence"],
                "caution": broad_caution,
            }
        elif top["family"] == "cdn_or_reverse_proxy_front":
            overall = {
                "label": tr("Looks like a CDN or reverse-proxy-style web edge", "Похоже на веб-edge в стиле CDN или reverse-proxy"),
                "confidence": top["confidence"],
                "caution": tr("Edge-like web behavior can be normal for third-party fronting and is not tunnel evidence by itself.", "Веб-поведение в стиле edge может быть нормальным для стороннего фронтирования и само по себе не является признаком туннеля."),
            }
        elif top["family"] == "tls_camouflage_relay":
            overall = {
                "label": tr("Plausible TLS-camouflaged relay/front", "Вероятный TLS-замаскированный релей/фронт"),
                "confidence": top["confidence"],
                "caution": tr("This remains a family-level hypothesis, not a product-level identification.", "Это остается гипотезой на уровне семейства, а не идентификацией конкретного продукта."),
            }
        elif top["family"] in {"exposed_v2ray_transport", "direct_http_proxy", "quic_relay"}:
            overall = {
                "label": tr("Tunnel/proxy-like surface characteristics are present", "Присутствуют характеристики поверхности, похожие на туннель/прокси"),
                "confidence": top["confidence"],
                "caution": tr("Interpretation depends on how specific the exposed semantics are.", "Интерпретация зависит от того, насколько специфична обнаруженная семантика."),
            }

    return {
        "hypotheses": hypotheses[:5],
        "top_family": top["family"] if top else None,
        "top_label": top["label"] if top else None,
        "overall_assessment": overall,
        "tls_surface_class": {"id": tls_surface, "reasons": tls_surface_reasons[:2]},
        "cert_routing_profile": _cert_routing_profile(tls_surface),
        "surface_risk": _surface_risk(findings),
        "hardening_hints": _hardening_hints(payload, findings),
    }


def render_text(inference: dict[str, Any]) -> str:
    hyps = inference.get("hypotheses", [])
    if not hyps:
        return ""
    top = hyps[0]
    pct = int(round(top["score"] * 100))
    lines = [f"  {tr('Protocol hypotheses', 'Гипотезы протоколов')}", f"  Top: {top['label']} ({pct}% / {top['confidence']})"]
    examples = ", ".join(top.get("examples", [])[:3])
    if examples:
        lines.append(f"  Examples: {examples}")
    if top.get("supports"):
        lines.append(f"  {tr('Supports', 'Поддерживают')}:")
        for reason in top["supports"][:4]:
            lines.append(f"    - {reason}")
    if top.get("against"):
        lines.append(f"  {tr('Against', 'Против')}:")
        for reason in top["against"][:3]:
            lines.append(f"    - {reason}")
    others = hyps[1:3]
    if others:
        lines.append(f"  {tr('Other plausible families', 'Другие правдоподобные семейства')}:")
        for h in others:
            lines.append(f"    - {h['label']}: {int(round(h['score'] * 100))}% ({h['confidence']})")
    surface = inference.get("surface_risk")
    tls_surface = inference.get("tls_surface_class")
    if tls_surface:
        lines.append(f"  {tr('TLS surface class', 'Класс TLS-поверхности')}:")
        lines.append(f"    {tls_surface.get('id')}")
    cert_profile = inference.get("cert_routing_profile")
    if cert_profile:
        lines.append(f"  {tr('Cert routing profile', 'Профиль маршрутизации сертификата')}:")
        lines.append(f"    {cert_profile}")
    if surface:
        lines.append(f"  {tr('Surface risk', 'Риск поверхности')}:")
        lines.append(f"    {surface['label']} (score {surface['score']})")
        if surface.get("reasons"):
            lines.append(f"    {tr('because', 'потому что')}: {', '.join(surface['reasons'][:3])}")
    overall = inference.get("overall_assessment")
    if overall:
        lines.append(f"  {tr('Overall assessment', 'Общая оценка')}:")
        lines.append(f"    {overall['label']} ({overall['confidence']})")
        if overall.get("caution"):
            lines.append(f"    {tr('note', 'примечание')}: {overall['caution']}")
    hints = inference.get("hardening_hints") or []
    if hints:
        lines.append(f"  {tr('Hardening hints', 'Рекомендации по защите')}:")
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


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--text", action="store_true")
    ap.add_argument("--debug", action="store_true")
    ap.add_argument("--enrich", action="store_true")
    args = ap.parse_args()

    payload = json.load(sys.stdin)
    inf = infer_payload(payload)
    if args.text:
        txt = render_text(inf)
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
