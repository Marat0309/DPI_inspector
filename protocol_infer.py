#!/usr/bin/env python3
from __future__ import annotations
import argparse
import json
import sys
from typing import Any


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


def _add(bucket: dict[str, dict[str, Any]], key: str, pts: float, support: str | None = None, against: str | None = None) -> None:
    bucket.setdefault(key, {"score": 0.0, "supports": [], "against": []})
    bucket[key]["score"] += pts
    if support:
        bucket[key]["supports"].append(support)
    if against:
        bucket[key]["against"].append(against)


def _reason_factor(conf: int, supports: int, against: int) -> float:
    factor = 0.58 + min(0.20, supports * 0.04) + min(0.12, conf / 800)
    factor -= min(0.10, against * 0.02)
    return max(0.38, factor)


def _surface_risk(findings: dict[str, dict[str, Any]]) -> dict[str, Any]:
    score = 0
    reasons: list[str] = []
    if _sev(findings, "foreign_sni", "mismatched_sni") == "risk":
        score += 2
        reasons.append("answers to foreign SNI")
    if _sev(findings, "no_sni") == "risk":
        score += 2
        reasons.append("answers without SNI")
    if _sev(findings, "ws_leak") == "risk":
        score += 3
        reasons.append("WS transport endpoint exposed")
    if _sev(findings, "grpc_leak") == "risk":
        score += 3
        reasons.append("strong gRPC transport semantics exposed")
    elif _sev(findings, "grpc_leak") == "notice":
        score += 1
        reasons.append("weak gRPC hint")
    if _sev(findings, "grpc_strict_probe") == "risk":
        score += 4
        reasons.append("strict HTTP/2 gRPC semantics exposed")
    elif _sev(findings, "grpc_strict_probe") == "notice":
        score += 1
        reasons.append("partial strict gRPC hint")
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
    label = "low"
    if score >= 6:
        label = "high"
    elif score >= 3:
        label = "medium"
    return {"score": score, "label": label, "reasons": reasons[:5]}


def _hardening_hints(payload: dict[str, Any], findings: dict[str, dict[str, Any]]) -> list[str]:
    hints: list[str] = []
    target = payload.get("target", {})
    host = str(target.get("host", ""))
    is_domain = host and not host.replace(".", "").isdigit() and ":" not in host
    if _sev(findings, "http_redirect") == "notice":
        hints.append("Port 80 does not cleanly redirect to HTTPS; add a 301 redirect.")
    if _sev(findings, "headers") == "notice":
        hints.append("Add HSTS on the HTTPS server block to strengthen the web profile.")
    if _sev(findings, "foreign_sni", "mismatched_sni") == "risk" or _sev(findings, "no_sni") == "risk":
        hints.append("Tighten the default server / unknown-SNI handling, ideally dropping unmatched SNI.")
    if is_domain and hints:
        hints.append(f"For nginx targets, review harden_nginx.sh {host} --dry-run before applying changes.")
    return hints[:4]


def infer_payload(payload: dict[str, Any]) -> dict[str, Any]:
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
    connect_accepted = _sev(findings, "http_connect") == "risk" and "accepted" in _obs(findings, "http_connect").lower()
    connect_rejected = _sev(findings, "http_connect") == "ok"
    foreign_open = _sev(findings, "foreign_sni", "mismatched_sni") == "risk"
    nosni_open = _sev(findings, "no_sni") == "risk"
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
        _add(scores, "ordinary_web_front", 0.14, "combined normal-web behavior across path, CONNECT, and transport checks")
    if foreign_open:
        _add(scores, "ordinary_web_front", -0.14, against="answers to foreign SNI")
    if nosni_open:
        _add(scores, "ordinary_web_front", -0.10, against="answers without SNI")
    if foreign_open and nosni_open:
        _add(scores, "ordinary_web_front", -0.12, against="combined broad-SNI behavior increases scan surface")
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
        if foreign_open:
            _add(scores, "broad_tls_front", 0.10, "accepts foreign SNI")
        if nosni_open:
            _add(scores, "broad_tls_front", 0.08, "accepts no-SNI clients")
        if foreign_open and nosni_open:
            _add(scores, "broad_tls_front", 0.08, "combined foreign-SNI + no-SNI acceptance")
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

    # TLS camouflage relay
    if mode == "tcp":
        if public_cert:
            _add(scores, "tls_camouflage_relay", 0.10, "credible public certificate")
        if modern_tls:
            _add(scores, "tls_camouflage_relay", 0.08, "modern TLS profile")
        if web_ok:
            _add(scores, "tls_camouflage_relay", 0.06, "web-like fallback front")
        if foreign_open:
            _add(scores, "tls_camouflage_relay", 0.09, "accepts foreign SNI")
        if nosni_open:
            _add(scores, "tls_camouflage_relay", 0.07, "accepts no-SNI clients")
        if foreign_open and nosni_open:
            _add(scores, "tls_camouflage_relay", 0.10, "combined broad-SNI behavior")
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
        _add(scores, "no_clear_tunnel_evidence", 0.46, "normal web behavior with no exposed tunnel endpoints")
        if public_cert:
            _add(scores, "no_clear_tunnel_evidence", 0.12, "credible public certificate")
        if connect_rejected:
            _add(scores, "no_clear_tunnel_evidence", 0.10, "CONNECT rejected")
        if strong_web:
            _add(scores, "no_clear_tunnel_evidence", 0.10, "random-path behavior looks like a normal site")
        if headers_some:
            _add(scores, "no_clear_tunnel_evidence", 0.06, "normal HTTPS header surface")
        if foreign_open:
            _add(scores, "no_clear_tunnel_evidence", -0.05, against="still answers broadly on foreign SNI")
        if nosni_open:
            _add(scores, "no_clear_tunnel_evidence", -0.04, against="still answers without SNI")

    labels = {
        "ordinary_web_front": {"label": "Ordinary web front", "examples": ["nginx/apache/caddy style HTTPS site"]},
        "broad_tls_front": {"label": "Broad TLS front", "examples": ["wide-SNI TLS front", "generic HTTPS terminator"]},
        "tls_camouflage_relay": {"label": "TLS camouflage relay", "examples": ["Reality-like", "ShadowTLS-like", "Trojan-like"]},
        "exposed_v2ray_transport": {"label": "Exposed V2Ray-style transport", "examples": ["WS transport", "gRPC transport", "HTTP/2 transport"]},
        "http_tunneling_front": {"label": "HTTP tunneling / browser-like front", "examples": ["NaiveProxy-like", "WebTunnel-like", "MASQUE-like"]},
        "quic_relay": {"label": "QUIC relay family", "examples": ["Hysteria2-like", "TUIC-like", "QUIC transport"]},
        "direct_http_proxy": {"label": "Direct HTTP proxy semantics", "examples": ["CONNECT proxy"]},
        "no_clear_tunnel_evidence": {"label": "Ordinary web service with no clear tunnel evidence", "examples": ["normal site / web app"]},
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

    if foreign_open and nosni_open:
        for h in hypotheses:
            if h["family"] == "ordinary_web_front":
                h["score"] = round(max(0.0, h["score"] * 0.82), 3)
                if h["confidence"] == "high":
                    h["confidence"] = "medium"
                h["against"] = (h.get("against", []) + ["broad SNI acceptance weakens 'ordinary front' confidence"])[:5]
                break
        hypotheses.sort(key=lambda x: x["score"], reverse=True)

    top = hypotheses[0] if hypotheses else None

    overall = None
    if top:
        if top["family"] in {"ordinary_web_front", "no_clear_tunnel_evidence"} and top["score"] >= 0.60 and not ws_exposed and not grpc_exposed and not grpc_strict_exposed and not connect_accepted and not (foreign_open and nosni_open):
            conf_label = top["confidence"]
            if foreign_open and nosni_open and conf_label == "high":
                conf_label = "medium"
            overall = {
                "label": "Looks like an ordinary web service with no clear tunnel evidence",
                "confidence": conf_label,
                "caution": "This does not prove the absence of VPN/proxy use; it only means current probes did not surface clear tunnel indicators.",
            }
        elif top["family"] == "broad_tls_front":
            overall = {
                "label": "Ordinary-looking web front with broad TLS/SNI surface",
                "confidence": top["confidence"],
                "caution": "Broad SNI acceptance increases scan surface but is not, by itself, proof of relay usage.",
            }
        elif top["family"] == "tls_camouflage_relay":
            overall = {
                "label": "Plausible TLS-camouflaged relay/front",
                "confidence": top["confidence"],
                "caution": "This remains a family-level hypothesis, not a product-level identification.",
            }
        elif top["family"] in {"exposed_v2ray_transport", "direct_http_proxy", "quic_relay"}:
            overall = {
                "label": "Tunnel/proxy-like surface characteristics are present",
                "confidence": top["confidence"],
                "caution": "Interpretation depends on how specific the exposed semantics are.",
            }

    return {
        "hypotheses": hypotheses[:5],
        "top_family": top["family"] if top else None,
        "top_label": top["label"] if top else None,
        "overall_assessment": overall,
        "surface_risk": _surface_risk(findings),
        "hardening_hints": _hardening_hints(payload, findings),
    }


def render_text(inference: dict[str, Any]) -> str:
    hyps = inference.get("hypotheses", [])
    if not hyps:
        return ""
    top = hyps[0]
    pct = int(round(top["score"] * 100))
    lines = ["  Protocol hypotheses", f"  Top: {top['label']} ({pct}% / {top['confidence']})"]
    examples = ", ".join(top.get("examples", [])[:3])
    if examples:
        lines.append(f"  Examples: {examples}")
    if top.get("supports"):
        lines.append("  Supports:")
        for reason in top["supports"][:4]:
            lines.append(f"    - {reason}")
    if top.get("against"):
        lines.append("  Against:")
        for reason in top["against"][:3]:
            lines.append(f"    - {reason}")
    others = hyps[1:3]
    if others:
        lines.append("  Other plausible families:")
        for h in others:
            lines.append(f"    - {h['label']}: {int(round(h['score'] * 100))}% ({h['confidence']})")
    surface = inference.get("surface_risk")
    if surface:
        lines.append("  Surface risk:")
        lines.append(f"    {surface['label']} (score {surface['score']})")
        if surface.get("reasons"):
            lines.append(f"    because: {', '.join(surface['reasons'][:3])}")
    overall = inference.get("overall_assessment")
    if overall:
        lines.append("  Overall assessment:")
        lines.append(f"    {overall['label']} ({overall['confidence']})")
        if overall.get("caution"):
            lines.append(f"    note: {overall['caution']}")
    hints = inference.get("hardening_hints") or []
    if hints:
        lines.append("  Hardening hints:")
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
