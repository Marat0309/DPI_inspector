from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protocol_infer import infer_payload


def _base_findings() -> list[dict[str, str]]:
    return [
        {"id": "tls_cert", "severity": "ok", "observed": "public cert"},
        {"id": "http_fallback", "severity": "ok", "observed": "HTTP 200"},
        {"id": "random_path", "severity": "ok", "observed": "HTTP 404"},
        {"id": "tls_handshake", "severity": "ok", "observed": "TLSv1.3 / TLS_AES / h2"},
        {"id": "headers", "severity": "ok", "observed": "Server=nginx; HSTS=yes"},
        {"id": "alpn_profile", "severity": "ok", "observed": "h2=200, h1=200"},
        {"id": "http_connect", "severity": "ok", "observed": "CONNECT rejected (405)"},
        {"id": "ws_leak", "severity": "ok", "observed": "no WS"},
        {"id": "grpc_leak", "severity": "ok", "observed": "no gRPC"},
        {"id": "grpc_strict_probe", "severity": "ok", "observed": "no strict gRPC"},
    ]


def _payload(*extra: dict[str, str]) -> dict:
    return {
        "target": {"mode": "tcp"},
        "confidence": {"score": 100},
        "findings": _base_findings() + list(extra),
    }


def _score(result: dict, family: str) -> float | None:
    for item in result.get("hypotheses", []):
        if item["family"] == family:
            return float(item["score"])
    return None


def test_baseline_prefers_ordinary_web_without_broad_sni_signals() -> None:
    result = infer_payload(
        _payload(
            {"id": "foreign_sni", "severity": "ok", "observed": "no mismatch behavior"},
            {"id": "no_sni", "severity": "ok", "observed": "no cert without SNI"},
        )
    )
    assert result["top_family"] in {"ordinary_web_front", "no_clear_tunnel_evidence"}
    ordinary_score = _score(result, "ordinary_web_front")
    assert ordinary_score is not None
    assert ordinary_score >= 0.80


def test_broad_sni_pattern_reduces_ordinary_and_boosts_fronting_families() -> None:
    baseline = infer_payload(
        _payload(
            {"id": "foreign_sni", "severity": "ok", "observed": "no mismatch behavior"},
            {"id": "no_sni", "severity": "ok", "observed": "no cert without SNI"},
        )
    )
    broad_sni = infer_payload(
        _payload(
            {"id": "foreign_sni", "severity": "risk", "observed": "cert for foreign SNI"},
            {"id": "no_sni", "severity": "risk", "observed": "cert returned without SNI"},
        )
    )

    assert _score(broad_sni, "ordinary_web_front") < _score(baseline, "ordinary_web_front")
    assert _score(broad_sni, "broad_tls_front") is not None
    assert _score(broad_sni, "tls_camouflage_relay") is not None


def test_strict_grpc_risk_does_not_remove_ws_grpc_absence_bonus_for_tls_camouflage() -> None:
    strict_ok = infer_payload(
        _payload(
            {"id": "foreign_sni", "severity": "risk", "observed": "cert for foreign SNI"},
            {"id": "no_sni", "severity": "risk", "observed": "cert returned without SNI"},
            {"id": "grpc_strict_probe", "severity": "ok", "observed": "no strict gRPC"},
        )
    )
    strict_risk = infer_payload(
        _payload(
            {"id": "foreign_sni", "severity": "risk", "observed": "cert for foreign SNI"},
            {"id": "no_sni", "severity": "risk", "observed": "cert returned without SNI"},
            {"id": "grpc_strict_probe", "severity": "risk", "observed": "strict gRPC semantics"},
        )
    )

    assert _score(strict_ok, "tls_camouflage_relay") == _score(strict_risk, "tls_camouflage_relay")
