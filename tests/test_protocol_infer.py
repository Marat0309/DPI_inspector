from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protocol_infer import infer_payload


# ── Helpers ───────────────────────────────────────────────────

def _base_findings() -> list[dict]:
    return [
        {"id": "tls_cert",          "severity": "ok",     "observed": "public cert"},
        {"id": "http_fallback",     "severity": "ok",     "observed": "HTTP 200"},
        {"id": "random_path",       "severity": "ok",     "observed": "HTTP 404"},
        {"id": "tls_handshake",     "severity": "ok",     "observed": "TLSv1.3 / TLS_AES / h2"},
        {"id": "headers",           "severity": "ok",     "observed": "Server=nginx; HSTS=yes"},
        {"id": "alpn_profile",      "severity": "ok",     "observed": "h2=200, h1=200"},
        {"id": "http_connect",      "severity": "ok",     "observed": "CONNECT rejected (405)"},
        {"id": "ws_leak",           "severity": "ok",     "observed": "no WS"},
        {"id": "grpc_leak",         "severity": "ok",     "observed": "no gRPC"},
        {"id": "grpc_strict_probe", "severity": "ok",     "observed": "no strict gRPC"},
    ]


def _payload(*extra: dict, mode: str = "tcp", lang: str = "en") -> dict:
    """Build a payload; extra findings override base ones with the same id."""
    return {
        "target": {"mode": mode},
        "confidence": {"score": 100},
        "findings": _base_findings() + list(extra),
        "lang": lang,
    }


def _score(result: dict, family: str) -> float | None:
    for item in result.get("hypotheses", []):
        if item["family"] == family:
            return float(item["score"])
    return None


# ── Existing tests (unchanged) ────────────────────────────────

def test_baseline_prefers_ordinary_web_without_broad_sni_signals() -> None:
    result = infer_payload(
        _payload(
            {"id": "foreign_sni",   "severity": "ok", "observed": "no mismatch behavior"},
            {"id": "no_sni",        "severity": "ok", "observed": "no cert without SNI"},
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
            {"id": "no_sni",      "severity": "ok", "observed": "no cert without SNI"},
        )
    )
    broad_sni = infer_payload(
        _payload(
            {"id": "foreign_sni", "severity": "risk", "observed": "cert for foreign SNI"},
            {"id": "no_sni",      "severity": "risk", "observed": "cert returned without SNI"},
        )
    )

    assert _score(broad_sni, "ordinary_web_front") < _score(baseline, "ordinary_web_front")
    assert _score(broad_sni, "broad_tls_front") is not None
    assert _score(broad_sni, "tls_camouflage_relay") is not None


def test_strict_grpc_risk_does_not_remove_ws_grpc_absence_bonus_for_tls_camouflage() -> None:
    strict_ok = infer_payload(
        _payload(
            {"id": "foreign_sni",       "severity": "risk", "observed": "cert for foreign SNI"},
            {"id": "no_sni",            "severity": "risk", "observed": "cert returned without SNI"},
            {"id": "grpc_strict_probe", "severity": "ok",   "observed": "no strict gRPC"},
        )
    )
    strict_risk = infer_payload(
        _payload(
            {"id": "foreign_sni",       "severity": "risk", "observed": "cert for foreign SNI"},
            {"id": "no_sni",            "severity": "risk", "observed": "cert returned without SNI"},
            {"id": "grpc_strict_probe", "severity": "risk", "observed": "strict gRPC semantics"},
        )
    )

    assert _score(strict_ok, "tls_camouflage_relay") == _score(strict_risk, "tls_camouflage_relay")


# ── Transport exposure ────────────────────────────────────────
# These tests use minimal payloads (no clean-web baseline) because a server
# with exposed WS/gRPC would not typically present a full ordinary-web profile.

def _minimal_payload(*findings: dict, mode: str = "tcp", lang: str = "en") -> dict:
    """Payload with only the provided findings — no clean-web baseline."""
    return {
        "target": {"mode": mode},
        "confidence": {"score": 100},
        "findings": list(findings),
        "lang": lang,
    }


def test_ws_exposed_scores_exposed_v2ray_family() -> None:
    result = infer_payload(
        _minimal_payload({"id": "ws_leak", "severity": "risk", "observed": "WS upgrade 101"})
    )
    score = _score(result, "exposed_v2ray_transport")
    assert score is not None and score >= 0.30, f"exposed_v2ray score={score}"
    assert result["top_family"] == "exposed_v2ray_transport"


def test_grpc_exposed_scores_exposed_v2ray_family() -> None:
    result = infer_payload(
        _minimal_payload({"id": "grpc_leak", "severity": "risk", "observed": "gRPC 200"})
    )
    score = _score(result, "exposed_v2ray_transport")
    assert score is not None and score >= 0.30, f"exposed_v2ray score={score}"
    assert result["top_family"] == "exposed_v2ray_transport"


def test_connect_accepted_scores_direct_proxy() -> None:
    result = infer_payload(
        _minimal_payload(
            {"id": "http_connect", "severity": "risk", "observed": "CONNECT accepted (200)"}
        )
    )
    score = _score(result, "direct_http_proxy")
    assert score is not None and score >= 0.30, f"direct_http_proxy score={score}"
    assert result["top_family"] in {"direct_http_proxy", "http_tunneling_front"}


def test_ws_exposed_raises_score_relative_to_clean_baseline() -> None:
    """Confirm WS exposure lowers ordinary_web_front relative to a clean baseline."""
    clean = infer_payload(_payload())
    exposed = infer_payload(
        _payload({"id": "ws_leak", "severity": "risk", "observed": "WS upgrade 101"})
    )
    clean_score = _score(clean, "ordinary_web_front") or 0.0
    exposed_score = _score(exposed, "ordinary_web_front") or 0.0
    assert exposed_score < clean_score, (
        f"ws_exposed should lower ordinary_web_front: {clean_score} → {exposed_score}"
    )
    # and it should add a meaningful exposed_v2ray score
    assert (_score(exposed, "exposed_v2ray_transport") or 0.0) >= 0.30


# ── QUIC / UDP mode ───────────────────────────────────────────

def test_quic_mode_scores_quic_relay() -> None:
    result = infer_payload(
        _minimal_payload(
            {"id": "quic_handshake", "severity": "ok", "observed": "QUIC handshake OK"},
            mode="udp",
        )
    )
    score = _score(result, "quic_relay")
    assert score is not None and score >= 0.18, f"quic_relay score={score}"


def test_quic_mode_top_family_is_quic_relay() -> None:
    result = infer_payload(
        _minimal_payload(
            {"id": "quic_handshake", "severity": "ok", "observed": "QUIC handshake OK"},
            {"id": "quic_cert",      "severity": "ok", "observed": "public cert"},
            {"id": "raw_udp",        "severity": "ok", "observed": "no junk response"},
            mode="udp",
        )
    )
    assert result["top_family"] == "quic_relay"


# ── cert_san signals ──────────────────────────────────────────

def test_cert_san_match_raises_ordinary_web_front() -> None:
    baseline = infer_payload(_payload())
    san_match = infer_payload(
        _payload({"id": "cert_san", "severity": "ok", "observed": "SAN covers example.com"})
    )
    base_score = _score(baseline, "ordinary_web_front") or 0.0
    match_score = _score(san_match, "ordinary_web_front") or 0.0
    assert match_score >= base_score, (
        f"cert_san_match should raise ordinary_web_front: {base_score} → {match_score}"
    )


def test_cert_san_mismatch_lowers_ordinary_web_front() -> None:
    baseline = infer_payload(_payload())
    san_mismatch = infer_payload(
        _payload({"id": "cert_san", "severity": "notice", "observed": "SNI not in SAN"})
    )
    base_score = _score(baseline, "ordinary_web_front") or 0.0
    mismatch_score = _score(san_mismatch, "ordinary_web_front") or 0.0
    assert mismatch_score < base_score, (
        f"cert_san_mismatch should lower ordinary_web_front: {base_score} → {mismatch_score}"
    )


def test_cert_san_mismatch_raises_tls_camouflage_relay() -> None:
    # Need broad-SNI context for tls_camouflage_relay to be present at all
    broad = _payload(
        {"id": "mismatched_sni", "severity": "risk", "observed": "cert for foreign SNI"},
        {"id": "no_sni",         "severity": "risk", "observed": "cert returned without SNI"},
    )
    broad_with_san = _payload(
        {"id": "mismatched_sni", "severity": "risk", "observed": "cert for foreign SNI"},
        {"id": "no_sni",         "severity": "risk", "observed": "cert returned without SNI"},
        {"id": "cert_san",       "severity": "notice", "observed": "SNI not in SAN"},
    )
    score_without = _score(infer_payload(broad), "tls_camouflage_relay") or 0.0
    score_with = _score(infer_payload(broad_with_san), "tls_camouflage_relay") or 0.0
    assert score_with > score_without, (
        f"cert_san_mismatch should raise tls_camouflage_relay: {score_without} → {score_with}"
    )


# ── h2_settings signals ───────────────────────────────────────

def test_h2_settings_unusual_lowers_ordinary_web_front() -> None:
    baseline = infer_payload(_payload())
    unusual = infer_payload(
        _payload({"id": "h2_settings", "severity": "notice", "observed": "MAX_CONCURRENT_STREAMS=1000"})
    )
    base_score = _score(baseline, "ordinary_web_front") or 0.0
    unusual_score = _score(unusual, "ordinary_web_front") or 0.0
    assert unusual_score < base_score, (
        f"h2_settings_unusual should lower ordinary_web_front: {base_score} → {unusual_score}"
    )


# ── Default-cert TLS front ────────────────────────────────────

def test_default_cert_foreign_sni_scores_default_cert_front() -> None:
    result = infer_payload(
        _payload(
            {
                "id": "mismatched_sni",
                "severity": "risk",
                "observed": "different cert on foreign SNI",
                "returned_relation": "different-cert",
            }
        )
    )
    score = _score(result, "default_cert_tls_front")
    assert score is not None and score >= 0.18, (
        f"default_cert_tls_front should have a meaningful score; got {score}"
    )


# ── Surface risk ──────────────────────────────────────────────

def test_surface_risk_ws_exposed_is_at_least_medium() -> None:
    result = infer_payload(
        _payload({"id": "ws_leak", "severity": "risk", "observed": "WS upgrade 101"})
    )
    risk = result["surface_risk"]
    assert risk["label"] in {"medium", "high"}, f"Expected medium/high, got {risk['label']}"
    assert risk["score"] >= 3


def test_surface_risk_clean_ordinary_site_is_low() -> None:
    result = infer_payload(_payload())
    risk = result["surface_risk"]
    assert risk["label"] == "low", f"Expected low, got {risk['label']}"


# ── Edge cases ────────────────────────────────────────────────

def test_empty_findings_does_not_crash() -> None:
    result = infer_payload({"target": {"mode": "tcp"}, "confidence": {"score": 100}, "findings": []})
    assert isinstance(result, dict)
    assert "hypotheses" in result
    assert "surface_risk" in result


def test_unknown_finding_ids_do_not_affect_score() -> None:
    baseline = infer_payload(_payload())
    with_junk = infer_payload(
        _payload(
            {"id": "nonexistent_probe_xyz", "severity": "risk", "observed": "whatever"},
            {"id": "another_unknown_id",    "severity": "ok",   "observed": "data"},
        )
    )
    # Scores should be identical since unknown IDs are never consulted
    for family in ("ordinary_web_front", "exposed_v2ray_transport"):
        b = _score(baseline, family)
        w = _score(with_junk, family)
        assert b == w, f"{family}: baseline={b} but with_junk={w}"


def test_all_hypothesis_scores_are_in_unit_range() -> None:
    payloads = [
        _payload(),
        _payload({"id": "ws_leak",      "severity": "risk", "observed": "WS 101"}),
        _payload({"id": "grpc_leak",    "severity": "risk", "observed": "gRPC"}),
        _payload({"id": "http_connect", "severity": "risk", "observed": "CONNECT accepted"}),
        _payload(
            {"id": "mismatched_sni", "severity": "risk", "observed": "foreign cert"},
            {"id": "no_sni",         "severity": "risk", "observed": "cert no SNI"},
        ),
    ]
    for p in payloads:
        result = infer_payload(p)
        for h in result.get("hypotheses", []):
            s = h["score"]
            assert 0.0 <= s <= 1.0, f"Score out of range for {h['family']}: {s}"


# ── Localisation ──────────────────────────────────────────────

def test_lang_ru_does_not_crash_and_produces_russian_label() -> None:
    result = infer_payload(_payload(lang="ru"))
    assert isinstance(result, dict)
    top_label = result.get("top_label", "")
    # Ordinary web front in Russian contains a Cyrillic character
    assert any(ord(c) > 127 for c in top_label), (
        f"Expected Russian (Cyrillic) label, got: {top_label!r}"
    )


def test_lang_ru_surface_risk_reasons_are_russian() -> None:
    result = infer_payload(
        _payload(
            {"id": "ws_leak", "severity": "risk", "observed": "WS upgrade 101"},
            lang="ru",
        )
    )
    reasons = result["surface_risk"]["reasons"]
    assert len(reasons) > 0
    # At least one reason should contain a Cyrillic character
    assert any(any(ord(c) > 127 for c in r) for r in reasons), (
        f"Expected Russian reasons, got: {reasons}"
    )
