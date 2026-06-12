"""Pure-logic unit tests — no DB, no network, no ML stack required.

Run:  pytest -q
"""
from imposter_shield.core import classifier, scoring
from imposter_shield.reporting import claim_router
from imposter_shield.security.net import is_public_url, validate_public_url, UnsafeURLError

import pytest


# --------------------------------------------------------------- classifier

def test_financial_scam_detected():
    c = classifier.classify("Send me crypto and I'll double your money, guaranteed returns!")
    assert c.financial_solicitation > 0.5
    assert c.primary_harm == "financial_scam"
    assert "financial_scam" in c.matched


def test_defamation_detected():
    c = classifier.classify("I am a scammer and you should not trust me.")
    assert c.defamation > 0.5
    assert c.primary_harm == "defamation"


def test_benign_text_flags_nothing():
    c = classifier.classify("Photographer and educator. DMs open for collaborations.")
    assert c.financial_solicitation == 0.0
    assert c.defamation == 0.0
    assert c.primary_harm is None


# ----------------------------------------------------------------- scoring

def test_watermark_hit_forces_high_score():
    d = scoring.fuse(scoring.SignalInputs(face=0.2, text=0.1, watermark_hit=True))
    assert d.score >= 0.40            # boost applied
    assert any("watermark" in n for n in d.notes)


def test_strong_face_and_text_enters_review():
    d = scoring.fuse(scoring.SignalInputs(face=0.97, text=0.95,
                                          account_age_days=5, followers=10, following=2000,
                                          network_overlap=0.5),
                     review_threshold=0.90)
    assert d.enters_review is True


def test_score_is_bounded():
    d = scoring.fuse(scoring.SignalInputs(face=1.0, text=1.0, watermark_hit=True))
    assert 0.0 <= d.score <= 1.0


# ------------------------------------------------------------- claim_router

def test_financial_harm_routes_to_critical_fraud_report():
    recs = claim_router.route(claim_router.CaseSignals(
        confidence=0.95, harm_kinds={"financial_scam"}))
    top = recs[0]
    assert top.channel == "fraud_report"
    assert top.priority == "critical"
    assert top.requires_human is True


def test_defamation_routes_to_defamation_notice_not_dmca():
    recs = claim_router.route(claim_router.CaseSignals(
        confidence=0.9, harm_kinds={"defamation"}))
    channels = {r.channel for r in recs}
    assert "defamation_notice" in channels
    assert "dmca" not in channels        # DMCA is copyright-only


def test_baseline_always_offers_impersonation_report():
    recs = claim_router.route(claim_router.CaseSignals(confidence=0.5))
    assert any(r.channel == "impersonation_report" for r in recs)


# ----------------------------------------------------------------- SSRF net

@pytest.mark.parametrize("url", [
    "http://localhost/admin",
    "http://127.0.0.1:5432/",
    "http://169.254.169.254/latest/meta-data/",
    "file:///etc/passwd",
    "gopher://internal/",
])
def test_blocks_unsafe_urls(url):
    assert is_public_url(url) is False
    with pytest.raises(UnsafeURLError):
        validate_public_url(url)


def test_allows_public_https():
    # example.com resolves to a public IP; should pass the guard.
    assert is_public_url("https://example.com/profile") is True
