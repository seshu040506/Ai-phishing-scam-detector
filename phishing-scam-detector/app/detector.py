"""Combines the ML model and rule-based signals into one explainable result."""
from __future__ import annotations

from .features import (analyze_text, analyze_url, extract_urls, noisy_or,
                       severity_for)
from .model import predict_proba

MIN_TEXT_CHARS = 15  # below this (after removing links) we trust rules over ML


def _verdict(score: float) -> str:
    if score < 0.30:
        return "low"
    if score < 0.60:
        return "medium"
    return "high"


def analyze(text: str) -> dict:
    urls = [analyze_url(u, s, e) for u, s, e in extract_urls(text)]
    findings = analyze_text(text)

    remaining = text
    for u in sorted(urls, key=lambda r: r.start, reverse=True):
        remaining = remaining[:u.start] + remaining[u.end:]
    has_prose = len(remaining.strip()) >= MIN_TEXT_CHARS

    ml = predict_proba(text) if has_prose else None
    rule_score = noisy_or([f.weight for f in findings] + [u.risk for u in urls])

    if ml is None:
        final = rule_score
    else:
        final = 0.5 * ml + 0.5 * rule_score
    # one strong signal (e.g. asking for your OTP) is enough to warrant a warning
    if any(severity_for(f.weight) == "high" for f in findings) or any(u.risk >= 0.5 for u in urls):
        final = max(final, 0.60)
    final = max(0.0, min(1.0, final))

    out_findings = [{
        "category": f.category,
        "severity": severity_for(f.weight),
        "detail": f.detail,
        "evidence": f.evidence,
        "spans": [{"start": s, "end": e} for s, e in f.spans],
    } for f in sorted(findings, key=lambda f: -f.weight)]

    out_urls = [{
        "url": u.url,
        "host": u.host,
        "risk": round(u.risk, 3),
        "severity": severity_for(u.risk) if u.flags else "none",
        "flags": [f.detail for f in u.flags],
        "span": {"start": u.start, "end": u.end},
    } for u in urls]

    return {
        "risk_score": round(final * 100),
        "verdict": _verdict(final),
        "ml_probability": None if ml is None else round(ml, 3),
        "rule_score": round(rule_score, 3),
        "findings": out_findings,
        "urls": out_urls,
    }
