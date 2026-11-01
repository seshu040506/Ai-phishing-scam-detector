"""Rule-based analysis: URL heuristics and text red-flag detection.

Everything here is static analysis. The tool never opens, fetches or
resolves a URL, so analysing a malicious link is safe.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

BARE_TLDS = (
    "com|net|org|in|co|io|xyz|top|tk|ml|ga|cf|gq|click|work|zip|info|biz|"
    "online|site|link|support|live|shop|vip|icu|buzz|cn|ru"
)

URL_RE = re.compile(
    r"(?<![@\w])("
    r"(?:https?://|www\.)[^\s<>\"')\]]+"
    r"|(?:[a-z0-9-]+\.)+(?:" + BARE_TLDS + r")\b(?:/[^\s<>\"')\]]*)?"
    r")",
    re.IGNORECASE,
)

SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "work", "zip",
    "icu", "buzz", "vip", "support", "online", "site", "link", "live", "shop",
}
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "ow.ly",
    "rb.gy", "shorturl.at", "tiny.cc", "buff.ly", "rebrand.ly",
}
SECOND_LEVEL = {
    "co.uk", "co.in", "com.au", "com.br", "co.jp", "org.in", "net.in",
    "gov.in", "ac.in", "co.za", "com.sg", "co.nz",
}
SENSITIVE_WORDS = (
    "login", "signin", "verify", "secure", "update", "account", "confirm",
    "wallet", "kyc", "otp", "password", "billing", "refund", "reward", "claim",
)

# brand keyword -> registrable domains that really belong to it
BRANDS: dict[str, set[str]] = {
    "paypal": {"paypal.com", "paypal.me"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amazonaws.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com"},
    "apple": {"apple.com", "icloud.com"},
    "google": {"google.com", "google.co.in", "gmail.com", "youtube.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net"},
    "linkedin": {"linkedin.com"},
    "paytm": {"paytm.com"},
    "phonepe": {"phonepe.com"},
    "flipkart": {"flipkart.com"},
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "onlinesbi.com"},
    "hdfc": {"hdfcbank.com", "hdfc.com", "hdfclife.com"},
    "icici": {"icicibank.com", "icicilombard.com"},
    "axis": {"axisbank.com"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
}


def severity_for(weight: float) -> str:
    if weight >= 0.45:
        return "high"
    if weight >= 0.25:
        return "medium"
    return "low"


def noisy_or(weights: list[float]) -> float:
    """Combine independent signals: 1 - prod(1 - w)."""
    out = 1.0
    for w in weights:
        out *= 1.0 - max(0.0, min(1.0, w))
    return 1.0 - out


# --------------------------------------------------------------------- URLs
@dataclass
class UrlFlag:
    code: str
    weight: float
    detail: str


@dataclass
class UrlReport:
    url: str
    host: str
    start: int
    end: int
    flags: list[UrlFlag] = field(default_factory=list)

    @property
    def risk(self) -> float:
        return noisy_or([f.weight for f in self.flags])


def extract_urls(text: str) -> list[tuple[str, int, int]]:
    """Return (url, start, end) for every URL-like string in the text."""
    found = []
    for m in URL_RE.finditer(text):
        raw = m.group(1)
        stripped = raw.rstrip(".,;:!?")
        found.append((stripped, m.start(1), m.start(1) + len(stripped)))
    return found


def registrable_domain(host: str) -> str:
    labels = host.lower().strip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def analyze_url(url: str, start: int = 0, end: int = 0) -> UrlReport:
    explicit_scheme = re.match(r"(?i)^[a-z]+://", url) is not None
    parsable = url if explicit_scheme else "http://" + url
    flags: list[UrlFlag] = []

    try:
        parsed = urlparse(parsable)
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError:
        return UrlReport(url, "", start, end,
                         [UrlFlag("malformed", 0.3, "The link is malformed.")])

    if not host:
        return UrlReport(url, "", start, end,
                         [UrlFlag("malformed", 0.3, "The link has no valid host name.")])

    reg = registrable_domain(host)
    tld = host.rsplit(".", 1)[-1]
    labels = host.split(".")

    if _is_ip(host):
        flags.append(UrlFlag("ip_host", 0.5, "Uses a raw IP address instead of a domain name."))
    if "@" in url.split("//", 1)[-1].split("/", 1)[0]:
        flags.append(UrlFlag("at_symbol", 0.4, "Contains '@', which can hide the real destination."))
    if any(label.startswith("xn--") for label in labels):
        flags.append(UrlFlag("punycode", 0.4, "Uses punycode, often used for look-alike domains."))
    if reg in SHORTENERS:
        flags.append(UrlFlag("shortener", 0.25, "URL shortener hides the real destination."))
    if tld in SUSPICIOUS_TLDS:
        flags.append(UrlFlag("suspicious_tld", 0.3,
                             f"Uses the '.{tld}' domain ending, common in throwaway scam sites."))

    # brand impersonation: brand name appears in the host, but the domain isn't theirs
    tokens = set(re.split(r"[.\-_0-9]+", host))
    for brand, legit in BRANDS.items():
        mentioned = brand in tokens or (len(brand) >= 5 and brand in host)
        if mentioned and reg not in legit:
            flags.append(UrlFlag(
                "brand_impersonation", 0.55,
                f"Mentions '{brand}' but the real domain is '{reg}', not an official {brand} domain."))
            break

    if len(labels) - len(reg.split(".")) >= 3:
        flags.append(UrlFlag("many_subdomains", 0.2, "Unusually many sub-domains."))
    if host.count("-") >= 3:
        flags.append(UrlFlag("many_hyphens", 0.2, "Host name contains many hyphens."))
    digits = sum(c.isdigit() for c in host)
    if not _is_ip(host) and len(host) > 8 and digits / len(host) > 0.3:
        flags.append(UrlFlag("digit_heavy", 0.15, "Host name is mostly digits."))
    if len(url) >= 100:
        flags.append(UrlFlag("long_url", 0.1, "Very long URL."))
    if explicit_scheme and url.lower().startswith("http://"):
        flags.append(UrlFlag("no_tls", 0.15, "Uses plain http (no encryption)."))
    if port not in (None, 80, 443):
        flags.append(UrlFlag("odd_port", 0.15, f"Uses a non-standard port ({port})."))

    lowered = (parsed.path + "?" + (parsed.query or "") + " " + host).lower()
    hits = [w for w in SENSITIVE_WORDS if w in lowered]
    if hits:
        weight = 0.25 if len(hits) >= 2 else 0.15
        flags.append(UrlFlag("sensitive_words", weight,
                             "Contains words used in credential-theft links: " + ", ".join(hits[:4]) + "."))

    return UrlReport(url, host, start, end, flags)


# --------------------------------------------------------------- text signals
# Skip "do not share your OTP" style warnings, which are legitimate.
_NEG = r"(?<!not )(?<!never )(?<!n't )"

TEXT_RULES: list[tuple[str, str, float, str]] = [
    ("credential_request",
     r"\b" + _NEG + r"(?:send|share|enter|provide|confirm|verify|update|reply with|give)\b[^.\n]{0,40}?"
     r"\b(?:otp|one[- ]time (?:password|code)|password|passcode|pin|cvv|card number|card details|"
     r"ssn|social security|aadhaar|pan (?:card|number)|bank details|login details)\b",
     0.55, "Asks you to hand over a password, PIN, OTP, card or ID details."),
    ("payment_request",
     r"\b(?:gift ?cards?|bitcoin|crypto(?:currency)?|wire transfer|western union|money ?gram|"
     r"processing fee|registration fee|advance fee|customs fee|upi (?:pin|collect)|pay a small fee)\b",
     0.4, "Asks for an unusual payment (fees, gift cards, crypto, UPI PIN)."),
    ("prize_lure",
     r"\b(?:you(?:'ve| have)? won|winner|lottery|jackpot|lucky draw|congratulations|claim your|"
     r"free gift|prize)\b",
     0.35, "Promises a prize or reward you did not ask for."),
    ("job_scam",
     r"\b(?:work from home and earn|earn (?:up to )?[₹$]?\s?\d[\d,]*\s*(?:/|per )\s*(?:day|week|hour)|"
     r"part[- ]time job|guaranteed (?:income|returns|profit))\b",
     0.35, "Looks like a too-good-to-be-true job or investment offer."),
    ("threat",
     r"\b(?:suspend(?:ed)?|blocked|deactivated|terminated|locked|disconnected|legal action|arrest|"
     r"penalty|frozen|unauthori[sz]ed (?:access|activity|login|transaction))\b",
     0.30, "Threatens account loss or legal trouble to scare you."),
    ("kyc_bait",
     r"\b(?:re-?kyc|kyc|account verification|verify your account|"
     r"update your (?:details|information|account|pan|aadhaar))\b",
     0.30, "Uses a KYC / account-update pretext."),
    ("urgency",
     r"\b(?:urgent(?:ly)?|immediately|within \d+ (?:hours?|hrs?|minutes?|mins?)|act now|last chance|"
     r"final notice|expires? (?:today|soon)|right away|asap|tonight)\b",
     0.25, "Pressures you to act fast."),
    ("click_prompt",
     r"\b(?:click (?:here|the link|below)|tap (?:here|the link)|follow (?:this|the) link|open the link)\b",
     0.20, "Pushes you to click a link."),
    ("authority",
     r"\b(?:income tax|irs|customs|cyber ?crime|cbi|rbi|bank security|microsoft support|apple support)\b",
     0.15, "Claims to be an authority or official support team."),
    ("generic_greeting",
     r"\b(?:dear (?:customer|user|member|client|sir/?madam|account holder)|valued customer)\b",
     0.15, "Generic greeting instead of your name."),
]
_COMPILED = [(c, re.compile(p, re.IGNORECASE), w, d) for c, p, w, d in TEXT_RULES]


@dataclass
class TextFinding:
    category: str
    weight: float
    detail: str
    spans: list[tuple[int, int]]
    evidence: str


def analyze_text(text: str) -> list[TextFinding]:
    findings: list[TextFinding] = []
    for category, rx, weight, detail in _COMPILED:
        matches = list(rx.finditer(text))
        if not matches:
            continue
        spans = [(m.start(), m.end()) for m in matches[:5]]
        evidence = matches[0].group(0).strip()[:80]
        findings.append(TextFinding(category, weight, detail, spans, evidence))

    letters = [c for c in text if c.isalpha()]
    if len(letters) >= 20 and sum(c.isupper() for c in letters) / len(letters) > 0.4:
        findings.append(TextFinding("shouting", 0.10,
                                    "Mostly capital letters, a pressure tactic.", [], ""))
    m = re.search(r"!{2,}", text)
    if m:
        findings.append(TextFinding("exclamations", 0.10, "Repeated exclamation marks.",
                                    [(m.start(), m.end())], m.group(0)))
    return findings
