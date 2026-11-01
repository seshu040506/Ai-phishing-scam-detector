from app.features import analyze_text, analyze_url, extract_urls, registrable_domain


def codes(report):
    return {f.code for f in report.flags}


def test_extract_urls_ignores_emails_and_trailing_punctuation():
    found = extract_urls("Mail me at john@gmail.com or visit https://example.com/path.")
    assert [u for u, _, _ in found] == ["https://example.com/path"]


def test_registrable_domain_handles_second_level_tlds():
    assert registrable_domain("www.hdfcbank.co.in") == "hdfcbank.co.in"
    assert registrable_domain("a.b.example.com") == "example.com"


def test_ip_host_is_flagged():
    assert "ip_host" in codes(analyze_url("http://192.168.4.21/verify"))


def test_brand_impersonation_flagged_but_real_domain_is_not():
    assert "brand_impersonation" in codes(analyze_url("https://secure-paypal-login.top/account"))
    assert "brand_impersonation" not in codes(analyze_url("https://www.paypal.com/signin"))


def test_shortener_and_suspicious_tld():
    assert "shortener" in codes(analyze_url("bit.ly/abc123"))
    assert "suspicious_tld" in codes(analyze_url("http://offers.win-prize.xyz"))


def test_clean_url_has_low_risk():
    assert analyze_url("https://www.amazon.in/orders").risk < 0.2


def test_credential_request_detected_but_otp_warning_is_not():
    bad = {f.category for f in analyze_text("Please share your OTP and password to continue")}
    ok = {f.category for f in analyze_text("Your OTP is 482913. Do not share this OTP with anyone.")}
    assert "credential_request" in bad
    assert "credential_request" not in ok


def test_spans_point_at_matched_text():
    text = "Act now or your account will be suspended"
    for f in analyze_text(text):
        for s, e in f.spans:
            assert text[s:e].strip()
