from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

SCAM = ("Dear customer, your SBI account will be suspended within 24 hours. "
        "Complete KYC immediately: http://sbi-kyc-update.xyz/login and share your OTP.")
SAFE = "Hi team, the sprint review is scheduled for tomorrow at 11 am. Please update your tickets."


def test_health():
    assert client.get("/api/health").json() == {"status": "ok"}


def test_scam_scores_high():
    data = client.post("/api/analyze", json={"text": SCAM}).json()
    assert data["verdict"] == "high"
    assert data["risk_score"] >= 60
    assert data["findings"] and data["urls"]


def test_safe_message_scores_low():
    data = client.post("/api/analyze", json={"text": SAFE}).json()
    assert data["verdict"] == "low"
    assert data["risk_score"] < 30


def test_legit_otp_message_is_not_high_risk():
    data = client.post("/api/analyze", json={
        "text": "Your OTP for Amazon login is 482913. It is valid for 10 minutes. Do not share this OTP with anyone."}).json()
    assert data["verdict"] != "high"


def test_link_only_input():
    data = client.post("/api/analyze", json={"text": "http://192.168.4.21/verify"}).json()
    assert data["ml_probability"] is None
    assert data["verdict"] in {"medium", "high"}


def test_blank_and_oversized_input_rejected():
    assert client.post("/api/analyze", json={"text": "   "}).status_code == 422
    assert client.post("/api/analyze", json={"text": "a" * 10_001}).status_code == 422


def test_homepage_served():
    r = client.get("/")
    assert r.status_code == 200 and "Phishing" in r.text
