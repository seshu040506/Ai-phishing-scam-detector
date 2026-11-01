# AI Phishing & Scam Detector

A web tool that scores SMS messages, emails and links for phishing or scam risk, and **explains why**. It highlights the exact phrases and link features that raised the score, so you can see the reasoning instead of trusting a black box.

**Stack:** Python, FastAPI, scikit-learn (TF-IDF + logistic regression), vanilla HTML/JS front end.

## Features

- **Hybrid detection.** An NLP model estimates scam probability from the wording, while transparent rules catch known tricks. The two are combined into a 0-100 risk score.
- **Explainable output.** Every finding lists a category, severity and the matched text. The message is shown with the suspicious parts highlighted.
- **Link analysis (static, never fetched).** Flags raw IP hosts, `@` tricks, punycode look-alikes, URL shorteners, throwaway domain endings, brand impersonation (e.g. `secure-paypal-login.top`), odd ports, and credential-bait keywords.
- **Social-engineering patterns.** Urgency, threats, prize lures, KYC bait, fake fees, OTP/PIN/password requests, job and investment scams. Includes India-specific patterns (KYC, UPI, Aadhaar, PAN).
- **Avoids a common false positive.** "Do not share this OTP with anyone" is treated as a legitimate warning, not as a request for your OTP.
- **REST API** with interactive docs at `/docs`, plus a demo UI at `/`.

## Quick start

```bash
git clone https://github.com/<your-username>/phishing-scam-detector.git
cd phishing-scam-detector

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt

uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000. The model trains automatically on first start (a few seconds). To retrain manually: `python -m scripts.train`.

## API

`POST /api/analyze`

```json
{ "text": "Dear customer, your SBI account will be suspended. Complete KYC: http://sbi-kyc-update.xyz/login" }
```

Response (shortened):

```json
{
  "risk_score": 94,
  "verdict": "high",
  "ml_probability": 0.97,
  "rule_score": 0.93,
  "findings": [
    { "category": "kyc_bait", "severity": "medium", "detail": "Uses a KYC / account-update pretext.",
      "evidence": "KYC", "spans": [{ "start": 66, "end": 69 }] }
  ],
  "urls": [
    { "url": "http://sbi-kyc-update.xyz/login", "risk": 0.88, "severity": "high",
      "flags": ["Mentions 'sbi' but the real domain is 'sbi-kyc-update.xyz', not an official sbi domain."] }
  ]
}
```

`GET /api/health` returns `{"status": "ok"}`.

## How it works

```
text ──► extract links ──► URL heuristics ─────────────┐
  │                                                    ├─► combine ─► score 0-100 + findings
  ├────► regex red-flag rules (urgency, OTP, fees...) ─┤
  └────► TF-IDF (1-2 grams) + logistic regression ─────┘
```

- **Rules and links** are combined with a noisy-OR, so several weak signals add up and one strong signal (such as asking for an OTP) can raise the alarm on its own.
- **Final score** is 50% model probability + 50% rule score. For link-only input there is no text for the model, so the rule score is used alone.
- **Verdict:** below 30 low, 30-59 medium, 60 and above high.

## Project structure

```
app/
  main.py        FastAPI app and routes
  detector.py    combines model and rules into one result
  features.py    URL heuristics and text red-flag rules
  model.py       training, loading and prediction
scripts/
  train.py                 train the model
  generate_sample_data.py  rebuild the demo dataset
data/sample_dataset.csv    demo dataset (synthetic)
static/index.html          demo UI
tests/                     pytest suite
.github/workflows/ci.yml   runs tests on every push
```

## Tests

```bash
pytest -q
```

## Limitations (please read)

- The bundled dataset is **synthetic and small** (200 template-based messages), so the accuracy printed by `scripts.train` reflects the templates, **not real-world performance**. It exists so the project runs out of the box.
- For real use, retrain on a public dataset: put it in a CSV with columns `text,label` (1 = phishing/scam, 0 = legitimate) and run `python -m scripts.train path/to/data.csv`. Check each dataset's license first. Candidates include the UCI SMS Spam Collection and public phishing-email corpora.
- Rules are English-centric and can be evaded by a determined attacker. A low score does not prove a message is safe.
- Links are analysed as text only. There is no live reputation lookup (Google Safe Browsing, PhishTank, VirusTotal).

## Roadmap

- Train on real datasets and report precision/recall on a proper held-out set
- Reputation lookups via Safe Browsing / PhishTank APIs
- Email header analysis (SPF, DKIM, mismatched Reply-To)
- Support for Telugu and Hindi messages
- Browser extension and Docker image

## License

MIT, see [LICENSE](LICENSE).
