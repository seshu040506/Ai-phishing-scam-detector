"""Text classifier: TF-IDF + logistic regression."""
from __future__ import annotations

import csv
import re
from functools import lru_cache
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from .features import URL_RE

ROOT = Path(__file__).resolve().parent.parent
DATA_PATH = ROOT / "data" / "sample_dataset.csv"
MODEL_PATH = ROOT / "models" / "model.joblib"


def preprocess(text: str) -> str:
    """Lower-case and replace links with a token so the model learns
    'a link is present' instead of memorising particular URLs."""
    text = URL_RE.sub(" urltoken ", text)
    return text.lower()


def load_dataset(path: Path = DATA_PATH) -> tuple[list[str], list[int]]:
    texts, labels = [], []
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            texts.append(row["text"])
            labels.append(int(row["label"]))  # 1 = phishing/scam, 0 = legitimate
    return texts, labels


def build_pipeline() -> Pipeline:
    return Pipeline([
        ("tfidf", TfidfVectorizer(preprocessor=preprocess, ngram_range=(1, 2),
                                  sublinear_tf=True, strip_accents="unicode")),
        ("clf", LogisticRegression(max_iter=1000, class_weight="balanced")),
    ])


def train(data_path: Path = DATA_PATH, model_path: Path = MODEL_PATH,
          test_size: float = 0.2, seed: int = 42) -> dict:
    texts, labels = load_dataset(data_path)
    x_tr, x_te, y_tr, y_te = train_test_split(
        texts, labels, test_size=test_size, random_state=seed, stratify=labels)
    pipe = build_pipeline().fit(x_tr, y_tr)
    report = classification_report(y_te, pipe.predict(x_te), output_dict=True, zero_division=0)

    pipe.fit(texts, labels)  # final model uses all data
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipe, model_path)
    return report


@lru_cache(maxsize=1)
def get_model() -> Pipeline:
    """Load the saved model, training it first if it does not exist yet."""
    if not MODEL_PATH.exists():
        train()
    return joblib.load(MODEL_PATH)


def predict_proba(text: str) -> float:
    """Probability (0-1) that the text is phishing/scam."""
    return float(get_model().predict_proba([text])[0][1])
