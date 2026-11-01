"""Train the classifier:  python -m scripts.train [path/to/dataset.csv]

The CSV needs two columns: text, label  (1 = phishing/scam, 0 = legitimate).
"""
import sys
from pathlib import Path

from app.model import DATA_PATH, MODEL_PATH, train

if __name__ == "__main__":
    data = Path(sys.argv[1]) if len(sys.argv) > 1 else DATA_PATH
    report = train(data_path=data)
    print(f"Trained on {data}")
    for name in ("0", "1"):
        r = report[name]
        label = "legitimate" if name == "0" else "phishing/scam"
        print(f"  {label:14s} precision={r['precision']:.2f} recall={r['recall']:.2f} f1={r['f1-score']:.2f}")
    print(f"  accuracy       {report['accuracy']:.2f}  (hold-out 20%)")
    print(f"Saved model to {MODEL_PATH}")
