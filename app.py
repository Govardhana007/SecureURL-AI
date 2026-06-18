"""
app.py

Flask web app: user enters a URL, we extract the same 30 features used in
training, run the RandomForest model, and show a risk dashboard.
"""

import os

import joblib
import pandas as pd
from flask import Flask, render_template, request

from feature_extractor import extract_features, has_suspicious_words, LIVE_COMPUTABLE_FEATURES

MODEL_PATH = "model/phishing_model.pkl"

app = Flask(__name__)

if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(
        f"{MODEL_PATH} not found. Run `python train_model.py` first."
    )

model = joblib.load(MODEL_PATH)
print(f"Loaded model. Expecting {model.n_features_in_} features per prediction.")


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/predict", methods=["POST"])
def predict():
    url = request.form.get("url", "").strip()

    if not url:
        return render_template("index.html", error="Please enter a URL.")

    if " " in url or "." not in url:
        return render_template(
            "index.html",
            error="That doesn't look like a valid URL. Try something like https://example.com",
            url=url,
        )

    try:
        features = extract_features(url)
    except Exception as e:
        return render_template(
            "index.html", error=f"Couldn't parse that URL: {e}", url=url
        )

    if len(features) != model.n_features_in_:
        return render_template(
            "index.html",
            error=(
                f"Feature mismatch: extractor produced {len(features)} features, "
                f"model expects {model.n_features_in_}. Re-run train_model.py "
                "after any change to feature_extractor.py."
            ),
            url=url,
        )

    feature_df = pd.DataFrame([features], columns=LIVE_COMPUTABLE_FEATURES)
    prediction = model.predict(feature_df)[0]
    probability = max(model.predict_proba(feature_df)[0]) * 100

    suspicious_words = has_suspicious_words(url)

    if prediction == 1:
        result = "Legitimate Website"
        color = "green"
        risk_level = "Low Risk"
    else:
        result = "Phishing Website"
        color = "red"
        risk_level = "High Risk"

    return render_template(
        "index.html",
        result=result,
        score=round(probability, 2),
        url=url,
        color=color,
        risk_level=risk_level,
        suspicious_words=suspicious_words,
        feature_count=len(features),
    )


if __name__ == "__main__":
    # debug=True is fine for local development; turn off before deploying
    app.run(debug=True)
