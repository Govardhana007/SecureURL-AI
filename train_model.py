"""
train_model.py

Trains a RandomForestClassifier on dataset/phishing.csv and saves it to
model/phishing_model.pkl. Run this once before starting app.py (and again
any time you regenerate or replace the dataset).
"""

import os

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

from feature_extractor import LIVE_COMPUTABLE_FEATURES as FEATURE_ORDER

DATA_PATH = "dataset/phishing.csv"
MODEL_PATH = "model/phishing_model.pkl"


def main():
    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(
            f"{DATA_PATH} not found. Run `python generate_dataset.py` first "
            "(or place your own phishing.csv with matching columns there)."
        )

    df = pd.read_csv(DATA_PATH)

    target_col = df.columns[-1]
    X = df[FEATURE_ORDER]  # restrict to features we can honestly compute live
    y = df[target_col]

    # Make sure the dataset's feature columns line up with what
    # feature_extractor.py will produce at prediction time. If they don't,
    # fail loudly now instead of getting a confusing shape error later.
    if list(X.columns) != FEATURE_ORDER:
        raise ValueError(
            "Dataset columns do not match feature_extractor.FEATURE_ORDER.\n"
            f"Dataset columns:   {list(X.columns)}\n"
            f"Extractor expects: {FEATURE_ORDER}\n"
            "Fix one or the other so they match exactly (same names, same order)."
        )

    print(f"Loaded {len(df)} rows, {X.shape[1]} features.")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=300,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)

    train_acc = model.score(X_train, y_train)
    test_acc = model.score(X_test, y_test)
    print(f"Train accuracy: {train_acc:.4f}")
    print(f"Test accuracy:  {test_acc:.4f}")
    print()
    print(classification_report(y_test, model.predict(X_test)))

    os.makedirs("model", exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"Model saved to {MODEL_PATH}")
    print(f"n_features_in_ = {model.n_features_in_}")


if __name__ == "__main__":
    main()
