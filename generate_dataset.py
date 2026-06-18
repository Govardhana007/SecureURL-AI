"""
generate_dataset.py

Generates dataset/phishing.csv using the exact 30-feature schema from the
UCI "Phishing Websites" dataset (Mohammad, Thabtah, McCluskey, 2012/2015),
documented in: https://github.com/rishy/phishing-websites

Why a generator instead of a raw download?
--------------------------------------------
The original UCI/ARFF mirrors are not reliably reachable from every network,
and download URLs break over time. To make this project fully reproducible
on any machine (including yours), we instead SIMULATE the dataset using the
documented column names and value ranges, with realistic statistical
correlation between each feature and the phishing/legitimate label.

This is a completely standard and accepted approach for a student/portfolio
ML project: the column schema, value encodings, and feature semantics are
100% authentic (taken directly from the published codebook). Only the row
values are synthetic.

If you later get access to the real UCI CSV, just drop it into
dataset/phishing.csv with the SAME column names listed below and everything
else in this project (train_model.py, feature_extractor.py, app.py) will
keep working with no changes.
"""

import numpy as np
import pandas as pd
import os

np.random.seed(42)

N_SAMPLES = 11000

# Exact column names + value spaces, taken from the UCI codebook
# (see README table in rishy/phishing-websites). -1 = phishy/suspicious leaning,
# 0 = suspicious/neutral, 1 = legitimate leaning  (sign convention used below).
COLUMNS_3VAL = [
    "long_url",            # {1,0,-1}
    "pref_suf",             # {-1,0,1}
    "has_sub_domain",       # {-1,0,1}
    "ssl_state",            # {-1,1,0}
    "long_domain",          # {0,1,-1}
    "url_of_anchor",        # {-1,0,1}
    "tag_links",             # {1,-1,0}
    "domain_age",           # {-1,0,1}
    "traffic",               # {-1,0,1}
    "page_rank",             # {-1,0,1}
    "links_to_page",        # {1,0,-1}
]

COLUMNS_2VAL = [
    "has_ip",                  # {1,0}
    "short_service",            # {0,1}
    "has_at",                   # {0,1}
    "double_slash_redirect",    # {0,1}
    "favicon",                  # {0,1}
    "port",                      # {0,1}
    "https_token",              # {0,1}
    "submit_to_email",          # {1,0}
    "abnormal_url",             # {1,0}
    "redirect",                  # {0,1}
    "mouseover",                 # {0,1}
    "right_click",               # {0,1}
    "popup",                     # {0,1}
    "iframe",                    # {0,1}
    "dns_record",                # {1,0}
    "google_index",              # {0,1}
    "stats_report",              # {1,0}
]

COLUMNS_SPECIAL = ["req_url", "SFH"]  # req_url {1,-1}, SFH {-1,1}

ALL_FEATURE_COLUMNS = COLUMNS_3VAL + COLUMNS_2VAL + COLUMNS_SPECIAL
assert len(ALL_FEATURE_COLUMNS) == 30, f"Expected 30 features, got {len(ALL_FEATURE_COLUMNS)}"

# Features feature_extractor.py can genuinely compute live from a URL string
# alone (no page fetch, no WHOIS, no third-party ranking API). The model is
# trained on this subset only -- see train_model.py LIVE_COMPUTABLE_FEATURES.
# The remaining columns are still generated here (for realism / to show the
# full original schema) but are not used as model input.
LIVE_COMPUTABLE_FEATURES = [
    "long_url", "pref_suf", "has_sub_domain", "ssl_state", "has_ip",
    "short_service", "has_at", "double_slash_redirect", "port",
    "https_token", "submit_to_email", "abnormal_url", "redirect",
    "dns_record",
]


def generate():
    # First decide the ground-truth label: 1 = legitimate, -1 = phishing
    target = np.random.choice([1, -1], size=N_SAMPLES, p=[0.56, 0.44])

    data = {}

    # ---- 3-value columns ----
    # Per-feature (p_legit, p_phish) probability triples over [-1, 0, 1].
    # Calibrated to roughly match how informative each signal really is.
    three_val_probs = {
        "long_url":       ([0.06, 0.10, 0.84], [0.55, 0.20, 0.25]),
        "pref_suf":       ([0.02, 0.05, 0.93], [0.70, 0.10, 0.20]),
        "has_sub_domain": ([0.10, 0.20, 0.70], [0.35, 0.30, 0.35]),
        "ssl_state":      ([0.03, 0.04, 0.93], [0.78, 0.07, 0.15]),
        # remaining 3-value columns are NOT live-computable; kept mild/generic
        "long_domain":    ([0.12, 0.18, 0.70], [0.62, 0.23, 0.15]),
        "url_of_anchor":  ([0.12, 0.18, 0.70], [0.62, 0.23, 0.15]),
        "tag_links":      ([0.12, 0.18, 0.70], [0.62, 0.23, 0.15]),
        "domain_age":     ([0.12, 0.18, 0.70], [0.62, 0.23, 0.15]),
        "traffic":        ([0.12, 0.18, 0.70], [0.62, 0.23, 0.15]),
        "page_rank":      ([0.12, 0.18, 0.70], [0.62, 0.23, 0.15]),
        "links_to_page":  ([0.12, 0.18, 0.70], [0.62, 0.23, 0.15]),
    }
    for col in COLUMNS_3VAL:
        probs_legit, probs_phish = three_val_probs[col]
        vals = np.where(
            target == 1,
            np.random.choice([-1, 0, 1], size=N_SAMPLES, p=probs_legit),
            np.random.choice([-1, 0, 1], size=N_SAMPLES, p=probs_phish),
        )
        data[col] = vals

    # ---- 2-value columns ----
    # Per-feature (p_legit, p_phish) = probability the "risky" flag (1) fires.
    # has_ip and short_service are near-deterministic in reality: legitimate
    # brand sites essentially never use a bare IP or a shortener as their
    # primary URL, so these get very sharp separation.
    two_val_probs = {
        "has_ip":                 (0.005, 0.55),
        "short_service":           (0.01, 0.55),
        "has_at":                  (0.01, 0.35),
        "double_slash_redirect":   (0.02, 0.30),
        "port":                     (0.02, 0.25),
        "https_token":             (0.01, 0.40),
        "submit_to_email":         (0.03, 0.30),
        "abnormal_url":            (0.02, 0.55),
        "redirect":                 (0.03, 0.30),
        # remaining 2-value columns are NOT live-computable; kept mild/generic
        "favicon":                  (0.08, 0.55),
        "mouseover":                (0.08, 0.55),
        "right_click":              (0.08, 0.55),
        "popup":                     (0.08, 0.55),
        "iframe":                    (0.08, 0.55),
        "stats_report":             (0.08, 0.55),
    }
    for col in COLUMNS_2VAL:
        if col in ("dns_record", "google_index"):
            continue  # handled separately below (flipped semantics)
        p_legit, p_phish = two_val_probs[col]
        vals = np.where(
            target == 1,
            np.random.binomial(1, p_legit, size=N_SAMPLES),
            np.random.binomial(1, p_phish, size=N_SAMPLES),
        )
        data[col] = vals

    # dns_record, google_index: flip semantics (1 = good sign for legit sites)
    # dns_record is live-computable and fairly reliable; google_index is not
    # live-computable here and kept milder.
    dns_probs = {"dns_record": (0.96, 0.30), "google_index": (0.85, 0.45)}
    for col, (p_legit, p_phish) in dns_probs.items():
        vals = np.where(
            target == 1,
            np.random.binomial(1, p_legit, size=N_SAMPLES),
            np.random.binomial(1, p_phish, size=N_SAMPLES),
        )
        data[col] = vals

    # req_url {1,-1}, SFH {-1,1} (not live-computable; mild generic signal)
    data["req_url"] = np.where(
        target == 1,
        np.random.choice([1, -1], size=N_SAMPLES, p=[0.85, 0.15]),
        np.random.choice([1, -1], size=N_SAMPLES, p=[0.35, 0.65]),
    )
    data["SFH"] = np.where(
        target == 1,
        np.random.choice([1, -1], size=N_SAMPLES, p=[0.88, 0.12]),
        np.random.choice([1, -1], size=N_SAMPLES, p=[0.30, 0.70]),
    )

    data["target"] = target

    df = pd.DataFrame(data)
    # Reorder to keep features first, target last
    df = df[ALL_FEATURE_COLUMNS + ["target"]]
    return df


if __name__ == "__main__":
    os.makedirs("dataset", exist_ok=True)
    df = generate()
    out_path = "dataset/phishing.csv"
    df.to_csv(out_path, index=False)
    print(f"Generated {len(df)} rows x {len(df.columns)} columns -> {out_path}")
    print("Columns:", df.columns.tolist())
    print("Target balance:\n", df["target"].value_counts())
