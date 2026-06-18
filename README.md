# SecureURL AI — Phishing Website Detector

An AI-powered web app that analyzes a URL and predicts whether it's likely a
phishing site or a legitimate one, using a Random Forest classifier trained
on URL/domain-structure features.

## What makes this different from a typical tutorial version

A common mistake in small phishing-detector projects (including an earlier
draft of this one) is training a model on the classic UCI "Phishing
Websites" feature schema, but then writing a feature extractor that invents
unrelated numbers (raw URL length, dot counts, slash counts) instead of the
actual named features the model was trained on. The model runs without
error, but its predictions are meaningless, because column 7 means
"Links_in_tags" to the model and "slash count" to the extractor.

This version fixes that end to end:

1. **`generate_dataset.py`** builds a dataset using the *exact* named
   columns and value ranges from the published UCI/Mohammad-Thabtah-
   McCluskey schema (documented in the `rishy/phishing-websites` GitHub
   repo's codebook), with realistic statistical correlation between each
   feature and the phishing/legitimate label.
2. **`feature_extractor.py`** computes a *subset of those same named
   columns* — specifically, only the ones that can be honestly computed
   from a URL string alone, in real time, with no page fetch, no WHOIS
   lookup, and no third-party ranking API. See `LIVE_COMPUTABLE_FEATURES`.
3. **`train_model.py`** trains only on that same honest subset, and fails
   loudly if the dataset and extractor columns ever drift out of sync.
4. **`app.py`** ties it together with input validation and a dashboard.

## Why a generated dataset instead of a downloaded one?

The original UCI/ARFF mirrors aren't reliably reachable from every network
and the download URLs change over time. Generating the dataset locally from
the documented schema makes the whole project reproducible on any machine
with no external dependency at setup time. The column names, value
encodings, and feature semantics are taken directly from the published
codebook — only the row values are synthetic, calibrated so each feature's
correlation with the label roughly matches how informative that signal
really is in practice (e.g. `has_ip` is a near-deterministic phishing
signal; `has_sub_domain` alone is weak and noisy).

If you get access to a real phishing dataset later, just replace
`dataset/phishing.csv` with one that has the same column names (see
`ALL_FEATURE_COLUMNS` in `generate_dataset.py`) and rerun `train_model.py`.
Nothing else needs to change.

## Why only 14 of the original 30 features?

The full UCI schema includes features like domain registration length, web
traffic rank, Google PageRank, and whether a page disables right-click —
all of which require fetching the live page HTML, querying WHOIS, or
calling a third-party ranking API. Training on all 30 but only being able
to honestly compute ~14 of them in production (defaulting the rest to a
constant placeholder) actively hurts accuracy, because the model learns to
trust those placeholder values as if they were real signal.

This project instead trains the model on exactly the features it can
compute, so its confidence score reflects real evidence:

| Feature | What it checks |
|---|---|
| `long_url` | Is the URL unusually long? |
| `pref_suf` | Does the host contain a hyphen (e.g. `secure-paypal-login`)? |
| `has_sub_domain` | Excessive subdomain nesting |
| `ssl_state` | Is the connection HTTPS? |
| `has_ip` | Is a raw IP address used instead of a domain name? |
| `short_service` | Is a URL shortener (bit.ly, tinyurl, etc.) used? |
| `has_at` | Does the URL contain an `@` (used to obscure the real host)? |
| `double_slash_redirect` | Suspicious `//` redirect trick |
| `port` | Non-standard port |
| `https_token` | "https"/"http" used as a literal word inside the domain |
| `submit_to_email` | `mailto:` present |
| `abnormal_url` | IP-based or unparseable host |
| `redirect` | Multiple redirect markers |
| `dns_record` | Does the domain actually resolve via DNS? |

### Known limitation: shortened links (bit.ly, etc.)

A URL shortener itself (e.g. `bit.ly`) is a real, legitimate, long-standing
domain with valid DNS and HTTPS — the actual risk is hidden behind the
redirect target, which this project doesn't follow. The model flags
shorteners as a mild risk factor but won't reliably catch a malicious link
hidden behind one without resolving the redirect first (see "Ideas to
extend" below).

## Project structure

```
SecureURL-AI/
├── app.py                  Flask web app
├── feature_extractor.py    URL -> feature vector (live, no network calls except DNS)
├── train_model.py          Trains and saves the model
├── generate_dataset.py     Builds dataset/phishing.csv from the documented schema
├── requirements.txt
├── render.yaml             Render deployment config
├── Procfile                Alternative deployment entrypoint
├── dataset/
│   └── phishing.csv        Generated by generate_dataset.py
├── model/
│   └── phishing_model.pkl  Generated by train_model.py
├── templates/
│   └── index.html
└── static/
    └── style.css
```

## Setup (local, VS Code)

```bash
# 1. Create and activate a virtual environment (recommended)
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # macOS/Linux

# 2. Install dependencies
pip install -r requirements.txt

# 3. Generate the dataset
python generate_dataset.py

# 4. Train the model
python train_model.py

# 5. Run the app
python app.py
```

Visit `http://127.0.0.1:5000` and try:

- `https://google.com` → Legitimate
- `https://github.com` → Legitimate
- `http://192.168.1.1/verify-account` → Phishing
- `http://secure-bank0famerica-verify.com` → Phishing
- `http://verify-facebook-account.freehost.com` → Phishing

## Deploying to Render

1. Push this folder to a GitHub repo.
2. On Render, create a new **Web Service** from that repo. Render will pick
   up `render.yaml` automatically and run:
   - Build: `pip install -r requirements.txt && python generate_dataset.py && python train_model.py`
   - Start: `gunicorn app:app`
3. No environment variables are required for the basic version.

## Ideas to extend (for a stronger internship submission)

- **Follow redirects** for shortened URLs (`requests.head(url, allow_redirects=True)`)
  and re-run feature extraction on the final destination URL.
- **WHOIS domain age** via `python-whois`, replacing the `domain_age`
  placeholder with a real value, then retrain including it.
- **VirusTotal API** lookup for an additional reputation signal shown
  alongside the model's own prediction.
- **SSL certificate inspection** (issuer, validity period) instead of just
  checking for HTTPS presence.
- **Page content fetch** to compute the HTML-dependent features
  (`iframe`, `popup`, `mouseover`, `right_click`, `SFH`, `tag_links`) for a
  closer match to the original 30-feature UCI model.

Any of these is a good "what I'd improve next" talking point in an
interview even if you don't have time to implement it before applying.

## Disclaimer

This is an educational project. Predictions are probabilistic and based on
structural URL features only — they are not a substitute for a real
security product, and should not be the sole basis for trusting or
distrusting a website.
