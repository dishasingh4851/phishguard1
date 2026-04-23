from flask import Flask, render_template, request
import numpy as np
import pickle
from features import FeatureExtraction
from urllib.parse import urlparse
import difflib
import csv
import os
print("FILES:", os.listdir())
from datetime import datetime
import requests

app = Flask(__name__)

# ================================
# LOAD MODEL
# ================================
model_path = os.path.join(os.getcwd(), "model2.pkl")

with open(model_path, "rb") as f:
    model = pickle.load(f)

# ================================
# CSV FILE SETUP
# ================================
CSV_FILE = "scan_history.csv"

if not os.path.exists(CSV_FILE):
    with open(CSV_FILE, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["URL", "Result", "Confidence", "Timestamp"])

# ================================
# FEATURE ORDER
# ================================
original = [
    "UsingIP", "LongURL", "ShortURL", "Symbol@", "Redirecting",
    "PrefixSuffix", "SubDomains", "HTTPS", "DomainRegLen",
    "Favicon", "NonStdPort", "HTTPSDomainURL", "InfoEmail",
    "WebsiteForwarding", "AgeOfDomain", "GoogleIndex",
]

expected = [
    "PrefixSuffix", "GoogleIndex", "SubDomains", "Symbol@",
    "HTTPSDomainURL", "AgeOfDomain", "HTTPS", "UsingIP",
    "LongURL", "ShortURL", "Redirecting", "DomainRegLen",
    "InfoEmail", "Favicon", "WebsiteForwarding", "NonStdPort"
]

# ================================
# TRUSTED DOMAINS
# ================================
trusted_domains = [
    "google.com", "facebook.com", "amazon.com",
    "apple.com", "microsoft.com", "paypal.com",
    "github.com", "youtube.com"
]

# ================================
# NORMALIZE DOMAIN
# ================================
def normalize_domain(domain):
    replacements = {
        "0": "o",
        "1": "l",
        "3": "e",
        "5": "s",
        "@": "a"
    }
    for k, v in replacements.items():
        domain = domain.replace(k, v)
    return domain

# ================================
# FAKE DOMAIN CHECK
# ================================
def is_fake_similar(domain):
    normalized = normalize_domain(domain)

    for real in trusted_domains:
        similarity = difflib.SequenceMatcher(None, normalized, real).ratio()
        if similarity > 0.75 and domain != real:
            return True
    return False

# ================================
# URL VALIDATION
# ================================
def is_valid_url(url):
    parsed = urlparse(url)
    return (
        parsed.scheme in ["http", "https"] and
        parsed.netloc != "" and
        "." in parsed.netloc
    )

# ================================
# URL REACHABILITY CHECK
# ================================
def is_url_reachable(url):
    try:
        response = requests.get(url, timeout=5)
        return response.status_code < 400
    except:
        try:
            url = url.replace("https://", "http://")
            response = requests.get(url, timeout=5)
            return response.status_code < 400
        except:
            return False

# ================================
# SAVE TO CSV
# ================================
def save_to_csv(url, result, confidence):
    with open(CSV_FILE, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([url, result, confidence, datetime.now()])

# ================================
# GET STATS
# ================================
def get_stats():
    total = 0
    phishing = 0
    legit = 0

    with open(CSV_FILE, mode='r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            total += 1
            if "Phishing" in row["Result"]:
                phishing += 1
            elif "Legitimate" in row["Result"]:
                legit += 1

    return total, phishing, legit

# ================================
# HOME PAGE
# ================================
@app.route('/')
def home():
    total, phishing, legit = get_stats()
    return render_template(
        "index.html",
        total=total,
        phishing=phishing,
        legit=legit
    )

# ================================
# PREDICT ROUTE
# ================================
@app.route('/predict', methods=['POST'])
def predict():
    user_input = request.form['url'].strip()

    temp_url = user_input
    if not temp_url.startswith(("http://", "https://")):
        temp_url = "https://" + temp_url

    # INVALID URL
    if not is_valid_url(temp_url):
        total, phishing, legit = get_stats()
        return render_template(
            "index.html",
            url=user_input,
            result="⚠️ Invalid URL! Please enter a valid website.",
            confidence=0,
            color="orange",
            total=total,
            phishing=phishing,
            legit=legit
        )

    url = temp_url
    parsed = urlparse(url)
    domain = parsed.netloc.replace("www.", "")

    # ================================
    # CHECK IF SITE IS REACHABLE
    # ================================
    if not is_url_reachable(url):
        total, phishing, legit = get_stats()
        return render_template(
            "index.html",
            url=url,
            result="⚠️ Site can't be reached",
            confidence=0,
            color="orange",
            total=total,
            phishing=phishing,
            legit=legit
        )

    # NUMERIC DOMAIN
    if domain.replace(".", "").isdigit():
        save_to_csv(url, "Phishing", 0.95)
        total, phishing, legit = get_stats()

        return render_template(
            "index.html",
            url=url,
            result="🚨 Phishing Website (Numeric Domain)",
            confidence=0.95,
            color="red",
            total=total,
            phishing=phishing,
            legit=legit
        )

    # FAKE DOMAIN
    if is_fake_similar(domain):
        save_to_csv(url, "Phishing", 0.99)
        total, phishing, legit = get_stats()

        return render_template(
            "index.html",
            url=url,
            result="🚨 Phishing Website (Fake Domain Detected)",
            confidence=0.99,
            color="red",
            total=total,
            phishing=phishing,
            legit=legit
        )

    try:
        obj = FeatureExtraction(url)
        raw = obj.getFeaturesList()

        feature_dict = dict(zip(original, raw))
        ordered_features = [feature_dict[f] for f in expected]

        features_array = np.array(ordered_features).reshape(1, -1)

        prob = model.predict_proba(features_array)[0][0]
        threshold = 0.56

        if prob > threshold:
            result = "🚨 Phishing Website"
            label = "Phishing"
            color = "red"
        else:
            result = "✅ Legitimate Website"
            label = "Legitimate"
            color = "green"

        save_to_csv(url, label, round(prob, 2))
        total, phishing, legit = get_stats()

        return render_template(
            "index.html",
            url=url,
            result=result,
            confidence=round(prob, 2),
            color=color,
            total=total,
            phishing=phishing,
            legit=legit
        )

    except Exception as e:
        total, phishing, legit = get_stats()
        return render_template(
            "index.html",
            url=url,
            result=f"⚠️ Error: {str(e)}",
            confidence=0,
            color="orange",
            total=total,
            phishing=phishing,
            legit=legit
        )

# ================================
# RUN APP
# ================================
if __name__ == "__main__":
    app.run(debug=True)
