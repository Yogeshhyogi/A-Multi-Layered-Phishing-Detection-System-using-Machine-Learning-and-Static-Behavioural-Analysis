%%writefile app.py
from flask import Flask, render_template, request, jsonify
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from feature_extractors import extract_all_features
from static_analysis import fetch_live_behavior
from urllib.parse import urlparse
import difflib
import whois
from datetime import datetime

app = Flask(__name__)
models = {}

def get_domain_age(url):
    try:
        domain = urlparse(url).netloc
        if not domain: domain = url
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list): creation_date = creation_date[0]
        age_days = (datetime.now() - creation_date).days
        return age_days, creation_date.strftime('%Y-%m-%d')
    except:
        return None, "Unknown"

@app.route("/")
def index(): return render_template("index.html")

@app.route("/initialize", methods=["POST"])
def initialize():
    try:
        df1 = pd.read_csv('database/dataset_phishing.csv')
        y1 = df1['status'].map({'phishing': 1, 'legitimate': 0})
        X1 = df1.select_dtypes(include=['number']).drop('status', axis=1, errors='ignore')
        models['s1'] = RandomForestClassifier(n_estimators=50).fit(X1, y1)

        df2 = pd.read_csv('database/Phishing_Legitimate_full.csv')
        models['s2'] = RandomForestClassifier(n_estimators=50).fit(df2.drop(['id', 'CLASS_LABEL'], axis=1), df2['CLASS_LABEL'])

        df3 = pd.read_csv('database/ucipish.csv')
        models['s3'] = RandomForestClassifier(n_estimators=50).fit(df3.select_dtypes(include=['number']).drop('Label', axis=1), df3['Label'])
        return jsonify({"status": "success"})
    except Exception as e: return jsonify({"status": "error", "message": str(e)})

@app.route("/scan", methods=["POST"])
def scan():
    url = request.form.get("url").lower().strip()
    if not url.startswith('http'): url = 'http://' + url
    domain = urlparse(url).netloc.replace('www.', '')

    reasons = []
    is_safe = True
    
    # PRE-VALIDATION (The Whitelist)
    # Institutional and Gov domains you wanted
    institutional_tlds = ['.edu.in', '.ac.in', '.gov.in', '.edu', '.gov', '.nic.in']
    is_institutional = any(domain.endswith(tld) for tld in institutional_tlds)

    age_days, reg_date = get_domain_age(url)

    f1, f2, f3 = extract_all_features(url)
    live = fetch_live_behavior(url)

    prob1 = models['s1'].predict_proba([f1])[0][1]
    prob2 = models['s2'].predict_proba([f2])[0][1]
    prob3 = models['s3'].predict_proba([f3])[0][1]
    avg_score = (prob1 + prob2 + prob3) / 3

    if is_institutional and avg_score < 0.85:
        return jsonify({
            "result": "VERIFIED SAFE",
            "reason": "Institutional Infrastructure: Secure Educational/Government domain.",
            "safe": True, "domain_age_days": age_days, "reg_date": reg_date
        })

    brands = ['facebook.com', 'google.com', 'microsoft.com', 'amazon.com', 'apple.com', 'paypal.com']
    for b in brands:
        if domain == b:
            return jsonify({
                "result": "VERIFIED SAFE", "reason": f"Official {b} domain.",
                "safe": True, "domain_age_days": age_days, "reg_date": reg_date
            })
        # Typosquatting
        if difflib.SequenceMatcher(None, domain, b).ratio() > 0.85:
            reasons.append(f"Typosquatting: URL mimics {b}.")
            is_safe = False

    if avg_score > 0.75:
        reasons.append(f"AI Core detected phishing patterns ({round(avg_score*100)}%).")
        is_safe = False

    
    if live['iframe'] == 1 and avg_score > 0.45:
        reasons.append("Suspicious embedded frames detected.")
        is_safe = False
    
    
    if avg_score > 0.5:
        if len(url) > 100: reasons.append("Suspiciously long URL path.")
        if url.count('.') > 5: reasons.append("Excessive subdomains/dots.")

    res_text = "PHISHING DETECTED" if not is_safe else "WEBSITE SAFE"
    res_reason = " | ".join(reasons) if reasons else "Website appears legitimate based on behavioral audit."

    return jsonify({
        "result": res_text, "reason": res_reason, "safe": is_safe,
        "domain_age_days": age_days, "reg_date": reg_date
    })

if __name__ == "__main__": app.run()
