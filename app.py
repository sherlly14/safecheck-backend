from flask import Flask, request, jsonify
from flask_cors import CORS
import random
import re

app = Flask(__name__)
CORS(app)

stats = {"total_scans": 0, "safe": 0, "suspicious": 0, "scam": 0}

TRAINING_EXAMPLES = [
    {"id": 1, "type": "message", "text": "Congratulations! You won a lottery prize. Click here now to claim it.", "true_label": "scam", "explanation": ["Prize or lottery hook", "Urgent call to action", "Unexpected rewards are a common fraud tactic"]},
    {"id": 2, "type": "email", "text": "Your bank account will be blocked today. Verify your details immediately at http://bank-secure-verify.example", "true_label": "scam", "explanation": ["Threatening urgency", "Request for sensitive details", "Suspicious link pattern"]},
    {"id": 3, "type": "message", "text": "Hi, are we still meeting at 5 pm for coffee?", "true_label": "safe", "explanation": ["Normal personal context", "No link, urgency, or request for sensitive information"]},
    {"id": 4, "type": "link", "text": "https://example.com/account", "true_label": "safe", "explanation": ["HTTPS is present", "No obvious shortened URL or urgent social-engineering language"]},
    {"id": 5, "type": "message", "text": "Send the OTP now or your KYC will be suspended immediately.", "true_label": "scam", "explanation": ["Requests an OTP", "Uses urgency and account-threat language", "Legitimate organisations do not ask for OTPs by message"]}
]

KEYWORDS = {
    "urgency_language": ["urgent", "immediately", "asap", "today", "now", "account suspended", "blocked"],
    "credential_or_otp_request": ["otp", "password", "pin", "bank details", "cvv", "verify your details"],
    "prize_lottery_hook": ["winner", "won", "prize", "lottery", "congratulations", "free money"],
    "suspicious_action": ["click here", "claim now", "verify now", "send money", "pay now"]
}

def detect(content, input_type):
    text = content.lower().strip()
    features = {}
    reasons = []
    hits = 0
    for name, words in KEYWORDS.items():
        matched = [word for word in words if word in text]
        score = min(1.0, len(matched) / 2)
        features[name] = round(score, 2)
        if matched:
            hits += len(matched)
            reasons.append(f"Detected {name.replace('_', ' ')}: {', '.join(matched[:2])}")

    features["contains_link"] = 1.0 if re.search(r"https?://|www\.", text) else 0.0
    shortener = any(domain in text for domain in ["bit.ly", "tinyurl", "t.co", "goo.gl"])
    features["shortened_url"] = 1.0 if shortener else 0.0
    if shortener:
        hits += 2
        reasons.append("Contains a shortened URL, which can hide a destination")

    if input_type == "phone":
        valid = bool(re.fullmatch(r"\+?[0-9()\s-]{7,18}", content.strip()))
        features["phone_format_valid"] = 1.0 if valid else 0.0
        if not valid:
            return "suspicious", 42, ["The phone number format looks unusual", "Verify the caller through an official contact channel"], features
        return "safe", 78, ["The phone number format looks valid", "A valid format does not prove that a caller is trustworthy"], features

    if hits >= 3:
        return "scam", max(8, 34 - hits * 4), reasons + ["Do not share personal, banking, password, or OTP information"], features
    if hits >= 1:
        return "suspicious", max(40, 64 - hits * 5), reasons + ["Verify the sender independently before responding"], features
    return "safe", 86, ["No major spam or phishing patterns were detected", "Still verify unknown senders before taking action"], features

@app.post('/api/detect')
def api_detect():
    data = request.get_json(silent=True) or {}
    content = str(data.get('content', '')).strip()
    input_type = str(data.get('type', 'message'))
    if not content:
        return jsonify({"error": "Content is required"}), 400
    label, confidence, reasons, feature_scores = detect(content, input_type)
    stats["total_scans"] += 1
    stats[label] += 1
    return jsonify({"label": label, "confidence": confidence, "reasons": reasons, "feature_scores": feature_scores, "privacy": "Raw content is not stored by this demo backend."})

@app.get('/api/training-example')
def training_example():
    return jsonify(random.choice(TRAINING_EXAMPLES))

@app.post('/api/check-guess')
def check_guess():
    data = request.get_json(silent=True) or {}
    example = next((x for x in TRAINING_EXAMPLES if x['id'] == data.get('example_id')), None)
    if not example:
        return jsonify({"error": "Example not found"}), 404
    guess = data.get('guess')
    return jsonify({"is_correct": guess == example['true_label'], "true_label": example['true_label'], "explanation": example['explanation']})

@app.get('/api/stats')
def get_stats():
    return jsonify(stats)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
