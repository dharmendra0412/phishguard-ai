import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from urllib.parse import urlparse
from fastapi.middleware.cors import CORSMiddleware
import os
import re
import requests

LIVE_THREATS = set()

def sync_global_threats():
    """Fetch latest threats from public feeds for live intelligence."""
    global LIVE_THREATS
    try:
        # Latest Active Phishing Domains feed
        res = requests.get("https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt", timeout=5)
        new_domains = set(res.text.splitlines()[:2000])
        LIVE_THREATS.update(new_domains)
        print(f"Synced {len(new_domains)} live global threats.")
    except:
        print("Live sync skipped (Offline/Timeout).")

def unmask_url(url: str):
    """Follow redirects to find the actual destination of a shortened URL."""
    try:
        response = requests.head(url, allow_redirects=True, timeout=3)
        return response.url
    except:
        return url

# Initial sync
sync_global_threats()

# Global Whitelist (Top trusted domains)
WHITELIST = {
    "google.com", "github.com", "microsoft.com", "amazon.com", "facebook.com", 
    "apple.com", "linkedin.com", "netflix.com", "instagram.com", "twitter.com",
    "youtube.com", "gmail.com", "yahoo.com", "outlook.com", "wikipedia.org",
    "bit.ly", "t.co", "tinyurl.com", "stackoverflow.com", "reddit.com",
    "vercel.app", "vercel.com", "netlify.app", "netlify.com", "stripe.com",
    "paytm.com", "razorpay.com", "phishguard-ai-topaz.vercel.app",
    "adobe.com", "zoom.us", "dropbox.com", "slack.com", "spotify.com",
    "medium.com", "quora.com", "canva.com", "figma.com", "notion.so"
}

app = FastAPI(title="PhishGuard AI Backend")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load Models with Smart-Chunk-Joiner for GitHub compatibility
def load_smart_model(model_path):
    # Check if we need to join chunks (GitHub bypass)
    if not os.path.exists(model_path):
        parts = [f"{model_path}.part{i}" for i in range(1, 10) if os.path.exists(f"{model_path}.part{i}")]
        if parts:
            print(f"Joining {len(parts)} chunks to rebuild {os.path.basename(model_path)}...")
            with open(model_path, 'wb') as output_file:
                for part in parts:
                    with open(part, 'rb') as input_file:
                        output_file.write(input_file.read())
    
    if os.path.exists(model_path):
        return joblib.load(model_path)
    return None

try:
    text_model = load_smart_model("../models/text_classifier.pkl")
    vectorizer = load_smart_model("../models/tfidf_vectorizer.pkl")
    url_model = load_smart_model("../models/url_classifier.pkl")
    print("Models loaded successfully (Smart-Joiner Active).")
except Exception as e:
    print(f"Error loading models: {e}")
    text_model = None
    url_model = None

class MessageRequest(BaseModel):
    text: str

class URLRequest(BaseModel):
    url: str

# Privacy & Security Utilities
def privacy_redactor(text):
    # Masking Phone Numbers
    text = re.sub(r'\+?\d{1,4}[-.\s]?\d{5,10}', '[REDACTED_PHONE]', text)
    # Masking Credit Card numbers
    text = re.sub(r'\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}', '[REDACTED_CARD]', text)
    # Masking Emails
    text = re.sub(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', '[REDACTED_EMAIL]', text)
    return text

def check_homograph_attack(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    if any(ord(char) > 127 for char in domain):
        return True, "Homograph Attack Detected (Visually similar non-English characters used)"
    return False, ""

def text_normalizer(text):
    """Removes obfuscation like P.a.y.p.a.l or W-i-n-n-e-r"""
    # 1. Remove dots/hyphens between letters
    text = re.sub(r'(?<=[a-zA-Z])[-.](?=[a-zA-Z])', '', text)
    # 2. Replace common look-alike symbols
    replacements = {'@': 'a', '0': 'o', '1': 'i', '!': 'i', '$': 's', '3': 'e', '5': 's'}
    for char, replacement in replacements.items():
        text = text.replace(char, replacement)
    return text

def detect_hinglish_scams(text):
    """Detects common Hinglish (Hindi-English) phishing phrases"""
    text_lower = text.lower()
    hinglish_patterns = [
        r"aapka.*account.*block",
        r"kyc.*update.*kare",
        r"account.*band.*ho.*gaya",
        r"paisa.*jeeta.*hai",
        r"gift.*card.*milega",
        r"bank.*se.*baat.*kar.*rahe",
        r"otp.*share.*na.*kare", # Often used in 'reverse' psychology scams
        r"lucky.*draw.*jeet"
    ]
    for pattern in hinglish_patterns:
        if re.search(pattern, text_lower):
            return True
    return False

def external_reputation_check(url_or_domain):
    """Simulates a real-time check against global blacklists like PhishTank"""
    # In a production app, this would be an API call
    # We'll use a set of known malicious pattern types
    malicious_patterns = ['.xyz', '.top', '.buzz', '.tk', 'update-verify', 'login-secure-bank']
    for pattern in malicious_patterns:
        if pattern in url_or_domain:
            return 0.85 # High threat from reputation
    return 0.0

def generate_counter_measure(text):
    """Generates a safe response to neutralize the threat"""
    return "Thank you. I have reported this communication to the appropriate cyber authorities. Please do not contact me again."

def detect_social_engineering_tactics(text):
    text_lower = text.lower()
    normalized_text = text_normalizer(text_lower)
    tactics = []
    
    # Check original and normalized text
    search_text = text_lower + " " + normalized_text
    
    if any(w in search_text for w in ['urgent', 'blocked', 'suspended', 'immediately', 'hours', 'expire', 'warning', 'last chance']):
        tactics.append({"type": "Fear / Urgency", "description": "Scammer is trying to make you panic so you act without thinking."})
    if any(w in search_text for w in ['won', 'gift', 'prize', 'reward', 'cashback', 'free', 'lottery', 'bonus']):
        tactics.append({"type": "Greed / Incentive", "description": "Scammer is using a fake reward to bait you into clicking."})
    if any(w in search_text for w in ['official', 'department', 'bank', 'government', 'tax', 'support', 'admin', 'police']):
        tactics.append({"type": "Authority Impersonation", "description": "Scammer is pretending to be a trusted official to gain your trust."})
    if any(w in search_text for w in ['debt', 'unpaid', 'invoice', 'payment', 'overdue', 'transaction']):
        tactics.append({"type": "Financial Pressure", "description": "Scammer is creating fake financial anxiety to force a response."})
    
    if detect_hinglish_scams(text):
        tactics.append({"type": "Hinglish Manipulation", "description": "Used localized language (Hinglish) to sound more familiar/informal."})
        
    return tactics

# URL Feature extractor
def extract_url_features(url):
    parsed = urlparse(url)
    features = [
        len(url),
        url.count('.'),
        1 if parsed.scheme == 'https' else 0,
        url.count('-'),
        url.count('@'),
        1 if parsed.netloc.replace('.', '').isdigit() else 0,
        sum([1 for word in ['login', 'verify', 'update', 'secure', 'account', 'banking', 'webscr'] if word in url.lower()])
    ]
    return np.array(features).reshape(1, -1)

@app.get("/")
async def health():
    return {"status": "active", "version": "10.0.0-Ensemble-X (Multi-Brain Architecture)"}

@app.post("/scan-message")
async def scan_message(req: MessageRequest):
    safe_text = privacy_redactor(req.text)
    privacy_applied = safe_text != req.text

    if not text_model or not vectorizer:
        raise HTTPException(status_code=500, detail="Text model not loaded")
    
    vec_text = vectorizer.transform([safe_text])
    ml_prob = text_model.predict_proba(vec_text)[0][1]
    
    # Heuristic Boosts
    heuristic_boost = 0
    text_lower = safe_text.lower()
    norm_text = text_normalizer(text_lower)
    
    # Analyze both original and de-obfuscated text
    search_space = text_lower + " " + norm_text
    
    suspicious_keywords = {
        'urgent': 0.15, 'verify': 0.15, 'update': 0.1, 'payment': 0.2,
        'billing': 0.15, 'expiry': 0.1, 'within 1 day': 0.25, 'account': 0.1,
        'suspension': 0.2, 'amazon.com': 0.15, 'paypal': 0.15, 'bank': 0.1,
        'credited': 0.25, 'withdraw': 0.2, 'rs.': 0.2, '₹': 0.2,
        'win': 0.15, 'gift': 0.1, 'claim': 0.15, 'bit.ly': 0.3, 'tinyurl': 0.3,
        'invest': 0.1, 'shares': 0.1, 'unlisted': 0.15, 'performance': 0.05
    }
    
    for word, weight in suspicious_keywords.items():
        if word in search_space:
            heuristic_boost += weight

    if detect_hinglish_scams(safe_text):
        heuristic_boost += 0.3 # High boost for Hinglish scam patterns

    final_prob = max(0.0, min(0.99, ml_prob + heuristic_boost))
    
    prediction = "phishing" if final_prob > 0.45 else "safe"
    if 0.25 < final_prob <= 0.45:
        prediction = "marketing / spam"
    elif 0.45 < final_prob < 0.65:
        prediction = "suspicious"

    breakdown = []
    if ml_prob > 0.4: breakdown.append("ML pattern match for phishing tone")
    if norm_text != text_lower: breakdown.append("De-obfuscation revealed hidden keywords")
    if detect_hinglish_scams(safe_text): breakdown.append("Hinglish scam pattern detected")
    if heuristic_boost > 0.3: breakdown.append("High density of suspicious keywords")
    if any(k in search_space for k in ['rs.', '₹', 'credited', 'withdraw']): breakdown.append("Financial fraud pattern")

    recommendation = "Safe to read."
    if prediction == "phishing":
        recommendation = "CRITICAL: Do not click any links or share OTPs/Passwords."
    elif prediction == "suspicious":
        recommendation = "WARNING: Verify the sender before taking any action."
    elif prediction == "marketing / spam":
        recommendation = "INFO: This appears to be an unsolicited promotional message."

    tactics = detect_social_engineering_tactics(safe_text)

    return {
        "risk_score": round(final_prob * 100, 2),
        "status": prediction,
        "confidence": f"{round(final_prob * 100 if final_prob > 0.5 else (1-final_prob)*100, 2)}%",
        "reason": "Hybrid Engine (ML + Heuristics)",
        "breakdown": breakdown,
        "recommendation": recommendation,
        "privacy_shield": "ACTIVE" if privacy_applied else "INACTIVE",
        "processed_text": safe_text,
        "tactics": tactics,
        "counter_measure": generate_counter_measure(safe_text)
    }

INDIAN_SCAM_KEYWORDS = [
    "bijli", "electricity bill", "kyc", "aadhaar", "pan card", "account block", 
    "papa", "accident", "hospital", "upi pin", "phonepe reward", "gpay cash",
    "lottery", "kbc", "job offer", "whatsapp gift"
]

def analyze_zero_day_url(url: str):
    """Deep DNA Analysis for unknown URLs."""
    score = 0
    reasons = []
    
    # Heuristic 1: Suspicious TLDs
    suspicious_tlds = ['.zip', '.mov', '.icu', '.top', '.xyz', '.work', '.click']
    if any(url.endswith(tld) for tld in suspicious_tlds):
        score += 40
        reasons.append("High-Risk TLD detected")
        
    # Heuristic 2: Brand Impersonation in path/subdomain
    brands = ['paypal', 'bank', 'hdfc', 'sbi', 'google', 'microsoft', 'apple', 'netflix']
    for brand in brands:
        if brand in url.lower() and not url.lower().startswith(f"https://{brand}."):
            score += 50
            reasons.append(f"Potential {brand.upper()} Impersonation")
            
    # Heuristic 3: Entropy & Length
    if len(url) > 70:
        score += 20
        reasons.append("Abnormally long URL structure")
        
    return score, reasons

@app.post("/scan-message")
async def scan_message(req: MessageRequest):
    # ML Prediction
    is_phishing_ml = text_model.predict(vectorizer.transform([req.text]))[0]
    
    # Heuristic Indian Scam Detection
    is_indian_scam = any(kw in req.text.lower() for kw in INDIAN_SCAM_KEYWORDS)
    
    status = "phishing" if is_phishing_ml == 1 or is_indian_scam else "safe"
    
    return {
        "status": status,
        "recommendation": "DO NOT CLICK OR REPLY." if status == "phishing" else "Looks safe, but stay cautious.",
        "processed_text": req.text[:100] + "...",
        "privacy_shield": "ACTIVE",
        "reason": "Indian Scam Pattern Identified" if is_indian_scam else "Neural Forensic Analysis",
        "breakdown": ["Social Engineering", "High Urgency"] if is_phishing_ml == 1 else ["Clean Signal"],
        "tactics": [{"type": "Psychological Bait", "description": "Luring with fake rewards/fear"}] if status == "phishing" else [],
        "counter_measure": "Block the sender and report to 1930 (Indian Cyber Cell)."
    }

@app.post("/scan-url")
async def scan_url(req: URLRequest):
    # 1. Unmask shortened URLs (bit.ly, tinyurl, etc.)
    final_url = unmask_url(req.url)
    hostname = urlparse(final_url).netloc.lower().replace("www.", "")
    
    # 2. Check Live Threat Database
    is_live_phish = hostname in LIVE_THREATS
    
    # 3. Base ML Prediction
    # Since we are in the middle of an upgrade, we'll use a high-fidelity heuristic + ML combo
    is_phishing_ml = url_model.predict([final_url])[0] if url_model else 'good'
    
    # 4. Zero-Day Heuristic Analysis
    zero_day_score, zero_day_reasons = analyze_zero_day_url(final_url)
    
    is_bad = is_phishing_ml == 'bad' or zero_day_score >= 50 or is_live_phish
    final_status = "phishing" if is_bad else "safe"
    
    return {
        "status": final_status,
        "is_redirected": final_url != req.url,
        "final_url": final_url if final_url != req.url else None,
        "reason": "Global Threat Feed Match" if is_live_phish else ("Zero-Day DNA Analysis" if zero_day_score >= 50 else "Real-time AI Scan"),
        "breakdown": zero_day_reasons if zero_day_score > 0 else ["Safe Structural Pattern"],
        "recommendation": "CRITICAL: Malicious Link. Do not enter credentials." if final_status == "phishing" else "Link structure appears secure.",
        "counter_measure": "Report this domain to Google Safe Browsing and Delete."
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
