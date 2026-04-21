
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
import os
from urllib.parse import urlparse

# --- URL Feature Engineering ---
def extract_url_features(url):
    features = {}
    try:
        parsed = urlparse(url)
        features['url_len'] = len(url)
        features['dot_count'] = url.count('.')
        features['https'] = 1 if parsed.scheme == 'https' else 0
        features['hyphen_count'] = url.count('-')
        features['at_count'] = url.count('@')
        features['is_ip'] = 1 if parsed.netloc.replace('.', '').isdigit() else 0
        
        suspicious_keywords = ['login', 'verify', 'update', 'secure', 'account', 'banking', 'phish', 'webscr']
        features['suspicious_words'] = sum([1 for word in suspicious_keywords if word in url.lower()])
        
        return list(features.values())
    except:
        return [0] * 7

def train_url_model():
    print("Training URL Classifier (Large-Scale)...")
    if not os.path.exists("data/processed/urls_cleaned.csv.gz"):
        print("URL dataset not found. Run download_data.py first.")
        return

    # Pandas handles .gz automatically
    df = pd.read_csv("data/processed/urls_cleaned.csv.gz")
    sample_size = min(len(df), 100000) # Increased scale
    df = df.sample(sample_size, random_state=42)
    X = np.array([extract_url_features(u) for u in df['url']])
    y = df['label']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Use balanced weights for real-world imbalance
    # Slightly reduced depth for better size/performance balance
    model = RandomForestClassifier(n_estimators=100, max_depth=15, n_jobs=-1, class_weight='balanced')
    model.fit(X_train, y_train)
    
    y_pred = model.predict(X_test)
    print(f"URL Model Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    
    # Use compress=3 to keep the file size under 25MB
    joblib.dump(model, "models/url_classifier.pkl", compress=3)
    print("Saved Large-Scale URL model (Compressed).")

# --- SMS/Email Training ---
def train_text_model():
    print("Training Integrated Message Classifier (Large-Scale)...")
    dfs = []
    if os.path.exists("data/processed/sms_spam_cleaned.csv.gz"):
        dfs.append(pd.read_csv("data/processed/sms_spam_cleaned.csv.gz"))
    
    # Load all email parts
    import glob
    email_parts = glob.glob("data/processed/emails_cleaned_part_*.csv.gz")
    for part in email_parts:
        dfs.append(pd.read_csv(part))
    
    if not dfs:
        print("No text datasets found.")
        return

    df = pd.concat(dfs, ignore_index=True).dropna().drop_duplicates()
    print(f"Combined text dataset: {len(df)} samples")
    
    X_train, X_test, y_train, y_test = train_test_split(df['text'], df['label'], test_size=0.2, random_state=42)
    
    # ngram_range=(1, 2) captures phrases like "verify account"
    vectorizer = TfidfVectorizer(max_features=10000, stop_words='english', ngram_range=(1, 2))
    X_train_tfidf = vectorizer.fit_transform(X_train)
    X_test_tfidf = vectorizer.transform(X_test)
    
    model = LogisticRegression(max_iter=2000, class_weight='balanced')
    model.fit(X_train_tfidf, y_train)
    
    y_pred = model.predict(X_test_tfidf)
    print(f"Text Model Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    
    # Compressed saving
    joblib.dump(model, "models/text_classifier.pkl", compress=3)
    joblib.dump(vectorizer, "models/tfidf_vectorizer.pkl", compress=3)
    print("Saved Enhanced Text model and Vectorizer (Compressed).")

if __name__ == "__main__":
    if not os.path.exists("models"):
        os.makedirs("models", exist_ok=True)
    train_url_model()
    train_text_model()
