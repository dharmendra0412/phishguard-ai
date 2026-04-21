# PhishGuard AI: Hybrid Cybersecurity Detection System

PhishGuard AI is a high-performance, real-time threat detection system designed to identify phishing attempts in URLs, SMS, and Emails. It leverages a hybrid approach combining **Large-Scale Machine Learning** (700k+ records) with an **Intelligent Heuristic Layer**.

## 🚀 Features

- **Hybrid Detection Engine**: Combines Random Forest/Logistic Regression models with rule-based safety checks.
- **Massive Intelligence**: Trained on 650,000+ malicious URLs and 70,000+ phishing emails/SMS.
- **Real-Time Scanning**: Sub-second inference for URLs and text messages.
- **Multilingual Support**: Basic detection for Hindi and other regional phishing patterns.
- **Glassmorphism Dashboard**: A modern, sleek UI for real-time risk assessment and threat visualization.

## 🛠️ Tech Stack

- **Backend**: FastAPI (Python)
- **Frontend**: Vanilla JS, HTML5, CSS3 (Glassmorphism design)
- **Machine Learning**: Scikit-learn (Random Forest, TF-IDF Vectorization)
- **Data Processing**: Pandas, Joblib (with GZIP compression)

## 📦 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/YOUR_USERNAME/phishguard-ai.git
   cd phishguard-ai
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## 🧠 Usage

### 1. Data Collection
Fetch the massive real-world datasets (1.4M+ combined records):
```bash
python scripts/download_data.py
```

### 2. Model Training
Train the high-scale AI models:
```bash
python scripts/train_models.py
```

### 3. Run the System
Start the FastAPI inference engine:
```bash
cd backend
python main.py
```
Then open `frontend/index.html` in your browser or serve it using:
```bash
python -m http.server 3000 --directory frontend
```

## 🛡️ License
MIT License. Created with PhishGuard AI Engineering standards.
