
import pandas as pd
import requests
import zipfile
import io
import os

def download_file(url, label):
    print(f"Attempting to download {label} from: {url}")
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        return response
    except Exception as e:
        print(f"Failed to download from {url}: {e}")
        return None

def download_sms_spam():
    print("--- Processing SMS Spam ---")
    url = "https://archive.ics.uci.edu/ml/machine-learning-databases/00228/smsspamcollection.zip"
    r = download_file(url, "SMS Spam")
    if r:
        z = zipfile.ZipFile(io.BytesIO(r.content))
        z.extractall("data/raw/sms_spam")
        df = pd.read_csv("data/raw/sms_spam/SMSSpamCollection", sep='\t', names=['label', 'text'])
        df['label'] = df['label'].map({'ham': 0, 'spam': 1})
        df.to_csv("data/processed/sms_spam_cleaned.csv.gz", index=False, compression='gzip')
        print(f"SMS Spam processed: {len(df)} rows (Compressed)")

def download_url_dataset():
    print("--- Processing Phishing URLs (Massive Scale: 650K+) ---")
    mirrors = [
        "https://raw.githubusercontent.com/mango-cat/ECS171-Project/main/malicious_phish.csv",
        "https://raw.githubusercontent.com/mildsam/Phishing-Detection-System/main/dataset_phishing.csv"
    ]
    
    all_dfs = []
    for url in mirrors:
        r = download_file(url, "URL Dataset Mirror")
        if r:
            try:
                df = pd.read_csv(io.StringIO(r.text))
                # Detect columns (Ider-Zheng uses 'domain' and 'label')
                url_col = 'domain' if 'domain' in df.columns else ('url' if 'url' in df.columns else df.columns[0])
                label_col = 'label' if 'label' in df.columns else ('type' if 'type' in df.columns else df.columns[1])
                
                temp_df = df[[url_col, label_col]].copy()
                temp_df.columns = ['url', 'label']
                # Label mapping: 'bad'/1 -> 1, 'good'/0 -> 0
                temp_df['label'] = temp_df['label'].apply(lambda x: 1 if str(x).lower() in ['bad', 'phishing', 'malicious', '1', '1.0'] else 0)
                all_dfs.append(temp_df)
                print(f"Loaded {len(temp_df)} rows from mirror.")
            except Exception as e:
                print(f"Error processing mirror {url}: {e}")
    
    if all_dfs:
        final_df = pd.concat(all_dfs, ignore_index=True).drop_duplicates()
        
        # Split into chunks of 200,000 rows to ensure very small files
        chunk_size = 200000
        for i in range(0, len(final_df), chunk_size):
            chunk = final_df.iloc[i:i+chunk_size]
            part_num = (i // chunk_size) + 1
            filename = f"data/processed/urls_cleaned_part_{part_num}.csv.gz"
            chunk.to_csv(filename, index=False, compression='gzip')
            print(f"Saved {filename}: {len(chunk)} rows")
        
        # Clean up old combined file
        if os.path.exists("data/processed/urls_cleaned.csv.gz"):
            os.remove("data/processed/urls_cleaned.csv.gz")

def download_email_dataset():
    print("--- Processing Phishing Emails (Ultra Scale: 50K+) ---")
    mirrors = [
        "https://raw.githubusercontent.com/PuruSinghvi/Spam-Email-Classifier/main/Datasets/enron_spam_data.csv",
        "https://raw.githubusercontent.com/Matth-L/detectish/main/Phishing_Email.csv",
        "https://raw.githubusercontent.com/uzmabb182/Data_622/main/final_project_data_622/Phishing_Email.csv",
        "https://raw.githubusercontent.com/sadat1971/Phishing_Email/main/Data/curated_set.csv"
    ]
    
    all_dfs = []
    for url in mirrors:
        r = download_file(url, "Email Dataset Mirror")
        if r:
            try:
                # Handle Enron (sep may be different, usually csv)
                df = pd.read_csv(io.StringIO(r.text))
                df = df.dropna()
                
                # Detect columns (Enron uses 'Message' and 'Spam/Ham' or 'label')
                text_col = [c for c in df.columns if c.lower() in ['message', 'email text', 'text']][0]
                label_col = [c for c in df.columns if c.lower() in ['spam/ham', 'email type', 'label', 'is_phishing']][0]
                
                temp_df = df[[text_col, label_col]].copy()
                temp_df.columns = ['text', 'label']
                # Map labels: spam/phishing -> 1, ham/safe -> 0
                temp_df['label'] = temp_df['label'].apply(lambda x: 1 if str(x).lower() in ['spam', 'phishing email', '1', 'phish', '1.0'] else 0)
                all_dfs.append(temp_df)
                print(f"Loaded {len(temp_df)} rows from mirror.")
            except Exception as e:
                print(f"Error processing mirror {url}: {e}")
    
    if all_dfs:
        final_df = pd.concat(all_dfs, ignore_index=True).drop_duplicates()
        
        # Split into chunks of 20,000 rows to ensure each file is < 25MB
        chunk_size = 20000
        for i in range(0, len(final_df), chunk_size):
            chunk = final_df.iloc[i:i+chunk_size]
            part_num = (i // chunk_size) + 1
            filename = f"data/processed/emails_cleaned_part_{part_num}.csv.gz"
            chunk.to_csv(filename, index=False, compression='gzip')
            print(f"Saved {filename}: {len(chunk)} rows")
        
        # Clean up old combined file if it exists
        if os.path.exists("data/processed/emails_cleaned.csv.gz"):
            os.remove("data/processed/emails_cleaned.csv.gz")

if __name__ == "__main__":
    os.makedirs("data/raw", exist_ok=True)
    os.makedirs("data/processed", exist_ok=True)
    download_sms_spam()
    download_url_dataset()
    download_email_dataset()
