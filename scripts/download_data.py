
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
    print("--- Processing Phishing URLs (Ultimate Scale: 3M+) ---")
    mirrors = [
        "https://urlhaus.abuse.ch/downloads/csv/",
        "https://raw.githubusercontent.com/mango-cat/ECS171-Project/main/malicious_phish.csv",
        "https://raw.githubusercontent.com/mildsam/Phishing-Detection-System/main/dataset_phishing.csv"
    ]
    
    all_dfs = []
    for url in mirrors:
        r = download_file(url, "URL Dataset Mirror")
        if r:
            try:
                if "urlhaus" in url:
                    # URLhaus header line starts with #, so we define columns manually
                    import csv
                    cols = ['id', 'dateadded', 'url', 'url_status', 'threat', 'tags', 'urlhaus_link', 'reporter']
                    df = pd.read_csv(io.StringIO(r.text), comment='#', names=cols, on_bad_lines='skip', engine='python', quoting=csv.QUOTE_NONE)
                    temp_df = pd.DataFrame()
                    temp_df['url'] = df['url']
                    temp_df['label'] = 1 
                else:
                    df = pd.read_csv(io.StringIO(r.text))
                    url_col = 'url' if 'url' in df.columns else ('domain' if 'domain' in df.columns else df.columns[0])
                    label_col = 'type' if 'type' in df.columns else ('label' if 'label' in df.columns else df.columns[1])
                    temp_df = df[[url_col, label_col]].copy()
                    temp_df.columns = ['url', 'label']
                    temp_df['label'] = temp_df['label'].apply(lambda x: 0 if str(x).lower() in ['benign', 'safe', 'legitimate', '0', 'good'] else 1)
                
                all_dfs.append(temp_df)
                print(f"Loaded {len(temp_df)} rows from mirror.")
            except Exception as e:
                print(f"Error processing mirror {url}: {e}")
    
    if all_dfs:
        final_df = pd.concat(all_dfs, ignore_index=True).drop_duplicates()
        
        # Split into chunks of 300,000 rows for massive volume
        chunk_size = 300000
        for i in range(0, len(final_df), chunk_size):
            chunk = final_df.iloc[i:i+chunk_size]
            part_num = (i // chunk_size) + 1
            filename = f"data/processed/urls_cleaned_part_{part_num}.csv.gz"
            chunk.to_csv(filename, index=False, compression='gzip')
            print(f"Saved {filename}: {len(chunk)} rows")
        
        if os.path.exists("data/processed/urls_cleaned.csv.gz"):
            os.remove("data/processed/urls_cleaned.csv.gz")

def download_email_dataset():
    print("--- Processing Phishing Emails (Ultimate Scale: 150K+) ---")
    mirrors = [
        "https://huggingface.co/datasets/HoangPhuc/data_spam_email/resolve/main/combined_data.csv",
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
                df = pd.read_csv(io.StringIO(r.text))
                # Detect columns flexibly
                text_col = [c for c in df.columns if c.lower() in ['text', 'message', 'email text', 'body']][0]
                label_col = [c for c in df.columns if c.lower() in ['label', 'spam/ham', 'email type', 'is_phishing']][0]
                
                temp_df = df[[text_col, label_col]].copy()
                temp_df.columns = ['text', 'label']
                # Truncate to keep size manageable but intelligence high
                temp_df['text'] = temp_df['text'].astype(str).str.slice(0, 5000)
                # Map labels: spam/phishing -> 1, ham/safe -> 0
                temp_df['label'] = temp_df['label'].apply(lambda x: 1 if str(x).lower() in ['spam', 'phishing', '1', '1.0', 'phish'] else 0)
                all_dfs.append(temp_df)
                print(f"Loaded {len(temp_df)} rows from mirror.")
            except Exception as e:
                print(f"Error processing mirror {url}: {e}")
    
    if all_dfs:
        final_df = pd.concat(all_dfs, ignore_index=True).drop_duplicates()
        
        # Split into chunks of 30,000 rows for better compatibility
        chunk_size = 30000
        for i in range(0, len(final_df), chunk_size):
            chunk = final_df.iloc[i:i+chunk_size]
            part_num = (i // chunk_size) + 1
            filename = f"data/processed/emails_cleaned_part_{part_num}.csv.gz"
            chunk.to_csv(filename, index=False, compression='gzip')
            print(f"Saved {filename}: {len(chunk)} rows")
        
        if os.path.exists("data/processed/emails_cleaned.csv.gz"):
            os.remove("data/processed/emails_cleaned.csv.gz")

if __name__ == "__main__":
    os.makedirs("data/raw", exist_ok=True)
    os.makedirs("data/processed", exist_ok=True)
    download_sms_spam()
    download_url_dataset()
    download_email_dataset()
