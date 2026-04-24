
import os

def split_file(file_path, chunk_size=45*1024*1024): # 45MB chunks (Safe for GitHub)
    if not os.path.exists(file_path):
        print(f"File {file_path} not found.")
        return

    file_size = os.path.getsize(file_path)
    print(f"Splitting {file_path} ({file_size / (1024*1024):.2f} MB)...")

    with open(file_path, 'rb') as f:
        chunk_num = 1
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            chunk_name = f"{file_path}.part{chunk_num}"
            with open(chunk_name, 'wb') as chunk_file:
                chunk_file.write(chunk)
            print(f"Created: {chunk_name}")
            chunk_num += 1

if __name__ == "__main__":
    # Robust path detection
    possible_paths = ["models/url_classifier.pkl", "../models/url_classifier.pkl"]
    target = None
    for p in possible_paths:
        if os.path.exists(p):
            target = p
            break
            
    if target:
        split_file(target)
        print("Done! You can now upload the .part files to GitHub.")
    else:
        print("Error: models/url_classifier.pkl not found in root or parent directory.")
