import time
import hashlib
import os
import requests


FOLDER_TO_WATCH = "C:\Users\user\Desktop\Git"  
API_KEY = ""  
CHECK_INTERVAL = 5  

def get_file_hash(file_path):
    with open(file_path, "rb") as f:
        file_data = f.read()
    return hashlib.sha256(file_data).hexdigest()

def check_file_with_virustotal(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": API_KEY
    }
    response = requests.get(url, headers=headers)
    return response.json()


def monitor_folder():
    known_files = set(os.listdir(FOLDER_TO_WATCH))
    print("🔍 מתחיל מעקב...")                       
    while True:                    
        current_files = set(os.listdir(FOLDER_TO_WATCH))
        new_files = current_files - known_files
        for file_name in new_files:
            file_path = os.path.join(FOLDER_TO_WATCH, file_name)
            print(f"🆕 קובץ חדש זוהה: {file_name}")
            try:
                file_hash = get_file_hash(file_path)
                result = check_file_with_virustotal(file_hash)
                print(f"תוצאה מ-VirusTotal: {result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})}")
            except Exception as e:
                print(f"שגיאה בסריקת הקובץ: {e}")
        known_files = current_files
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    monitor_folder()

