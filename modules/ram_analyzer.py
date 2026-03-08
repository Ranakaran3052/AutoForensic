import re
import os
import time
import json
from datetime import datetime

def analyze_ram_dump_ultra(dump_file_path, output_json="forensic_report.json"):
    if not os.path.exists(dump_file_path):
        print(f"[-] Error: File {dump_file_path} not found.")
        return None

    file_size = os.path.getsize(dump_file_path)
    
    patterns = {
        "processes": re.compile(rb"[a-zA-Z0-9_\-]+\.exe"),
        "ips": re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        "urls": re.compile(rb"https?://[^\s\x00-\x1f\x7f-\xff]+"),
    } 

    suspicious_keywords = [
        b"powershell", b"mimikatz", b"cobaltstrike", b"meterpreter", 
        b"ransom", b"agenttesla", b"backdoor", b"lsass.exe", b"updater.exe"
    ]

    # Keeping them as sets internally for speed and uniqueness
    results_set = {k: set() for k in ["processes", "ips", "urls", "keywords"]}
    
    CHUNK_SIZE = 1024 * 1024 * 40 
    OVERLAP = 1024
    bytes_read = 0
    start_time = time.time()

    try:
        with open(dump_file_path, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                
                bytes_read += len(chunk)
                elapsed = time.time() - start_time
                percent = (bytes_read / file_size) * 100
                speed = (bytes_read / 1024**2) / (elapsed if elapsed > 0 else 1)
                
                print(f"\rProgress: [{int(percent/2)*'=':50}] {percent:.1f}% | Speed: {speed:.2f} MB/s", end="")

                # Extraction logic
                for p in patterns["processes"].findall(chunk):
                    results_set["processes"].add(p.decode(errors="ignore").lower())
                for ip in patterns["ips"].findall(chunk):
                    results_set["ips"].add(ip.decode(errors="ignore"))
                for u in patterns["urls"].findall(chunk):
                    results_set["urls"].add(u.decode(errors="ignore"))

                chunk_lower = chunk.lower()
                for key in suspicious_keywords:
                    if key in chunk_lower:
                        results_set["keywords"].add(key.decode(errors="ignore"))

                if len(chunk) == CHUNK_SIZE:
                    f.seek(f.tell() - OVERLAP)

        # CRITICAL FIX: Convert sets to lists before returning
        final_results = {k: sorted(list(v)) for k, v in results_set.items()}
        
        print(f"\n\n[+] Scan Complete. Saving to {output_json}...")
        save_to_json(final_results, output_json, dump_file_path)
        
        return final_results

    except Exception as e:
        print(f"\n[-] Error: {e}")
        return None

def save_to_json(data, filename, source):
    report = {
        "metadata": {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "source_file": source
        },
        "findings": data # data is already converted to lists now
    }
    with open(filename, "w") as jf:
        json.dump(report, jf, indent=4)