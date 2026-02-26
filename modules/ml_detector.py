import re
import math
import requests
import numpy as np
from collections import Counter
from sklearn.ensemble import IsolationForest

# ==============================
# CONFIG
# ==============================
VT_API_KEY = "YOUR_API_KEY_HERE"
ENTROPY_THRESHOLD = 3.5


# ==============================
# 1️⃣ DNS EXTRACTION FROM DUMP
# ==============================
def extract_dns_from_dump(dump_file_path):
    dns_pattern = r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}"
    domains = set()

    try:
        with open(dump_file_path, "r", errors="ignore") as f:
            content = f.read()
            matches = re.findall(dns_pattern, content)
            for match in matches:
                domains.add(match.lower())
    except Exception as e:
        print("Error reading dump file:", e)

    return list(domains)


# ==============================
# 2️⃣ ENTROPY CALCULATION
# ==============================
def calculate_entropy(domain):
    domain = domain.replace(".", "")
    length = len(domain)

    if length == 0:
        return 0

    frequencies = Counter(domain)
    entropy = 0

    for count in frequencies.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)

    return entropy


# ==============================
# 3️⃣ LOCAL REPUTATION CHECK
# ==============================
def check_domain_reputation(domain):
    known_bad_keywords = [
        "malware", "phishing", "stealer", "ransom", "exploit", "c2", "command", "control",
        "botnet", "free", "login","breach", "leak", "dark", "web", 
        "hacker", "attack", "ddos", "scam", "fraud", "suspicious", "danger", "threat",
        "free-login", "darkweb", "xyz" , "top", "club", "online" , "site", "website", "net",
        "org", "info", "biz", "co", "io", "me", "us", "cc", "pw", "tk", "ml", "ga", "cf", "gq" ,
        "drugs", "casino" , "apk", "crypter", "keylogger",
        "miner", "ransomware", "spyware", "trojan", "virus", "worm", "backdoor", "ddos", "phishing", 
        "scam", "fraud", "suspicious", "danger", "threat"
    ]

    for keyword in known_bad_keywords:
        if keyword in domain:
            return True

    return False


# ==============================
# 4️⃣ VIRUSTOTAL CHECK
# ==============================
def check_virustotal_domain(domain):

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": a0e9a18a67d6c72fa04d0b0dbf5cca990b81b7f9e60fcc73af45900c351dd5a2}

    try:
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]

            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0)
            }
        else:
            return {"malicious": 0, "suspicious": 0}

    except:
        return {"malicious": 0, "suspicious": 0}
        raise


# ==============================
# 5️⃣ FULL DNS ANALYSIS
# ==============================
def analyze_domains(domains):

    analyzed_results = []
    suspicious_dns_count = 0

    for domain in domains:

        entropy = calculate_entropy(domain)
        high_entropy = entropy > ENTROPY_THRESHOLD

        bad_reputation = check_domain_reputation(domain)

        vt_result = check_virustotal_domain(domain)

        # Threat Scoring Logic
        threat_score = 0

        if bad_reputation:
            threat_score += 3

        if high_entropy:
            threat_score += 2

        threat_score += (vt_result["malicious"] * 2)
        threat_score += vt_result["suspicious"]

        if threat_score > 3:
            suspicious_dns_count += 1

        analyzed_results.append({
            "domain": domain,
            "entropy": round(entropy, 2),
            "high_entropy": high_entropy,
            "vt_malicious": vt_result["malicious"],
            "vt_suspicious": vt_result["suspicious"],
            "threat_score": threat_score
        })

    return analyzed_results, suspicious_dns_count


# ==============================
# 6️⃣ ML ANOMALY DETECTION
# ==============================
def detect_anomaly(suspicious_log_count, suspicious_dns_count=0):

    # Weighted Risk Score
    risk_score = (suspicious_log_count * 0.6) + (suspicious_dns_count * 0.4)

    # Normal baseline data
    normal_data = np.array([
        [1, 0],
        [2, 1],
        [1, 1],
        [3, 0],
        [2, 2],
        [1, 0]
    ])

    model = IsolationForest(contamination=0.2, random_state=42)
    model.fit(normal_data)

    test_sample = np.array([[suspicious_log_count, suspicious_dns_count]])
    prediction = model.predict(test_sample)

    # Final Classification
    if prediction[0] == -1 and risk_score > 5:
        status = "HIGH RISK - MALICIOUS"
    elif prediction[0] == -1:
        status = "MEDIUM RISK - SUSPICIOUS"
    elif risk_score > 5:
        status = "MEDIUM RISK - SUSPICIOUS"
    else:
        status = "LOW RISK - NORMAL"

    return status, round(risk_score, 2)


# ==============================
# 7️⃣ MAIN PIPELINE FUNCTION
# ==============================
def run_forensic_dns_pipeline(dump_file_path, suspicious_log_count):

    print("\n[+] Extracting DNS from dump...")
    domains = extract_dns_from_dump(dump_file_path)

    print(f"[+] Found {len(domains)} unique domains")

    print("[+] Running DNS threat intelligence analysis...")
    analysis_results, suspicious_dns_count = analyze_domains(domains)

    print("[+] Running ML anomaly detection...")

    suspicious_logs =parse_log(args.log ) if args.log else []
    suspicious_dns=[]
    suspicious_logs_count = len(suspicious_logs)
    suspicious_dns_count=len(suspicious_dns)

    status, risk_score = detect_anomaly(
        suspicious_log_count,
        suspicious_dns_count
    )

    return {
        "domains_analyzed": analysis_results,
        "suspicious_dns_count": suspicious_dns_count,
        "final_status": status,
        "risk_score": risk_score
    }