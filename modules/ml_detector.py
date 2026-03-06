import re
import math
import requests
import numpy as np
from collections import Counter
from sklearn.ensemble import IsolationForest

# ==============================
# CONFIG
# ==============================
VT_API_KEY = "a0e9a18a67d6c72fa04d0b0dbf5cca990b81b7f9e60fcc73af45900c351dd5a2"
ENTROPY_THRESHOLD = 3.5


# ==============================
# 1️⃣ DNS EXTRACTION FROM DUMP
# ==============================
def extract_dns_from_dump(dump_file_path):
    dns_pattern = r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}"
    domains = set()
    try:
        # Open in Binary Mode ('rb') to handle non-text characters in dumps
        with open(dump_file_path, "rb") as f:
            content = f.read().decode("latin-1", errors="ignore")
            matches = re.findall(dns_pattern, content)
            for match in matches:
                domains.add(match.lower())
    except Exception as e:
        print(f"Error: {e}")
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
    # Split into parts to avoid "bad" matching "badger.com"
    parts = domain.lower().split('.')
    suspicious_tlds = { "malware", "stealer", "ransom", "exploit", "c2", "command", "control",
        "botnet", "free","breach", "leak", "dark", "web", 
        "hacker", "attack","free-login", "darkweb", "xyz" , "top", "club", "online" , "site", "website", "net",
        "org", "info", "biz", "co", "io", "me", "us", "cc", "pw", "tk", "ml", "ga", "cf", "gq" ,
        "drugs", "casino" , "apk", "crypter", "keylogger",
        "miner", "ransomware", "spyware", "trojan", "virus", "worm", "backdoor", "ddos", "phishing", 
        "scam", "fraud", "suspicious", "danger", "threat"}
    
    # Check TLD
    if parts[-1] in suspicious_tlds:
        return True
        
    # Check Keywords
    malicious_terms = {"malware", "c2", "stealer", "phish"}
    return any(term in domain for term in malicious_terms) 



# ==============================
# 4️⃣ VIRUSTOTAL CHECK
# ==============================
def check_virustotal_domain(domain):

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VT_API_KEY}

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

def detect_anomaly(suspicious_log_count, suspicious_dns_count):
    # Base calculation that doesn't rely ONLY on the ML model
    # This prevents the "stuck at 2" issue
    base_risk = (suspicious_log_count * 10) + (suspicious_dns_count * 5)
    
    # ML Component
    normal_data = np.array([[0,0], [1,0], [0,1], [2,1], [1,2]])
    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(normal_data)
    
    test_sample = np.array([[suspicious_log_count, suspicious_dns_count]])
    is_anomaly = model.predict(test_sample)[0] # -1 if anomaly
    
    # If ML flags it as an anomaly, boost the score
    if is_anomaly == -1:
        base_risk += 25 
        
    final_score = min(base_risk, 100)
    
    if final_score >= 80: status = "CRITICAL"
    elif final_score >= 50: status = "HIGH"
    elif final_score >= 25: status = "MEDIUM"
    else: status = "LOW"
    
    return status, final_score


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

    suspicious_log_count =  suspicious_log_count  
    # This should be passed as an argument; using the provided value

    # suspicious_logs = []  # parse_log is not defined; replaced with empty list
    # suspicious_dns=[]
    # suspicious_logs_count = len(suspicious_logs)
    # suspicious_dns_count=len(suspicious_dns)

    status, risk_score = detect_anomaly(
        suspicious_log_count,
        suspicious_dns_count
    )

    return {
        "domains_analyzed": analysis_results,
        "suspicious_dns_count": suspicious_dns_count,
        "suspicious_logs_count": suspicious_log_count,
        "final_status": status,
        "risk_score": risk_score
    }