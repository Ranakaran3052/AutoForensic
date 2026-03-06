import re
import math
import requests
from collections import Counter

VT_API_KEY = "YOUR_NEW_KEY"
ENTROPY_THRESHOLD = 3.5


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


def analyze_domains(domains):
    analyzed_results = []
    suspicious_dns_count = 0

    for domain in domains:
        entropy = calculate_entropy(domain)
        high_entropy = entropy > ENTROPY_THRESHOLD

        threat_score = 2 if high_entropy else 0

        if threat_score > 1:
            suspicious_dns_count += 1

        analyzed_results.append({
            "domain": domain,
            "entropy": round(entropy, 2),
            "high_entropy": high_entropy,
            "threat_score": threat_score
        })

    return analyzed_results, suspicious_dns_count


def run_forensic_dns_pipeline(dump_file_path):

    domains = extract_dns_from_dump(dump_file_path)
    print(f"[+] Found {len(domains)} unique domains in the dump.")

    analysis_results, suspicious_dns_count = analyze_domains(domains)

    return {
        "domains_analyzed": analysis_results,
        "suspicious_dns_count": suspicious_dns_count,

    }