import re
import math

# Simple domain regex
DOMAIN_REGEX = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"

SUSPICIOUS_KEYWORDS = [
    "malware", "phishing", "exploit",
    "command", "control", "c2", "botnet"
]

def calculate_entropy(domain):
    """
    Calculate Shannon entropy for basic DGA detection
    """
    prob = [float(domain.count(c)) / len(domain) for c in dict.fromkeys(list(domain))]
    entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy

def extract_dns_from_dump(file_path):
    dns_queries = []
    suspicious_domains = []

    with open(file_path, "r", errors="ignore") as f:
        content = f.read()

    domains = re.findall(DOMAIN_REGEX, content)

    for domain in domains:
        entropy = calculate_entropy(domain)

        # Basic suspicious logic
        if any(keyword in domain.lower() for keyword in SUSPICIOUS_KEYWORDS) or entropy > 3.5:
            suspicious_domains.append((domain, round(entropy, 2)))

        dns_queries.append(domain)

    return dns_queries, suspicious_domains