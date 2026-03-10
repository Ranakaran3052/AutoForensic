import re
import math
import whois
import tldextract
from datetime import datetime, timezone

DOMAIN_REGEX = r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}"

SUSPICIOUS_KEYWORDS = [
    "malware", "phishing", "exploit",
    "command", "control", "c2", "botnet",
    "free", "breach", "leak", "dark", "web",
    "stealer", "ransom", "hacker", "attack", "ddos",
    "free-login", "darkweb", "xyz", "top", "club", "online",
    "site", "website", "net", "login", "auth", "secure", "update", "admin", "portal"
]

SAFE_DOMAINS = [
    "google.com", "microsoft.com", "amazonaws.com",
    "github.com", "windows.com", "cloudflare.com",
    "tryhackme.com", "linkedin.com", "facebook.com", "twitter.com",
    "apple.com", "oracle.com", "ibm.com", "adobe.com",
    "paypal.com", "dropbox.com", "slack.com", "zoom.us"
]

# High-risk TLDs commonly abused for malicious activity
HIGH_RISK_TLDS = {
    "xyz", "top", "club", "online", "site", "tk", "ml", "ga", "cf",
    "gq", "pw", "cc", "ws", "info", "biz", "buzz", "icu", "cyou"
}

# Known malicious domain patterns (simulating a threat-intel blocklist)
KNOWN_MALICIOUS_PATTERNS = [
    r".*-update\d+\.",
    r".*\d{4,}\.",           # Many digits in subdomain
    r".*secure-.*login\.",
    r".*paypal.*verify\.",
    r".*[a-z]{20,}\.",       # Very long random-looking subdomain
]


def calculate_entropy(domain):
    prob = [float(domain.count(c)) / len(domain) for c in dict.fromkeys(domain)]
    entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy


def get_domain_age_days(domain):
    """
    Query WHOIS to get domain registration age in days.
    Returns None if lookup fails.
    """
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            now = datetime.now(timezone.utc)
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)
            return (now - creation_date).days
    except Exception:
        pass
    return None


def score_domain(domain):
    """
    Score a domain from 0 (safe) to 100 (highly suspicious).
    Returns (score, reasons[]) tuple.
    """
    score = 0
    reasons = []

    extracted = tldextract.extract(domain)
    registered_domain = extracted.registered_domain  # e.g. "example.com"
    subdomain = extracted.subdomain
    tld = extracted.suffix
    sld = extracted.domain  # second-level domain

    # 1. High-risk TLD check
    if tld in HIGH_RISK_TLDS:
        score += 25
        reasons.append(f"High-risk TLD: .{tld}")

    # 2. Suspicious keyword in domain
    matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in domain]
    if matched_keywords:
        score += min(20, len(matched_keywords) * 7)
        reasons.append(f"Suspicious keywords: {matched_keywords}")

    # 3. High entropy (DGA-like)
    entropy = calculate_entropy(sld)
    if entropy > 3.7:
        score += 20
        reasons.append(f"High entropy SLD ({entropy:.2f}) - possible DGA")

    # 4. DNS tunneling (very long domain)
    if len(domain) > 40:
        score += 15
        reasons.append(f"Long domain ({len(domain)} chars) - possible DNS tunneling")

    # 5. Excessive subdomains
    subdomain_count = len(subdomain.split(".")) if subdomain else 0
    if subdomain_count >= 3:
        score += 10
        reasons.append(f"Excessive subdomains ({subdomain_count} levels)")

    # 6. Known malicious pattern match
    for pattern in KNOWN_MALICIOUS_PATTERNS:
        if re.match(pattern, domain):
            score += 30
            reasons.append(f"Matches known malicious pattern: {pattern}")
            break

    # 7. WHOIS domain age check (newly registered = suspicious)
    age_days = get_domain_age_days(registered_domain)
    if age_days is not None:
        if age_days < 30:
            score += 30
            reasons.append(f"Very newly registered domain ({age_days} days old)")
        elif age_days < 180:
            score += 15
            reasons.append(f"Recently registered domain ({age_days} days old)")
    else:
        # WHOIS lookup failure can itself be suspicious
        score += 5
        reasons.append("WHOIS lookup failed (possibly privacy-protected or unregistered)")

    return min(score, 100), reasons


def classify_domain(score):
    if score >= 70:
        return "MALICIOUS"
    elif score >= 40:
        return "SUSPICIOUS"
    elif score >= 20:
        return "LOW-RISK"
    else:
        return "LIKELY SAFE"


def extract_dns_from_dump(file_path):
    dns_queries = set()
    results = []

    suspicious_domains = []
    dga_domains = []
    tunneling_domains = []

    with open(file_path, "rb") as f:
        content = f.read().decode(errors="ignore")

    domains = re.findall(DOMAIN_REGEX, content)

    for domain in domains:
        domain = domain.lower()

        # Skip known safe domains
        if any(safe in domain for safe in SAFE_DOMAINS):
            continue

        if domain in dns_queries:
            continue
        dns_queries.add(domain)

        entropy = calculate_entropy(domain)

        # Legacy categorization (kept for backward compatibility)
        if any(keyword in domain for keyword in SUSPICIOUS_KEYWORDS):
            suspicious_domains.append(domain)
        if entropy > 3.7:
            dga_domains.append((domain, round(entropy, 2)))
        if len(domain) > 40:
            tunneling_domains.append(domain)

        # New: full domain scoring
        score, reasons = score_domain(domain)
        classification = classify_domain(score)

        results.append({
            "domain": domain,
            "score": score,
            "classification": classification,
            "entropy": round(entropy, 2),
            "reasons": reasons
        })

    # Sort by risk score descending
    results.sort(key=lambda x: x["score"], reverse=True)

    return {
        "all_domains": list(dns_queries),
        "scored_results": results,
        # Legacy outputs
        "suspicious_domains": suspicious_domains,
        "dga_domains": dga_domains,
        "tunneling_domains": tunneling_domains,
    }


def print_report(results):
    print(f"\n{'='*60}")
    print(f"  DNS DUMP ANALYSIS REPORT")
    print(f"{'='*60}")
    print(f"  Total unique domains found: {len(results['all_domains'])}\n")

    for entry in results["scored_results"]:
        label = entry["classification"]
        color = {
            "MALICIOUS":    "\033[91m",  # red
            "SUSPICIOUS":   "\033[93m",  # yellow
            "LOW-RISK":     "\033[94m",  # blue
            "LIKELY SAFE":  "\033[92m",  # green
        }.get(label, "")
        reset = "\033[0m"

        print(f"  {color}[{label}]{reset} {entry['domain']}")
        print(f"    Score   : {entry['score']}/100")
        print(f"    Entropy : {entry['entropy']}")
        if entry["reasons"]:
            print(f"Reasons:")
            for r in entry["reasons"]:
                print(f"      - {r}")
        print()


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python solution.py <dns_dump_file>")
        sys.exit(1)

    output = extract_dns_from_dump(sys.argv[1])
    print_report(output)