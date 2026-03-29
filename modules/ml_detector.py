import re
import math
import os
import requests
import numpy as np
from collections import Counter
from sklearn.ensemble import IsolationForest

# ── optional: pip install python-evtx ──
try:
    import Evtx.Evtx as evtx # type: ignore
    import xml.etree.ElementTree as ET
    EVTX_AVAILABLE = True
except ImportError:
    EVTX_AVAILABLE = False

# ==============================
# CONFIG
# ==============================
VT_API_KEY = "your_api_key_here"
ENTROPY_THRESHOLD = 3.5

# ── Regex Patterns ──────────────────────────────────────────────────
PATTERNS = {
    "domain":   re.compile(r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}"),
    "ip":       re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
                           r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),
    "url":      re.compile(r"https?://[^\s\"'<>\]]{4,}"),
    "email":    re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}"),
    "filepath": re.compile(r"(?:[A-Za-z]:\\|/(?:etc|var|tmp|home|usr|proc|sys)"
                           r")[^\s\"'<>]{3,}"),
    "registry": re.compile(r"HKEY_[A-Z_]+(?:\\[^\s\"'<>\\]{1,100})+",
                           re.IGNORECASE),
    "process":  re.compile(r"([A-Za-z0-9_\-]+\.exe)(?:\s+\(PID\s*:?\s*(\d+)\))?",
                           re.IGNORECASE),
    "cmd":      re.compile(r"(?:cmd\.exe|powershell(?:\.exe)?|bash|sh|wscript"
                           r"|cscript|mshta|rundll32|regsvr32)"
                           r"[^\n\r]{0,300}", re.IGNORECASE),
}

# Artifacts unique to structured log lines
LOG_LINE_PATTERN = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[^\s]*)\s+"
    r"(?P<level>INFO|WARN(?:ING)?|ERROR|DEBUG|CRITICAL)?\s*"
    r"(?P<message>.+)",
    re.IGNORECASE
)

SAFE_DOMAINS = {
    "google.com", "microsoft.com", "amazonaws.com", "github.com",
    "windows.com", "cloudflare.com", "tryhackme.com", "linkedin.com",
    "facebook.com", "twitter.com", "apple.com", "oracle.com",
    "ibm.com", "adobe.com", "paypal.com", "dropbox.com",
    "slack.com", "zoom.us", "windowsupdate.com", "digicert.com",
}

PRIVATE_IP_RANGES = re.compile(
    r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|::1|fe80:)"
)


# ==============================
# FILE TYPE DETECTION
# ==============================
def detect_file_type(file_path: str) -> str:
    ext = os.path.splitext(file_path)[1].lower()
    if ext in (".evtx",):
        return "evtx"
    if ext in (".log", ".txt", ".csv", ".tsv"):
        return "log"
    # Binary dump: .dmp .raw .bin .mem or no extension
    return "dump"


# ==============================
# RAW CONTENT READER
# ==============================
def read_raw_content(file_path: str) -> str:
    """Read any file as text, handling binary gracefully."""
    with open(file_path, "rb") as f:
        return f.read().decode("latin-1", errors="ignore")


# ==============================
# EVTX READER  (Windows Event Log)
# ==============================
def read_evtx_content(file_path: str) -> str:
    """Extract all record XML as a single text blob."""
    if not EVTX_AVAILABLE:
        print("[!] python-evtx not installed — falling back to raw read")
        return read_raw_content(file_path)

    lines = []
    with evtx.Evtx(file_path) as log:
        for record in log.records():
            try:
                xml_str = record.xml()
                root = ET.fromstring(xml_str)
                # Flatten all text nodes
                lines.append(" ".join(root.itertext()))
            except Exception:
                continue
    return "\n".join(lines)


# ==============================
# 1. UNIVERSAL ARTIFACT EXTRACTOR
# ==============================
def extract_artifacts_from_file(file_path: str) -> dict:
    """
    Extracts domains, IPs, URLs, emails, file paths, registry keys,
    processes, and suspicious commands from any supported file type.
    """
    file_type = detect_file_type(file_path)

    if file_type == "evtx":
        content = read_evtx_content(file_path)
    else:
        content = read_raw_content(file_path)

    artifacts = _extract_artifacts_from_text(content, file_type)
    artifacts["source_file"] = os.path.basename(file_path)
    artifacts["file_type"]   = file_type
    return artifacts


def _extract_artifacts_from_text(content: str, file_type: str) -> dict:
    domains   = set()
    ips       = set()
    urls      = set()
    emails    = set()
    filepaths = set()
    registry  = set()
    processes = set()
    sus_cmds  = []
    log_events= []

    # ── Extract all pattern matches ──────────────────────────
    for url in PATTERNS["url"].findall(content):
        urls.add(url.rstrip(".,;)'\""))

    for email in PATTERNS["email"].findall(content):
        emails.add(email.lower())

    for fp in PATTERNS["filepath"].findall(content):
        filepaths.add(fp)

    for reg in PATTERNS["registry"].findall(content):
        registry.add(reg)

    for match in PATTERNS["process"].finditer(content):
        proc = match.group(1).lower()
        pid  = match.group(2) or "?"
        processes.add(f"{proc} (PID: {pid})")

    for cmd in PATTERNS["cmd"].findall(content):
        cleaned = cmd.strip()
        if cleaned and cleaned not in sus_cmds:
            sus_cmds.append(cleaned)

    # ── Domains (filter safe + extract from URLs) ─────────────
    raw_domains = PATTERNS["domain"].findall(content)
    for d in raw_domains:
        d = d.lower().rstrip(".")
        if not any(safe in d for safe in SAFE_DOMAINS):
            domains.add(d)

    # ── IPs (filter private ranges) ───────────────────────────
    for ip in PATTERNS["ip"].findall(content):
        if not PRIVATE_IP_RANGES.match(ip):
            ips.add(ip)

    # ── Log-specific: parse structured lines ──────────────────
    if file_type in ("log", "evtx"):
        for line in content.splitlines():
            m = LOG_LINE_PATTERN.match(line.strip())
            if m:
                log_events.append({
                    "timestamp": m.group("timestamp"),
                    "level":     m.group("level") or "INFO",
                    "message":   m.group("message")[:300],
                })

    return {
        "domains":            sorted(domains),
        "ips":                sorted(ips),
        "urls":               sorted(urls),
        "emails":             sorted(emails),
        "filepaths":          sorted(filepaths),
        "registry_keys":      sorted(registry),
        "processes":          sorted(processes),
        "suspicious_commands": sus_cmds[:50],
        "log_events":         log_events[:500],   # cap for memory
    }


# ==============================
# MULTI-FILE PIPELINE ENTRY
# ==============================
def extract_from_all_files(file_paths: list) -> dict:
    """
    Accepts a mixed list of dump + log file paths.
    Merges all artifacts into one unified result.
    """
    merged = {
        "domains":             set(),
        "ips":                 set(),
        "urls":                set(),
        "emails":              set(),
        "filepaths":           set(),
        "registry_keys":       set(),
        "processes":           set(),
        "suspicious_commands": [],
        "log_events":          [],
        "sources":             [],
    }

    for path in file_paths:
        if not os.path.exists(path):
            print(f"[!] File not found, skipping: {path}")
            continue

        print(f"[+] Processing: {path}")
        result = extract_artifacts_from_file(path)

        merged["domains"].update(result["domains"])
        merged["ips"].update(result["ips"])
        merged["urls"].update(result["urls"])
        merged["emails"].update(result["emails"])
        merged["filepaths"].update(result["filepaths"])
        merged["registry_keys"].update(result["registry_keys"])
        merged["processes"].update(result["processes"])
        merged["suspicious_commands"].extend(result["suspicious_commands"])
        merged["log_events"].extend(result["log_events"])
        merged["sources"].append({
            "file":      result["source_file"],
            "type":      result["file_type"],
            "domain_ct": len(result["domains"]),
            "ip_ct":     len(result["ips"]),
            "url_ct":    len(result["urls"]),
        })

    # Deduplicate lists
    merged["suspicious_commands"] = list(dict.fromkeys(merged["suspicious_commands"]))
    merged["domains"]      = sorted(merged["domains"])
    merged["ips"]          = sorted(merged["ips"])
    merged["urls"]         = sorted(merged["urls"])
    merged["emails"]       = sorted(merged["emails"])
    merged["filepaths"]    = sorted(merged["filepaths"])
    merged["registry_keys"]= sorted(merged["registry_keys"])
    merged["processes"]    = sorted(merged["processes"])

    return merged


# ==============================
# 2. ENTROPY CALCULATION
# ==============================
def calculate_entropy(domain: str) -> float:
    domain = domain.replace(".", "")
    length = len(domain)
    if length == 0:
        return 0.0
    frequencies = Counter(domain)
    return -sum((c / length) * math.log2(c / length)
                for c in frequencies.values())


# ==============================
# 3. LOCAL REPUTATION CHECK
# ==============================
def check_domain_reputation(domain: str) -> bool:
    parts = domain.lower().split(".")
    suspicious_tlds = {
        "xyz", "top", "club", "online", "site", "tk", "ml",
        "ga", "cf", "gq", "pw", "cc", "ws", "info", "biz",
        "buzz", "icu", "cyou", "apk",
    }
    malicious_terms = {
        "malware", "c2", "stealer", "phish", "ransom",
        "botnet", "exploit", "darkweb", "keylogger",
    }
    if parts[-1] in suspicious_tlds:
        return True
    return any(term in domain for term in malicious_terms)


# ==============================
# 4. VIRUSTOTAL CHECK
# ==============================
def check_virustotal_domain(domain: str) -> dict:
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            stats = (response.json()["data"]["attributes"]
                     ["last_analysis_stats"])
            return {
                "malicious":  stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
            }
    except Exception:
        pass
    return {"malicious": 0, "suspicious": 0}


# ==============================
# 5. FULL DNS ANALYSIS
# ==============================
def analyze_domains(domains: list) -> tuple:
    analyzed_results    = []
    suspicious_dns_count = 0

    for domain in domains:
        entropy      = calculate_entropy(domain)
        high_entropy = entropy > ENTROPY_THRESHOLD
        bad_rep      = check_domain_reputation(domain)
        vt_result    = check_virustotal_domain(domain)

        threat_score  = 0
        classification = "LIKELY SAFE"

        if bad_rep:
            threat_score += 3
        if high_entropy:
            threat_score += 2
        threat_score += vt_result["malicious"]  * 2
        threat_score += vt_result["suspicious"]

        if threat_score >= 7:
            classification = "MALICIOUS"
        elif threat_score >= 4:
            classification = "SUSPICIOUS"
        elif threat_score >= 2:
            classification = "LOW-RISK"

        if threat_score > 3:
            suspicious_dns_count += 1

        analyzed_results.append({
            "domain":         domain,
            "entropy":        round(entropy, 2),
            "high_entropy":   high_entropy,
            "vt_malicious":   vt_result["malicious"],
            "vt_suspicious":  vt_result["suspicious"],
            "threat_score":   threat_score,
            "score":          min(threat_score * 10, 100),
            "classification": classification,
            "reasons": _build_reasons(bad_rep, high_entropy, vt_result, domain),
        })

    return analyzed_results, suspicious_dns_count


def _build_reasons(bad_rep, high_entropy, vt_result, domain):
    reasons = []
    if bad_rep:
        reasons.append("Suspicious TLD or malicious keyword match")
    if high_entropy:
        reasons.append(f"High entropy — possible DGA")
    if vt_result["malicious"] > 0:
        reasons.append(f"VirusTotal: {vt_result['malicious']} malicious detections")
    if vt_result["suspicious"] > 0:
        reasons.append(f"VirusTotal: {vt_result['suspicious']} suspicious flags")
    if len(domain) > 40:
        reasons.append("Long domain — possible DNS tunneling")
    return reasons


# ==============================
# 6. ML ANOMALY DETECTION
# ==============================
def detect_anomaly(suspicious_log_count: int, suspicious_dns_count: int) -> tuple:
    base_risk = (suspicious_log_count * 10) + (suspicious_dns_count * 5)

    normal_data = np.array([[0,0],[1,0],[0,1],[2,1],[1,2]])
    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(normal_data)

    test_sample = np.array([[suspicious_log_count, suspicious_dns_count]])
    if model.predict(test_sample)[0] == -1:
        base_risk += 25

    final_score = min(base_risk, 100)

    if   final_score >= 80: status = "CRITICAL"
    elif final_score >= 50: status = "HIGH"
    elif final_score >= 25: status = "MEDIUM"
    else:                   status = "LOW"

    return status, final_score


# ==============================
# 7. MAIN PIPELINE
# ==============================
def run_forensic_dns_pipeline(file_paths: list, suspicious_log_count: int = 0) -> dict:
    """
    file_paths: list of dump and/or log file paths (mixed types supported)
    """
    print("\n[+] Extracting artifacts from files...")
    all_artifacts = extract_from_all_files(file_paths)

    domains = all_artifacts["domains"]
    print(f"[+] Found {len(domains)} unique domains across all files")
    print(f"[+] Found {len(all_artifacts['ips'])} external IPs")
    print(f"[+] Found {len(all_artifacts['urls'])} URLs")
    print(f"[+] Found {len(all_artifacts['emails'])} email addresses")
    print(f"[+] Found {len(all_artifacts['processes'])} processes")
    print(f"[+] Found {len(all_artifacts['log_events'])} structured log events")

    print("\n[+] Running DNS threat intelligence analysis...")
    analysis_results, suspicious_dns_count = analyze_domains(domains)

    # Auto-count suspicious logs if not provided
    if suspicious_log_count == 0:
        suspicious_log_count = sum(
            1 for e in all_artifacts["log_events"]
            if e["level"] in ("ERROR", "CRITICAL", "WARNING", "WARN")
        )

    print("[+] Running ML anomaly detection...")
    status, risk_score = detect_anomaly(suspicious_log_count, suspicious_dns_count)

    return {
        # DNS
        "domains_analyzed":     analysis_results,
        "suspicious_dns_count": suspicious_dns_count,
        # Other artifacts
        "ips":                  all_artifacts["ips"],
        "urls":                 all_artifacts["urls"],
        "emails":               all_artifacts["emails"],
        "filepaths":            all_artifacts["filepaths"],
        "registry_keys":        all_artifacts["registry_keys"],
        "processes":            all_artifacts["processes"],
        "suspicious_commands":  all_artifacts["suspicious_commands"],
        "log_events":           all_artifacts["log_events"],
        "sources":              all_artifacts["sources"],
        # Scoring
        "suspicious_logs_count": suspicious_log_count,
        "final_status":          status,
        "risk_score":            risk_score,
    }