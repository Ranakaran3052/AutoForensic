import re

def analyze_ram_dump(dump_file_path):

    processes = set()
    domains = set()
    urls = set()
    ips = set()
    suspicious_commands = []

    process_pattern = r"[a-zA-Z0-9_\-]+\.exe"
    dns_pattern = r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}"
    ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
    url_pattern = r"https?://[^\s]+"

    suspicious_keywords = [
        "powershell",
        "cmd.exe",
        "mimikatz",
        "meterpreter",
        "keylogger",
        "ransom",
        "malware",
        "c2",
        "backdoor"
    ]

    try:
        print("[+] Reading RAM dump...")

        with open(dump_file_path, "rb") as f:
            content = f.read().decode(errors="ignore")

        print("[+] Extracting forensic artifacts from memory...")

        # Extract processes
        process_matches = re.findall(process_pattern, content)
        for p in process_matches:
            processes.add(p.lower())

        # Extract domains
        dns_matches = re.findall(dns_pattern, content)
        for d in dns_matches:
            domains.add(d.lower())

        # Extract IPs
        ip_matches = re.findall(ip_pattern, content)
        for ip in ip_matches:
            ips.add(ip)

        # Extract URLs
        url_matches = re.findall(url_pattern, content)
        for u in url_matches:
            urls.add(u)

        # Detect suspicious commands
        for keyword in suspicious_keywords:
            if keyword in content.lower():
                suspicious_commands.append(keyword)

    except Exception as e:
        print("Error analyzing RAM dump:", e)

    return {
        "processes": list(processes),
        "domains": list(domains),
        "ips": list(ips),
        "urls": list(urls),
        "suspicious_commands": suspicious_commands
    }