import re

def parse_log(file_path):

    suspicious = []

    # Regex patterns
    pid_pattern = r"\bpid[=: ]?(\d+)\b|\[(\d+)\]"
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    domain_pattern = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
    user_pattern = r"user\s+(\w+)|for\s+(\w+)"
    command_pattern = r"(powershell|cmd\.exe|bash|nc|netcat|python|perl|wget|curl)"

    with open(file_path, "r", errors="ignore") as f:
        for line in f:

            l = line.lower()
            event = None

            # ---------------- PID ----------------
            pid_match = re.search(pid_pattern, line, re.IGNORECASE)
            pid = None
            if pid_match:
                pid = pid_match.group(1) or pid_match.group(2)

            # ---------------- USER ----------------
            user_match = re.search(user_pattern, line, re.IGNORECASE)
            user = None
            if user_match:
                user = user_match.group(1) or user_match.group(2)

            # ---------------- DOMAIN ----------------
            domain_match = re.search(domain_pattern, line)
            domain = domain_match.group(0) if domain_match else None

            # ---------------- IP ----------------
            ip_match = re.search(ip_pattern, line)
            ip = ip_match.group(0) if ip_match else None

            # ---------------- COMMAND ----------------
            command_match = re.search(command_pattern, line, re.IGNORECASE)
            command = command_match.group(0) if command_match else None

            # ---------------- EVENT DETECTION ----------------

            if re.search(r"failed login|authentication failure|login failed", l):
                event = "Brute Force Login Attempt"

            elif re.search(r"permission denied|access denied|unauthorized", l):
                event = "Unauthorized Access Attempt"

            elif re.search(r"sudo|root access|privilege escalation", l):
                event = "Privilege Escalation Attempt"

            elif re.search(r"wget|curl|download", l):
                event = "Possible Malware Download"

            elif re.search(r"powershell|cmd.exe|bash -i|nc -e", l):
                event = "Suspicious Command Execution"

            elif re.search(r"dns query|resolve|lookup", l):
                event = "Suspicious DNS Activity"

            elif re.search(r"connection to|outbound connection|c2", l):
                event = "Possible Command & Control Communication"

            elif re.search(r"failed|error|denied", l):
                event = "System Security Error"

            # ---------------- BUILD RESULT ----------------

            if event:

                result = f"[EVENT: {event}]"

                if pid:
                    result += f" [PID: {pid}]"

                if user:
                    result += f" [USER: {user}]"

                if ip:
                    result += f" [IP: {ip}]"

                if domain:
                    result += f" [DOMAIN: {domain}]"

                if command:
                    result += f" [COMMAND: {command}]"

                result += f" -> {line.strip()}"

                suspicious.append(result)

    return suspicious