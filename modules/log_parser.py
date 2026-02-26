import re

def parse_log(file_path):
    suspicious = []

    with open(file_path, "r") as f:
        for line in f:
            if re.search(r"failed|error|denied|unauthorized", line, re.IGNORECASE):
                suspicious.append(line.strip())

    return suspicious