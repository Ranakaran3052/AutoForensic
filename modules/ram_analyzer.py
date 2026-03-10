import re
import os
import time
import json
import hashlib
from datetime import datetime

# ==============================
# CASE ID VALIDATOR
# ==============================
def validate_case_id(case_name: str) -> bool:
    """
    Valid format: CASE-YYYYMMDD-XXXX
    Example:      CASE-20240115-0042
    """
    return bool(re.match(r"^CASE-\d{8}-\d{3,6}$", case_name))


def generate_case_id() -> str:
    date_str = datetime.now().strftime("%Y%m%d")
    uid      = hashlib.md5(os.urandom(8)).hexdigest()[:4].upper()
    return f"CASE-{date_str}-{uid}"


# ==============================
# SHA-256 INTEGRITY HASH
# ==============================
def hash_file(file_path: str) -> str:
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


# ==============================
# JSON WRITER
# ==============================
def save_to_json(data: dict, filename: str, source: str,
                 case_name: str, sha256: str):
    report = {
        "metadata": {
            "case_id":    case_name,              # ← was missing
            "sha256":     sha256,                 # ← was missing
            "timestamp":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "source_file": os.path.basename(source),
            "analyst":    "AutoForenX Engine",
        },
        "findings": data
    }
    with open(filename, "w") as jf:
        json.dump(report, jf, indent=4)
    print(f"[+] Report saved: {filename}")


# ==============================
# MAIN FUNCTION
# ==============================
def analyze_ram_dump_ultra(
    dump_file_path,
    output_json="forensic_report.json",
    case_name=None                          # ← fix 1: was blank (SyntaxError)
):

    # ── Case ID verification ──────────────────────────────────
    if not case_name:
        case_name = generate_case_id()
        print(f"[!] No case name provided. Auto-generated: {case_name}")

    elif not validate_case_id(case_name):
        print(f"[✗] Invalid Case ID: '{case_name}'")
        print(f"    Expected format : CASE-YYYYMMDD-XXXX")
        print(f"    Example         : CASE-20240115-0042")
        suggestion = generate_case_id()
        print(f"[?] Suggested ID  : {suggestion}")
        confirm = input("    Use suggested ID? (y/n): ").strip().lower()
        if confirm == "y":
            case_name = suggestion
            print(f"[✓] Case ID set to: {case_name}")
        else:
            print("[-] Aborting — re-run with a valid Case ID.")
            return None
    else:
        print(f"[✓] Case ID verified: {case_name}")

    # ── Dump file check ───────────────────────────────────────
    if not os.path.exists(dump_file_path):
        print(f"[-] Error: File '{dump_file_path}' not found.")
        print(f"    Case '{case_name}' cannot proceed without a valid dump file.")
        return None

    file_size = os.path.getsize(dump_file_path)
    print(f"[+] File  : {dump_file_path} ({file_size / (1024**2):.2f} MB)")

    # ── Integrity hash ────────────────────────────────────────
    print("[+] Computing SHA-256 hash...")
    sha256 = hash_file(dump_file_path)
    print(f"[+] SHA-256: {sha256}")

    # ── Patterns ──────────────────────────────────────────────
    patterns = {
        "processes": re.compile(rb"[a-zA-Z0-9_\-]+\.exe"),
        "ips":       re.compile(
                        rb"\b(?:10|172|192|198|72|29|162|171)"
                        rb"\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
                     ),
        "urls":      re.compile(rb"https?://[^\s\x00-\x1f\x7f-\xff]+"),
        # ── fix 2: added domains pattern (was missing entirely) ──
        "domains":   re.compile(rb"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}"),
    }

    suspicious_keywords = [
        b"powershell", b"mimikatz", b"cobaltstrike", b"meterpreter",
        b"ransom",     b"agenttesla", b"backdoor",   b"lsass.exe",
        b"updater.exe",b"cmd.exe",   b"wscript.exe", b"regsvr32.exe",
        b"rundll32.exe",b"nc.exe",   b"netcat.exe",  b"python.exe",
        b"perl.exe",   b"wget.exe",  b"curl.exe",
    ]

    results_set = {k: set() for k in ["processes", "ips", "urls", "domains", "keywords"]}

    CHUNK_SIZE = 1024 * 1024 * 40  # 40 MB
    OVERLAP    = 1024
    bytes_read = 0
    start_time = time.time()

    # ── Chunked scan ──────────────────────────────────────────
    try:
        with open(dump_file_path, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break

                bytes_read += len(chunk)
                elapsed = time.time() - start_time
                percent = (bytes_read / file_size) * 100
                speed   = (bytes_read / 1024**2) / (elapsed if elapsed > 0 else 1)

                # fix 3: progress bar width was calculated wrong (always 50 chars)
                bar_fill = int(percent / 2)
                bar      = ("=" * bar_fill).ljust(50)
                print(f"\r[{bar}] {percent:.1f}% | {speed:.2f} MB/s | "
                      f"Case: {case_name}", end="")

                # Extraction
                for p in patterns["processes"].findall(chunk):
                    results_set["processes"].add(p.decode(errors="ignore").lower())

                for ip in patterns["ips"].findall(chunk):
                    results_set["ips"].add(ip.decode(errors="ignore"))

                for u in patterns["urls"].findall(chunk):
                    results_set["urls"].add(u.decode(errors="ignore"))

                for d in patterns["domains"].findall(chunk):
                    results_set["domains"].add(d.decode(errors="ignore").lower())

                chunk_lower = chunk.lower()
                for key in suspicious_keywords:
                    if key in chunk_lower:
                        results_set["keywords"].add(key.decode(errors="ignore"))

                # fix 4: overlap seek only when a full chunk was read
                if len(chunk) == CHUNK_SIZE:
                    f.seek(f.tell() - OVERLAP)

        print(f"\n\n[✓] Scan complete for case: {case_name}")

        # fix 5: convert sets → sorted lists BEFORE passing to save_to_json
        final_results = {k: sorted(list(v)) for k, v in results_set.items()}

        # fix 6: save_to_json now receives case_name + sha256 (were missing before)
        save_to_json(final_results, output_json, dump_file_path, case_name, sha256)

        # fix 7: return enriched dict so pipeline consumers get full context
        return {
            "case_id":       case_name,
            "sha256":        sha256,
            "source_file":   dump_file_path,
            "output_json":   output_json,
            "processes":     final_results["processes"],
            "ips":           final_results["ips"],
            "urls":          final_results["urls"],
            "domains":       final_results["domains"],
            "keywords":      final_results["keywords"],
            # Alias expected by generate_report()
            "suspicious_commands": [kw for kw in final_results["keywords"]],
        }

    except Exception as e:
        print(f"\n[-] Error during scan: {e}")
        return None