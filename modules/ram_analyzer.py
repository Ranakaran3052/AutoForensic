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
    # ==============================
    # DELETED FILE ARTIFACTS
    # Looks for MFT remnants, recycle bin paths, shadow copy
    # references, and common deleted-file magic byte headers
    # still resident in memory after deletion.
    # ==============================
    DELETED_FILE_MAGIC = {
        b"\x4D\x5A":           "PE/EXE",        # MZ header
        b"\x50\x4B\x03\x04":   "ZIP/Office",     # ZIP / DOCX / XLSX
        b"\x25\x50\x44\x46":   "PDF",
        b"\xFF\xD8\xFF":       "JPEG",
        b"\x89\x50\x4E\x47":   "PNG",
        b"\xD0\xCF\x11\xE0":   "OLE/DOC/XLS",   # Legacy Office
        b"\x52\x61\x72\x21":   "RAR",
        b"\x37\x7A\xBC\xAF":   "7-Zip",
        b"\x1F\x8B":           "GZIP",
        b"\x42\x4D":           "BMP",
        b"\x47\x49\x46\x38":   "GIF",
        b"\x53\x51\x4C\x69":   "SQLite DB",
        b"\x4C\x00\x00\x00":   "Windows LNK",   # Shell link / shortcut
    }

    # ==============================
    # USER CREDENTIALS & PASSWORDS
    # Targets NTLM hashes, credential blobs, registry hive
    # strings, and cleartext password context patterns.
    # ==============================
    CRED_CONTEXT_WINDOW = 80   # bytes captured around each hit

    patterns = {
        "processes": re.compile(rb"[a-zA-Z0-9_\-]+\.exe"),
        "ips":       re.compile(
                        rb"\b(?:10|172|192|198|72|29|162|171)"
                        rb"\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
                     ),

        # URLs: must have a valid hostname after scheme, no raw punctuation-only paths
        "urls":      re.compile(
                        rb"https?://"
                        rb"[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+"  # valid URI chars only
                        rb"(?<![\"'<>,;)\]\s])"                        # strip trailing junk
                     ),

        # Emails: stricter — require proper TLD (2-6 alpha chars), no numeric-only domains
        "emails":    re.compile(
                        rb"[a-zA-Z0-9][a-zA-Z0-9._%+\-]{1,63}"
                        rb"@"
                        rb"[a-zA-Z0-9][a-zA-Z0-9.\-]{0,63}"
                        rb"\.[a-zA-Z]{2,6}\b"
                     ),

        "suspicious_commands": re.compile(
                        rb"(?:powershell|mimikatz|cobaltstrike|meterpreter|ransom|agenttesla"
                        rb"|backdoor|lsass\.exe|updater\.exe|cmd\.exe|wscript\.exe"
                        rb"|regsvr32\.exe|rundll32\.exe|nc\.exe|netcat\.exe|python\.exe"
                        rb"|perl\.exe|wget\.exe|curl\.exe|\.onion)"
                     ),

        # Domains: require at least one letter in the label (blocks -.10.bq style noise),
        # minimum 4-char TLD-bearing hostname, known real TLD suffix
        "domains":   re.compile(
                        rb"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
                        rb"+(?:com|net|org|edu|gov|mil|int|io|co|uk|de|fr|ru|cn|br|au"
                        rb"|jp|in|nl|se|no|fi|dk|pl|cz|hu|ro|bg|hr|sk|si|lt|lv|ee"
                        rb"|info|biz|name|mobi|travel|museum|onion|xyz|top|site|live"
                        rb"|online|store|tech|app|dev|cloud|media|news|blog|shop)\b"
                     ),

        # Contacts: stricter — require minimum 7 digits, disallow all-zero numbers
        "contacts":  re.compile(
                        rb"\b(\+?(?:[1-9]\d{0,2}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4,})\b"
                     ),

        # ── Deleted file artifacts ─────────────────────────────
        # MFT / $MFT entry signatures still in RAM
        "mft_entries":       re.compile(rb"FILE[\x00-\xFF]{0,4}\x00{2}"),
        # $Recycle.Bin / RECYCLER paths
        "recycle_paths":     re.compile(rb"(?:\$Recycle\.Bin|\$RECYCLE\.BIN|RECYCLER)[^\x00\r\n]{0,120}", re.IGNORECASE),
        # Volume shadow copy references
        "shadow_refs":       re.compile(rb"\\\\?\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy\d+[^\x00\r\n]{0,80}", re.IGNORECASE),
        # Deleted file path remnants (tombstone strings)
        "deleted_paths":     re.compile(rb"(?:[A-Za-z]:\\[^\x00\r\n]{4,120}\.(?:exe|dll|docx?|xlsx?|pdf|zip|rar|7z|lnk|bat|ps1|vbs|tmp))\x00", re.IGNORECASE),

        # ── Credentials & passwords ────────────────────────────
        # NTLM hash: 32 hex chars (LM or NT half)
        "ntlm_hashes":       re.compile(rb"[0-9a-fA-F]{32}:[0-9a-fA-F]{32}"),
        # Net-NTLMv2 challenge/response blob prefix
        "netntlm_blobs":     re.compile(rb"NTLMSSP\x00[\x01-\x03]\x00{3}[\x00-\xFF]{12,200}"),
        # SAM / LSASS credential key strings
        "lsass_strings":     re.compile(rb"(?:SAMKey|LSASS|NL\$KM|DPAPI|MasterKey|CryptProtect)[^\x00\r\n]{0,80}", re.IGNORECASE),
        # Cleartext password context: keyword followed by printable value
        "cleartext_creds":   re.compile(rb"(?:password|passwd|pwd|pass|secret|token|apikey|api_key|auth_token|Authorization)"
                                        rb"[\s:='\"\x00]{1,8}([\x20-\x7E]{4,64})", re.IGNORECASE),
        # Windows credential store / vault blobs
        "cred_vault":        re.compile(rb"Windows Credentials[\x00-\xFF]{0,4}|vcrd[\x00-\xFF]{2}|\.vcrd\x00", re.IGNORECASE),
        # Base64-encoded credential blobs (≥32 chars, common in tokens/cookies)
        "b64_creds":         re.compile(rb"(?:eyJ|TVqQ|AAAA)[A-Za-z0-9+/]{32,}={0,2}"),
        # Browser saved-password sqlite key pattern
        "browser_creds":     re.compile(rb"(?:logins\.json|key4\.db|Login Data|Cookies|Web Data)[^\x00]{0,60}", re.IGNORECASE),
    }

    suspicious_keywords = [
        b"powershell", b"mimikatz", b"cobaltstrike", b"meterpreter",
        b"ransom",     b"agenttesla", b"backdoor",   b"lsass.exe",
        b"updater.exe",b"cmd.exe",   b"wscript.exe", b"regsvr32.exe",
        b"rundll32.exe",b"nc.exe",   b"netcat.exe",  b"python.exe",
        b"perl.exe",   b"wget.exe",  b"curl.exe",
    ]

    results_set = {k: set() for k in [
        "processes", "ips", "urls", "domains", "keywords",
        "suspicious_commands", "emails", "contacts",
        # deleted-file artifact keys
        "mft_entries", "recycle_paths", "shadow_refs", "deleted_paths",
        "deleted_file_magic",
        # credential keys
        "ntlm_hashes", "netntlm_blobs", "lsass_strings",
        "cleartext_creds", "cred_vault", "b64_creds", "browser_creds",
    ]}

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

                for e in patterns["emails"].findall(chunk):
                    results_set["emails"].add(e.decode(errors="ignore").lower())

                for sc in patterns["suspicious_commands"].findall(chunk):
                    results_set["suspicious_commands"].add(sc.decode(errors="ignore").lower())
    

                for n in patterns["contacts"].findall(chunk):
                    results_set["contacts"].add(n.decode(errors="ignore"))
                

                chunk_lower = chunk.lower()
                for key in suspicious_keywords:
                    if key in chunk_lower:
                        results_set["keywords"].add(key.decode(errors="ignore"))

                # ── Deleted file artifacts ─────────────────────
                for match in patterns["mft_entries"].finditer(chunk):
                    offset = match.start()
                    snippet = chunk[offset:offset+16].hex()
                    results_set["mft_entries"].add(f"offset~{bytes_read - len(chunk) + offset}|{snippet}")

                for p in patterns["recycle_paths"].findall(chunk):
                    results_set["recycle_paths"].add(p.decode(errors="ignore").strip("\x00"))

                for s in patterns["shadow_refs"].findall(chunk):
                    results_set["shadow_refs"].add(s.decode(errors="ignore").strip("\x00"))

                for dp in patterns["deleted_paths"].findall(chunk):
                    results_set["deleted_paths"].add(dp.decode(errors="ignore").strip("\x00"))

                # Magic-byte scan for deleted file headers in RAM
                for magic, ftype in DELETED_FILE_MAGIC.items():
                    pos = 0
                    while True:
                        pos = chunk.find(magic, pos)
                        if pos == -1:
                            break
                        abs_offset = bytes_read - len(chunk) + pos
                        results_set["deleted_file_magic"].add(
                            f"{ftype}@offset:{abs_offset}"
                        )
                        pos += len(magic)

                # ── Credentials & passwords ────────────────────
                for h in patterns["ntlm_hashes"].findall(chunk):
                    results_set["ntlm_hashes"].add(h.decode(errors="ignore"))

                for blob in patterns["netntlm_blobs"].findall(chunk):
                    results_set["netntlm_blobs"].add(blob[:32].hex() + "…")

                for ls in patterns["lsass_strings"].findall(chunk):
                    results_set["lsass_strings"].add(ls.decode(errors="ignore").strip())

                for m in patterns["cleartext_creds"].finditer(chunk):
                    keyword = chunk[max(0, m.start()-CRED_CONTEXT_WINDOW):m.start()].decode(errors="ignore")[-20:]
                    value   = m.group(1).decode(errors="ignore")
                    results_set["cleartext_creds"].add(f"{keyword.strip()}={value}")

                for cv in patterns["cred_vault"].findall(chunk):
                    results_set["cred_vault"].add(cv.decode(errors="ignore").strip("\x00"))

                for b64 in patterns["b64_creds"].findall(chunk):
                    entry = b64.decode(errors="ignore")
                    results_set["b64_creds"].add(entry[:60] + ("…" if len(entry) > 60 else ""))

                for bc in patterns["browser_creds"].findall(chunk):
                    results_set["browser_creds"].add(bc.decode(errors="ignore").strip("\x00"))

                # fix 4: overlap seek only when a full chunk was read
                if len(chunk) == CHUNK_SIZE:
                    f.seek(f.tell() - OVERLAP)

        print(f"\n\n[✓] Scan complete for case: {case_name}")

        # ── Post-extraction noise filters ─────────────────────
        # Domains: remove anything starting with punctuation, pure
        # numbers, or JS/HTML fragments left by the regex
        def _clean_domains(raw: set) -> set:
            out = set()
            skip_prefixes = ("-", ".", "_", "/", "\\", "*", "?", "#", "!")
            for d in raw:
                if not d or len(d) < 4:
                    continue
                if d[0] in skip_prefixes:
                    continue
                # Must contain at least one letter in first label
                first_label = d.split(".")[0]
                if not any(c.isalpha() for c in first_label):
                    continue
                # Skip obvious JS/code fragments
                if any(x in d for x in ("(", ")", "{", "}", "[", "]",
                                         "=", "<", ">", '"', "'")):
                    continue
                out.add(d)
            return out

        # URLs: remove anything with no real path content after scheme
        def _clean_urls(raw: set) -> set:
            out = set()
            junk_suffixes = ('"', "'", ")", "(", ",", ";", "<", ">",
                             "}", "{", "]", "[")
            for u in raw:
                if len(u) < 12:          # too short to be real
                    continue
                host_part = u.split("//")[-1].split("/")[0]
                if not host_part or len(host_part) < 4:
                    continue
                # Must have a dot in hostname
                if "." not in host_part:
                    continue
                # Strip trailing punctuation noise
                cleaned = u.rstrip("".join(junk_suffixes))
                if cleaned:
                    out.add(cleaned)
            return out

        # Emails: strip phone-number false positives that slipped through
        def _clean_emails(raw: set) -> set:
            out = set()
            for e in raw:
                if "@" not in e:
                    continue
                local, _, domain = e.partition("@")
                if not local or not domain:
                    continue
                if "." not in domain:
                    continue
                # Reject if local part is all digits (phone number)
                if local.replace("+","").replace("-","").isdigit():
                    continue
                out.add(e)
            return out

        # Contacts: reject all-zero or obviously fake numbers
        def _clean_contacts(raw: set) -> set:
            out = set()
            for c in raw:
                digits = re.sub(r"\D", "", c)
                if len(digits) < 7:
                    continue
                if len(set(digits)) == 1:   # e.g. 0000000, 1111111
                    continue
                out.add(c)
            return out

        results_set["domains"]  = _clean_domains(results_set["domains"])
        results_set["urls"]     = _clean_urls(results_set["urls"])
        results_set["emails"]   = _clean_emails(results_set["emails"])
        results_set["contacts"] = _clean_contacts(results_set["contacts"])

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
            # Deleted-file evidence
            "mft_entries":        final_results["mft_entries"],
            "recycle_paths":      final_results["recycle_paths"],
            "shadow_refs":        final_results["shadow_refs"],
            "deleted_paths":      final_results["deleted_paths"],
            "deleted_file_magic": final_results["deleted_file_magic"],
            # Credential evidence
            "ntlm_hashes":        final_results["ntlm_hashes"],
            "netntlm_blobs":      final_results["netntlm_blobs"],
            "lsass_strings":      final_results["lsass_strings"],
            "cleartext_creds":    final_results["cleartext_creds"],
            "cred_vault":         final_results["cred_vault"],
            "b64_creds":          final_results["b64_creds"],
            "browser_creds":      final_results["browser_creds"],
            # Alias expected by generate_report()
            "suspicious_commands": [kw for kw in final_results["keywords"]],
        }

    except Exception as e:
        import traceback
        print(f"\n[-] Error during scan: {e}")
        print("[-] Full traceback:")
        traceback.print_exc()
        return None