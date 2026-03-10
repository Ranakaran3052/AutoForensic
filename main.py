import os
import argparse
from modules.hasher       import generate_hash
from modules.metadata     import get_metadata
from modules.log_parser   import parse_log
from modules.report       import generate_report
from modules.database     import init_db, insert_case
from modules.ml_detector  import detect_anomaly
from modules.dashboard    import show_dashboard
from modules.dns_pipeline import run_forensic_dns_pipeline
from modules.ram_analyzer import analyze_ram_dump_ultra

# ==============================
# CLI ARGUMENTS
# ==============================
parser = argparse.ArgumentParser(
    description="AutoForenX - Enterprise Forensic Automation CLI"
)
parser.add_argument("--file",      help="File for analysis")
parser.add_argument("--log",       help="Log file to parse")
parser.add_argument("--dump",      help="Dump file for DNS + RAM extraction")
parser.add_argument("--case",      help="Case name for report (format: CASE-YYYYMMDD-XXXX)")
parser.add_argument("--dashboard", action="store_true", help="Show forensic dashboard")

args = parser.parse_args()

init_db()

# ==============================
# DASHBOARD MODE
# ==============================
if args.dashboard:
    show_dashboard()

# ==============================
# INVESTIGATION MODE
# ==============================
elif args.case:

    # ── Safe defaults — prevents ALL NameErrors ───────────────
    hash_value           = "N/A"
    metadata             = {}
    suspicious_logs      = []
    email_list           = []          # fix 1: always defined here
    analysis_results     = []
    suspicious_dns_count = 0
    status               = "LOW"
    risk_score           = 0.0
    ram_results          = {           # fix 2: keys match generate_report()
        "processes":          [],
        "domains":            [],
        "ips":                [],
        "urls":               [],
        "suspicious_commands":[],
        "emails":             [],      # fix 2: was "email_addresses"
    }

    # ── File hash + metadata ──────────────────────────────────
    if args.file:
        print("[+] Generating hash...")
        hash_value = generate_hash(args.file)
        print("[+] Extracting metadata...")
        metadata = get_metadata(args.file)

    # ── Log parsing ───────────────────────────────────────────
    if args.log:
         if os.path.exists(args.log):
          print("[+] Parsing logs...")
          suspicious_logs, log_emails = parse_log(args.log)
          email_list = sorted(set(log_emails))
          print(f"[+] Suspicious log events : {len(suspicious_logs)}")
          print(f"[+] Emails from logs      : {len(email_list)}")
         else:
          print(f"[!] Log file not found: {args.log} — skipping log analysis")
    else:
     print("[*] No log file provided — skipping log analysis")

    suspicious_log_count = len(suspicious_logs)

    # ── DNS + RAM forensics ───────────────────────────────────
    if args.dump:

        # DNS pipeline — fix 3: pass as list, pass case_name
        print("[+] Running DNS forensic pipeline...")
        dns_output = run_forensic_dns_pipeline(
            dump_file_path=[args.dump]             # fix 3: wrap in list
        )
        analysis_results     = dns_output.get("domains_analyzed", [])
        suspicious_dns_count = dns_output.get("suspicious_dns_count", 0)

        # Merge DNS emails into email_list
        email_list = sorted(set(
            email_list + dns_output.get("emails", [])
        ))

        # RAM analysis — fix 4: pass case_name
        print("[+] Performing RAM forensic analysis...")
        raw_ram = analyze_ram_dump_ultra(
            dump_file_path=args.dump,
            output_json=f"{args.case}_ram.json",
            case_name=args.case            # fix 4: was missing
        )

        if raw_ram:
            # fix 5: only copy known list keys — skip str fields like case_id/sha256
            list_keys = ("processes", "ips", "urls", "domains",
                         "suspicious_commands", "emails")
            ram_results = {
                k: sorted(list(raw_ram[k]))
                for k in list_keys
                if k in raw_ram
            }

            # Merge RAM emails into email_list
            email_list = sorted(set(
                email_list + ram_results.get("emails", [])
            ))

            # Update hash from RAM if file hash wasn't provided
            if hash_value == "N/A":
                hash_value = raw_ram.get("sha256", "N/A")

            print(f"[+] Processes : {len(ram_results.get('processes', []))}")
            print(f"[+] IPs       : {len(ram_results.get('ips', []))}")
            print(f"[+] Domains   : {len(ram_results.get('domains', []))}")
            print(f"[+] Emails    : {len(email_list)}")

    # ── ML anomaly detection ──────────────────────────────────
    print("[+] Running ML anomaly detection...")
    status, risk_score = detect_anomaly(
        suspicious_log_count,
        suspicious_dns_count
    )
    print(f"[AI] Status     : {status}")
    print(f"[AI] Risk Score : {risk_score}/100")

    # ── Generate report ───────────────────────────────────────
    print("[+] Generating report...")
    generate_report(
        case_name=args.case,
        hash_value=hash_value,
        metadata=metadata,
        suspicious_logs=suspicious_logs,
        dns_results=analysis_results,
        ram_results=ram_results,
        suspicious_dns_count=suspicious_dns_count,
        email_list=email_list,            # fix 1: now always defined
        final_status=status,
        risk_score=risk_score
    )

    # ── Save to database ──────────────────────────────────────
    print("[+] Saving case to database...")
    insert_case(
        args.case,
        hash_value,
        suspicious_log_count,
        risk_score
    )

    print("\n[✓] Investigation completed successfully.")
    print(f"    Case     : {args.case}")
    print(f"    Status   : {status}")
    print(f"    Score    : {risk_score}/100")
    print(f"    Report   : reports/{args.case}_report.pdf")

else:
    parser.print_help()