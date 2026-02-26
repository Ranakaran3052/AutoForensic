import argparse
from modules.hasher import generate_hash
from modules.metadata import get_metadata
from modules.log_parser import parse_log
from modules.timeline import generate_timeline
from modules.report import generate_report
from modules.database import init_db, insert_case
from modules.ml_detector import detect_anomaly
from modules.dashboard import show_dashboard

parser = argparse.ArgumentParser(description="AutoForenX - Enterprise Forensic Automation CLI")

parser.add_argument("--file", help="File for analysis")
parser.add_argument("--log", help="Log file to parse")
parser.add_argument("--case", help="Case name for report")
parser.add_argument("--dashboard", action="store_true", help="Show forensic dashboard")

args = parser.parse_args()

init_db()

if args.dashboard:
    show_dashboard()

elif args.case:

    suspicious_logs = []
    hash_value = "N/A"
    metadata = {}

    # ---- FILE HASH + METADATA ----
    if args.file:
        print("[+] Generating hash...")
        hash_value = generate_hash(args.file)

        print("[+] Extracting metadata...")
        metadata = get_metadata(args.file)

    # ---- LOG PARSING ----
    if args.log:
        print("[+] Parsing logs...")
        suspicious_logs = parse_log(args.log)

    # ---- ML DETECTION ----
    print("[+] Running ML anomaly detection...")
    status, risk_score = detect_anomaly(suspicious_logs_count, suspicious_dns_count)

    print(f"[AI RESULT] Status: {status}")
    print(f"[AI RESULT] Risk Score: {risk_score}")

    # ---- REPORT ----
    print("[+] Generating report...")
    generate_report(args.case, hash_value, metadata, suspicious_logs)

    # ---- DATABASE ----
    print("[+] Saving case to database...")
    insert_case(
        args.case,
        hash_value,
        len(suspicious_logs),
        risk_score
    )

    print("[✓] Investigation completed successfully.")

else:
    print("\nUsage:")
    print(" python main.py --case <casename> [--file file] [--log log]")
    print(" python main.py --dashboard\n")