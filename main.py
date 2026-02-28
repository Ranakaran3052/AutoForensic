import argparse
from modules.hasher import generate_hash
from modules.metadata import get_metadata
from modules.log_parser import parse_log
from modules.report import generate_report
from modules.database import init_db, insert_case
from modules.ml_detector import detect_anomaly
from modules.dashboard import show_dashboard
from modules.dns_pipeline import run_forensic_dns_pipeline  # <-- make sure this exists

parser = argparse.ArgumentParser(description="AutoForenX - Enterprise Forensic Automation CLI")

parser.add_argument("--file", help="File for analysis")
parser.add_argument("--log", help="Log file to parse")
parser.add_argument("--dump", help="Dump file for DNS extraction")  # ✅ Added
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

    # ---------------- FILE HASH + METADATA ----------------
    if args.file:
        print("[+] Generating hash...")
        hash_value = generate_hash(args.file)

        print("[+] Extracting metadata...")
        metadata = get_metadata(args.file)

    # ---------------- LOG PARSING ----------------
    if args.log:
        print("[+] Parsing logs...")
        suspicious_logs = parse_log(args.log)
    else:
        suspicious_logs = []

    suspicious_log_count = len(suspicious_logs)

    # ---------------- DNS PIPELINE ----------------
    if args.dump:
        dns_output = run_forensic_dns_pipeline(
            args.dump,
            suspicious_log_count
        )

        analysis_results = dns_output["domains_analyzed"]
        suspicious_dns_count = dns_output["suspicious_dns_count"]
        status = dns_output["final_status"]
        risk_score = dns_output["risk_score"]

    else:
        analysis_results = []
        suspicious_dns_count = 0

        print("[+] Running ML anomaly detection...")
        status, risk_score = detect_anomaly(
            suspicious_log_count,
            suspicious_dns_count
        )

    print(f"[AI RESULT] Status: {status}")
    print(f"[AI RESULT] Risk Score: {risk_score}")

    # ---------------- REPORT ----------------
    print("[+] Generating report...")
    print("DEBUG: calling generate_report now with the following parameters:")
    generate_report(
        case_name=args.case,
        hash_value=hash_value,
        metadata=metadata,
        suspicious_logs=suspicious_logs,
        dns_results=analysis_results,
        suspicious_dns_count=suspicious_dns_count,
        final_status=status,
        risk_score=risk_score
    )

    # ---------------- DATABASE ----------------
    print("[+] Saving case to database...")
    insert_case(
        args.case,
        hash_value,
        suspicious_log_count,
        risk_score
    )

    print("[✓] Investigation completed successfully.")

else:
    print("\nUsage:")
    print(" python main.py --case <casename> [--file file] [--log log] [--dump dump]")
    print(" python main.py --dashboard\n")