import argparse
from modules.hasher import generate_hash
from modules.metadata import get_metadata
from modules.log_parser import parse_log
from modules.report import generate_report
from modules.database import init_db, insert_case
from modules.ml_detector import detect_anomaly
from modules.dashboard import show_dashboard
from modules.dns_pipeline import run_forensic_dns_pipeline 
from modules.ram_analyzer import analyze_ram_dump_ultra

parser = argparse.ArgumentParser(description="AutoForenX - Enterprise Forensic Automation CLI")

parser.add_argument("--file", help="File for analysis")
parser.add_argument("--log", help="Log file to parse")
parser.add_argument("--dump", help="Dump file for DNS extraction")  
parser.add_argument("--case", help="Case name for report")
parser.add_argument("--dashboard", action="store_true", help="Show forensic dashboard")

# ... (imports remain the same)

args = parser.parse_args()

init_db()

if args.dashboard:
    show_dashboard()

elif args.case:
    # --- Initialize Variables to Prevent NameErrors ---
    suspicious_logs = []
    hash_value = "N/A"
    metadata = {}
    analysis_results = []
    suspicious_dns_count = 0
    status = "Unknown"
    risk_score = 0.0
    ram_results = {"processes": [], "domains": [], "ips": [], "keywords": []}

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

    suspicious_log_count = len(suspicious_logs)

    # ---------------- DNS & RAM FORENSICS (DUMP) ----------------
    if args.dump:
        # DNS Pipeline
        dns_output = run_forensic_dns_pipeline(args.dump)
        analysis_results = dns_output.get("domains_analyzed", [])
        suspicious_dns_count = dns_output.get("suspicious_dns_count", 0)

        # RAM Analysis
        print("[+] Performing RAM forensic analysis...")
        raw_ram = analyze_ram_dump_ultra(args.dump)
        if raw_ram:
            # Safety: Ensure everything is a list for the report module
            ram_results = {k: list(v) for k, v in raw_ram.items()}
            
            print(f"[+] Processes found: {len(ram_results.get('processes', []))}")
            print(f"[+] IPs found: {len(ram_results.get('ips', []))}")

    #--------------------- ML ANOMALY DETECTION ----------------
    print("[+] Running ML anomaly detection...")
    status, risk_score = detect_anomaly(
        suspicious_log_count,
        suspicious_dns_count
    )

    print(f"[AI RESULT] Status: {status}")
    print(f"[AI RESULT] Risk Score: {risk_score}")

    # ---------------- REPORT ----------------
    print("[+] Generating report...")
    # This will now work without the 'set' subscriptable error
    generate_report(
        case_name=args.case,
        hash_value=hash_value,
        metadata=metadata,
        suspicious_logs=suspicious_logs,
        dns_results=analysis_results,
        ram_results=ram_results,
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
    parser.print_help()


    