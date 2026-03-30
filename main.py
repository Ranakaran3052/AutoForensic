import os
import argparse
from modules.hasher           import generate_hash
from modules.metadata         import get_metadata
from modules.log_parser       import parse_log
from modules.report           import generate_report
from modules.database         import init_db, insert_case
from modules.ml_detector      import detect_anomaly
from modules.dashboard        import show_dashboard
from modules.dns_pipeline     import run_forensic_dns_pipeline
from modules.ram_analyzer     import analyze_ram_dump_ultra
from modules.mobile_forensics import run_mobile_module

# ==============================
# CLI ARGUMENTS
# ==============================
parser = argparse.ArgumentParser(
    description="AutoForenX - Enterprise Forensic Automation CLI"
)
parser.add_argument("--file",      help="File for analysis")
parser.add_argument("--log",       help="Log file to parse")
parser.add_argument("--dump",      help="Dump file for DNS + RAM extraction")
parser.add_argument("--mobile",    help="Mobile acquisition path (dir / .ab / .zip / .img)")
parser.add_argument("--platform",  help="Mobile platform hint: android | ios | auto (default: auto)",
                    default="auto", choices=["auto", "android", "ios"])
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
    email_list           = []
    analysis_results     = []
    suspicious_dns_count = 0
    status               = "LOW"
    risk_score           = 0.0
    ram_results          = {
        "processes":          [],
        "domains":            [],
        "ips":                [],
        "urls":               [],
        "suspicious_commands":[],
        "emails":             [],
    }
    mobile_findings      = {}          # always defined

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

        # DNS pipeline
        print("[+] Running DNS forensic pipeline...")
        dns_output = run_forensic_dns_pipeline(
            dump_file_path=[args.dump]
        )
        analysis_results     = dns_output.get("domains_analyzed", [])
        suspicious_dns_count = dns_output.get("suspicious_dns_count", 0)

        email_list = sorted(set(
            email_list + dns_output.get("emails", [])
        ))

        # RAM analysis
        print("[+] Performing RAM forensic analysis...")
        raw_ram = analyze_ram_dump_ultra(
            dump_file_path=args.dump,
            output_json=f"{args.case}_ram.json",
            case_name=args.case
        )

        if raw_ram:
            list_keys = ("processes", "ips", "urls", "domains",
                         "suspicious_commands", "emails")
            ram_results = {
                k: sorted(list(raw_ram[k]))
                for k in list_keys
                if k in raw_ram
            }

            email_list = sorted(set(
                email_list + ram_results.get("emails", [])
            ))

            if hash_value == "N/A":
                hash_value = raw_ram.get("sha256", "N/A")

            print(f"[+] Processes : {len(ram_results.get('processes', []))}")
            print(f"[+] IPs       : {len(ram_results.get('ips', []))}")
            print(f"[+] Domains   : {len(ram_results.get('domains', []))}")
            print(f"[+] Emails    : {len(email_list)}")

            # ── Mobile forensics ──────────────────────────────
            # Uses --mobile path if given, falls back to --dump
            mobile_source = args.mobile or args.dump
            print(f"\n[+] Running mobile forensics module ({args.platform.upper()})...")
            print(f"    Source: {mobile_source}")

            combined        = run_mobile_module(
                ram_result   = raw_ram,
                mobile_source= mobile_source,
                platform     = args.platform,
                output_dir   = "mobile_reports",
            )
            mobile_findings = combined.get("mobile", {})

            # Merge mobile emails into master email list
            mob_calls    = mobile_findings.get("call_logs",      [])
            mob_msgs     = mobile_findings.get("messages",        [])
            mob_locs     = mobile_findings.get("location_data",   [])
            mob_inst     = mobile_findings.get("apps_installed",  [])
            mob_uninst   = mobile_findings.get("apps_uninstalled",[])
            mob_devids   = mobile_findings.get("device_ids",      {})
            mob_voip     = mobile_findings.get("voip_artifacts",  [])
            mob_creds    = mobile_findings.get("raw_scan_hits",   {})

            # Surface any phone numbers / device IDs into email_list
            # so they appear in the master report
            extra_contacts = []
            for k in ("phone_numbers", "phone_e164"):
                extra_contacts.extend(mob_creds.get(k, []))
            email_list = sorted(set(email_list + extra_contacts))

            # Suspicious app alert
            suspicious_apps = [
                a for a in mob_inst if a.get("suspicious")
            ]

            print(f"\n[+] Mobile results:")
            print(f"    Device IDs     : {len(mob_devids)} type(s)")
            print(f"    Call logs      : {len(mob_calls)}")
            print(f"    VoIP artifacts : {len(mob_voip)}")
            print(f"    Messages       : {len(mob_msgs)}")
            print(f"    Location fixes : {len(mob_locs)}")
            print(f"    Apps installed : {len(mob_inst)}")
            print(f"    Apps removed   : {len(mob_uninst)}")
            if suspicious_apps:
                print(f"\n    [!] SUSPICIOUS APPS ({len(suspicious_apps)}):")
                for a in suspicious_apps:
                    pkg = a.get("package") or a.get("bundle_id", "unknown")
                    print(f"        → {pkg}")

        else:
            print("[!] RAM analysis returned no results — skipping mobile module")

    elif args.mobile:
        # Mobile-only mode: no RAM dump, but --mobile was provided
        print(f"\n[+] Running mobile forensics module ({args.platform.upper()})...")
        print(f"    Source: {args.mobile}")
        combined        = run_mobile_module(
            ram_result   = {"case_id": args.case},
            mobile_source= args.mobile,
            platform     = args.platform,
            output_dir   = "mobile_reports",
        )
        mobile_findings = combined.get("mobile", {})
        mob_calls  = mobile_findings.get("call_logs",     [])
        mob_msgs   = mobile_findings.get("messages",      [])
        mob_locs   = mobile_findings.get("location_data", [])
        mob_inst   = mobile_findings.get("apps_installed",[])
        print(f"[+] Call logs : {len(mob_calls)} | Messages: {len(mob_msgs)} | "
              f"Locations: {len(mob_locs)} | Apps: {len(mob_inst)}")

    # ── ML anomaly detection ──────────────────────────────────
    print("\n[+] Running ML anomaly detection...")
    status, risk_score = detect_anomaly(
        suspicious_log_count,
        suspicious_dns_count
    )
    print(f"[AI] Status     : {status}")
    print(f"[AI] Risk Score : {risk_score}/100")

    # ── Generate report ───────────────────────────────────────
    print("[+] Generating report...")
    generate_report(
        case_name            = args.case,
        hash_value           = hash_value,
        metadata             = metadata,
        suspicious_logs      = suspicious_logs,
        dns_results          = analysis_results,
        ram_results          = ram_results,
        suspicious_dns_count = suspicious_dns_count,
        email_list           = email_list,
        final_status         = status,
        risk_score           = risk_score,
    )

    # ── Save to database ──────────────────────────────────────
    print("[+] Saving case to database...")
    insert_case(
        args.case,
        hash_value,
        risk_score,
    )

    print("\n[✓] Investigation completed successfully.")
    print(f"    Case     : {args.case}")
    print(f"    Status   : {status}")
    print(f"    Hash     : {hash_value}")
    print(f"    Score    : {risk_score}/100")
    print(f"    Report   : reports/{args.case}_report.pdf")
    if mobile_findings:
        print(f"    Mobile   : mobile_reports/{args.case}_mobile_*.json")

else:
    parser.print_help()