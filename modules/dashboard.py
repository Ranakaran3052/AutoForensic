import sqlite3
from tabulate import tabulate

DB_PATH = "database/cases.db"


def show_dashboard():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # ==============================
    # SYSTEM METRICS
    # ==============================
    cursor.execute("SELECT COUNT(*) FROM cases")
    total_cases = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM logs WHERE severity='HIGH'")
    high_alerts = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM evidence")
    evidence_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM iocs")
    total_iocs = cursor.fetchone()[0]

    # ==============================
    # RECENT CASES
    # ==============================
    cursor.execute("""
        SELECT case_id, case_name, created_at
        FROM cases
        ORDER BY id DESC
        LIMIT 10
    """)

    rows = cursor.fetchall()

    # ==============================
    # PROCESS DATA
    # ==============================
    recent_cases = []

    for case_id, case_name, created_at in rows:

        case_id = case_id or "UNKNOWN-ID"
        case_name = case_name or "Unnamed Case"

        display_name = f"{case_id} | {case_name}"

        # Count suspicious logs per case
        cursor.execute("""
            SELECT COUNT(*) FROM logs
            WHERE case_id=? AND severity='HIGH'
        """, (case_id,))
        suspicious = cursor.fetchone()[0]

        # Risk score (dynamic)
        risk = round((suspicious * 5), 2)

        recent_cases.append((display_name, suspicious, risk, created_at))

    conn.close()

    # ==============================
    # PRINT DASHBOARD
    # ==============================
    print("\n" + "=" * 70)
    print(" 🔐 AutoForenX Enterprise Forensic Dashboard ".center(70))
    print("=" * 70)

    print(f"\n📁 Total Cases        : {total_cases}")
    print(f"⚠️  High Alerts       : {high_alerts}")
    print(f"📄 Evidence Files     : {evidence_count}")
    print(f"🧬 Total IOCs         : {total_iocs}")

    print("\n📊 Recent Investigations:")

    headers = ["Case", "High Alerts", "Risk Score", "Created At"]

    if recent_cases:
        print(tabulate(recent_cases, headers=headers, tablefmt="grid"))
    else:
        print("No investigations found.")

    print("\n🟢 System Status : OPERATIONAL")
    print("=" * 70 + "\n")