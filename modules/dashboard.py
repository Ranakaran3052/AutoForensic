import sqlite3
from tabulate import tabulate

DB_PATH = "database/cases.db"

def show_dashboard():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Total cases
    cursor.execute("SELECT COUNT(*) FROM cases")
    total_cases = cursor.fetchone()[0]

    # High risk cases
    cursor.execute("SELECT COUNT(*) FROM cases WHERE risk_score > 0.5")
    high_risk = cursor.fetchone()[0]
    # Fetch recent cases
    cursor.execute("""
        SELECT case_name , case_id , suspicious_count, risk_score
        FROM cases
        ORDER BY id DESC
        LIMIT 10
    """)

    rows = cursor.fetchall()
    conn.close()

    recent_cases = []

    for case_id, case_name, suspicious, risk in rows:

        # Handle missing case_id
        if not case_id:
            case_id = "UNKNOWN-ID"

        display_name = f"{case_id} | {case_name}"

        # Format risk score
        risk = round(risk, 2)

        recent_cases.append((display_name, suspicious, risk))

    print("\n" + "="*60)
    print(" AutoForenX Enterprise Forensic Dashboard ".center(60))
    print("="*60)

    print(f"\nTotal Cases Investigated : {total_cases}")
    print(f"High Risk Cases (>0.5)   : {high_risk}")

    print("\nRecent Investigations:")

    headers = ["Case ID + Case Name", "Suspicious Events", "Risk Score"]

    if recent_cases:
        print(tabulate(recent_cases, headers=headers, tablefmt="grid"))
    else:
        print("No investigations found.")

    print("\nSystem Status : OPERATIONAL")
    print("="*60 + "\n")