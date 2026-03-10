import sqlite3
from tabulate import tabulate

DB_PATH = "database/cases.db"

def show_dashboard():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM cases")
    total_cases = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM cases WHERE risk_score > 0.5")
    high_risk = cursor.fetchone()[0]

    cursor.execute("SELECT case_name, suspicious_count, risk_score FROM cases ORDER BY id DESC LIMIT 5")
    recent_cases = cursor.fetchall()

    conn.close()

    print("\n" + "="*60)
    print(" AutoForenX Enterprise Forensic Dashboard")
    print("="*60)

    print(f"\nTotal Cases Investigated: {total_cases}")
    print(f"High Risk Cases (Risk > 0.5): {high_risk}")

    print("\nRecent Investigations:")
    headers = ["Case Name", "Suspicious Events", "Risk Score"]
    print(tabulate(recent_cases, headers=headers, tablefmt="grid"))

    print("\nSystem Status: OPERATIONAL")
    print("="*60 + "\n")