import sqlite3
import os

DB_PATH = "database/cases.db"

def init_db():
    os.makedirs("database", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_name TEXT,
            file_hash TEXT,
            suspicious_count INTEGER,
            risk_score REAL
        )
    """)

    conn.commit()
    conn.close()


def insert_case(case_name, file_hash, suspicious_count, risk_score):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO cases (case_name, file_hash, suspicious_count, risk_score)
        VALUES (?, ?, ?, ?)
    """, (case_name, file_hash, suspicious_count, risk_score))

    conn.commit()
    conn.close()