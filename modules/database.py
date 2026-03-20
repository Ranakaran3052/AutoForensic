import os
import sqlite3

DB_PATH = "database/cases.db"

def get_connection():
    os.makedirs("database", exist_ok=True)
    return sqlite3.connect(DB_PATH)

# ==============================
# INIT DATABASE
# ==============================
def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    # CASES TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS cases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id TEXT UNIQUE,
        case_name TEXT,
        investigator TEXT,
        status TEXT DEFAULT 'open',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # EVIDENCE TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS evidence (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id TEXT,
        file_name TEXT,
        file_hash TEXT,
        file_type TEXT,
        file_size INTEGER,
        analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(case_id) REFERENCES cases(case_id)
    )
    """)

    # IOC TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS iocs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id TEXT,
        ioc_type TEXT,        -- IP, DOMAIN, HASH, URL
        ioc_value TEXT,
        severity TEXT,        -- LOW, MEDIUM, HIGH
        source TEXT,          -- log, memory, file
        detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(case_id) REFERENCES cases(case_id)
    )
    """)

    # LOGS TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id TEXT,
        log_line TEXT,
        severity TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(case_id) REFERENCES cases(case_id)
    )
    """)

    conn.commit()
    conn.close()

# ==============================
# INSERT FUNCTIONS
# ==============================

def insert_case(case_id, case_name, investigator="unknown"):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    INSERT OR IGNORE INTO cases (case_id, case_name, investigator)
    VALUES (?, ?, ?)
    """, (case_id, case_name, investigator))

    conn.commit()
    conn.close()


def insert_evidence(case_id, file_name, file_hash, file_type, file_size):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO evidence (case_id, file_name, file_hash, file_type, file_size)
    VALUES (?, ?, ?, ?, ?)
    """, (case_id, file_name, file_hash, file_type, file_size))

    conn.commit()
    conn.close()


def insert_ioc(case_id, ioc_type, ioc_value, severity="MEDIUM", source="log"):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO iocs (case_id, ioc_type, ioc_value, severity, source)
    VALUES (?, ?, ?, ?, ?)
    """, (case_id, ioc_type, ioc_value, severity, source))

    conn.commit()
    conn.close()


def insert_log(case_id, log_line, severity="LOW"):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO logs (case_id, log_line, severity)
    VALUES (?, ?, ?)
    """, (case_id, log_line, severity))

    conn.commit()
    conn.close()

def get_connection():
    try:
        return sqlite3.connect(DB_PATH)
    except sqlite3.DatabaseError:
        print("[!] Database corrupted. Recreating...")
        os.remove(DB_PATH)
        return sqlite3.connect(DB_PATH)