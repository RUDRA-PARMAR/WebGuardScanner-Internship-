import sqlite3
import json
import os
import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "webguard.db")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the database and creates the scans table if it doesn't exist."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            reachable INTEGER NOT NULL,
            total_findings INTEGER NOT NULL,
            critical_count INTEGER NOT NULL,
            high_count INTEGER NOT NULL,
            medium_count INTEGER NOT NULL,
            low_count INTEGER NOT NULL,
            info_count INTEGER NOT NULL,
            security_score INTEGER NOT NULL,
            risk_rating TEXT NOT NULL,
            raw_report TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def calculate_security_metrics(severity_counts):
    """
    Calculates a security score out of 100 and maps it to a risk rating.
    Weights:
      - Critical: -30 points
      - High: -20 points
      - Medium: -10 points
      - Low: -2 points
      - Info: -0 points
    """
    crit = severity_counts.get("critical", 0)
    high = severity_counts.get("high", 0)
    med = severity_counts.get("medium", 0)
    low = severity_counts.get("low", 0)
    
    score = 100 - (crit * 30 + high * 20 + med * 10 + low * 2)
    score = max(0, score)
    
    if crit > 0:
        rating = "Critical"
    elif high > 0:
        rating = "High"
    elif med > 0:
        rating = "Medium"
    elif low > 0:
        rating = "Low"
    else:
        rating = "Safe"
        
    return score, rating

def save_scan(url, report):
    """
    Saves a completed scan report to the database.
    Computes and updates the security score and risk rating.
    """
    severity_counts = report.get("severity_counts", {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
    })
    
    score, rating = calculate_security_metrics(severity_counts)
    
    # Store calculated metrics back in the report dict for consistency
    report["security_score"] = score
    report["risk_rating"] = rating
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    timestamp = datetime.datetime.now().isoformat()
    report["timestamp"] = timestamp
    reachable = 1 if report.get("reachable", False) else 0
    total_findings = report.get("total_findings", 0)
    
    cursor.execute("""
        INSERT INTO scans (
            url, timestamp, reachable, total_findings,
            critical_count, high_count, medium_count, low_count, info_count,
            security_score, risk_rating, raw_report
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        url,
        timestamp,
        reachable,
        total_findings,
        severity_counts.get("critical", 0),
        severity_counts.get("high", 0),
        severity_counts.get("medium", 0),
        severity_counts.get("low", 0),
        severity_counts.get("info", 0),
        score,
        rating,
        json.dumps(report)
    ))
    
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return scan_id

def get_history():
    """Returns a list of summary records for all past scans, sorted from newest to oldest."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, url, timestamp, reachable, total_findings,
               critical_count, high_count, medium_count, low_count, info_count,
               security_score, risk_rating
        FROM scans
        ORDER BY timestamp DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    
    history = []
    for r in rows:
        history.append({
            "id": r["id"],
            "url": r["url"],
            "timestamp": r["timestamp"],
            "reachable": bool(r["reachable"]),
            "total_findings": r["total_findings"],
            "severity_counts": {
                "critical": r["critical_count"],
                "high": r["high_count"],
                "medium": r["medium_count"],
                "low": r["low_count"],
                "info": r["info_count"]
            },
            "security_score": r["security_score"],
            "risk_rating": r["risk_rating"]
        })
    return history

def get_scan_detail(scan_id):
    """Retrieves and deserializes the full scan report for a specific scan ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp, raw_report FROM scans WHERE id = ?", (scan_id,))
    row = cursor.fetchone()
    conn.close()
    
    if row:
        report = json.loads(row["raw_report"])
        report["timestamp"] = row["timestamp"]
        return report
    return None
