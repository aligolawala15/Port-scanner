import sqlite3
from datetime import datetime


DATABASE = "data/scans.db"


def create_database():

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            ip TEXT,
            port INTEGER,
            scan_time TEXT
        )
    """)

    connection.commit()
    connection.close()


def save_scan(target, ip, ports):

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    for port in ports:

        cursor.execute("""
            INSERT INTO scans
            (target, ip, port, scan_time)
            VALUES (?, ?, ?, ?)
        """, (
            target,
            ip,
            port,
            datetime.now().isoformat()
        ))

    connection.commit()
    connection.close()