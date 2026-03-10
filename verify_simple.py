import sqlite3
import os

db_path = 'randaframes.db'
if not os.path.exists(db_path):
    print(f"Error: {db_path} not found.")
    exit(1)

try:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    tables = ['organisations', 'users', 'wallets', 'transactions', 'admin_roles']
    for table in tables:
        try:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            count = cursor.fetchone()[0]
            print(f"{table}: {count}")
        except sqlite3.OperationalError as e:
            print(f"{table}: Table not found or error ({e})")

    cursor.execute("SELECT username FROM users WHERE role LIKE '%admin%' AND organisation_id IS NULL")
    admins = cursor.fetchall()
    print(f"Remaining Admins: {[a[0] for a in admins]}")
    
    conn.close()
except Exception as e:
    print(f"An error occurred: {e}")
