import sqlite3

conn = sqlite3.connect("security.db")
cursor = conn.cursor()

rows = cursor.execute("""
SELECT id, timestamp, ai_decision, mitigation_status
FROM security_logs
LIMIT 20
""").fetchall()

print("\n Sample Logs:")
for row in rows:
    print(row)

conn.close()
