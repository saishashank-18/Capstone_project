import sqlite3

DB_PATH = "/Users/testuser/Desktop/project-sem/security.db"

def mitigate_attack(db_id):
    action = "Rate limiting applied, suspicious traffic blocked"

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    UPDATE security_logs
    SET mitigation_status = ?, actions = ?
    WHERE id = ?
    """, ("COMPLETED", action, db_id))

    conn.commit()
    conn.close()

    return action
