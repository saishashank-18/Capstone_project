import pandas as pd
import sqlite3
import pickle
from datetime import datetime
from mitigate import mitigate_attack
import time
import os
import threading
import math
import logging
from flask import Flask, render_template, jsonify


app = Flask(__name__, template_folder='templates')
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)  

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/logs')
def api_logs():
    try:
        conn = sqlite3.connect("/Users/testuser/Desktop/project-sem/security.db")
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT ai_decision, COUNT(*) as count FROM security_logs GROUP BY ai_decision")
        counts = {row['ai_decision']: row['count'] for row in cursor.fetchall()}
        normal_count = counts.get('NORMAL', 0)
        attack_count = counts.get('ATTACK', 0)
        
        cursor.execute("""
            SELECT id, timestamp, packet_rate, byte_rate, source_count, ai_decision, mitigation_status, actions 
            FROM security_logs ORDER BY id DESC LIMIT 50
        """)
        def clean_val(v):
            if v is None: return 0.0
            try:
                f = float(v)
                return 0.0 if math.isinf(f) or math.isnan(f) else f
            except:
                return 0.0

        logs = [dict(row) for row in cursor.fetchall()]
        for log in logs:
            log['packet_rate'] = clean_val(log['packet_rate'])
            log['byte_rate'] = clean_val(log['byte_rate'])
        conn.close()
        
        logs.reverse()
        return jsonify({
            'status': 'success',
            'summary': {'normal': normal_count, 'attack': attack_count, 'total': normal_count + attack_count},
            'logs': logs
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

def run_dashboard():
    app.run(host='127.0.0.1', port=5050, debug=False, use_reloader=False)


threading.Thread(target=run_dashboard, daemon=True).start()


conn = sqlite3.connect("/Users/testuser/Desktop/project-sem/security.db")
cursor = conn.cursor()
cursor.execute("DROP TABLE IF EXISTS security_logs")
cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, packet_rate REAL, byte_rate REAL,
        source_count INTEGER, ai_decision TEXT, mitigation_status TEXT, actions TEXT
    )
""")
conn.commit()
conn.close()

DB_PATH = "/Users/testuser/Desktop/project-sem/security.db"
CSV_PATH = "DrDoS_UDP.csv"
CHUNK_SIZE = 100000

print("="*60)
print(" http://127.0.0.1:5050 ")
print("="*60)
time.sleep(2)


print("📂 DDoS UDP Traffic Monitoring System")


with open("model.pkl", "rb") as f: 
    model = pickle.load(f)


conn = sqlite3.connect(DB_PATH) 
cursor = conn.cursor()

normal_count = 0
attack_count = 0

for chunk in pd.read_csv(CSV_PATH, chunksize=CHUNK_SIZE, low_memory=False):

    chunk.columns = chunk.columns.str.strip()


    packet_col = next(c for c in chunk.columns if "packet" in c.lower() and "flow" in c.lower())
    byte_col = next(c for c in chunk.columns if "byte" in c.lower() and "flow" in c.lower())
    source_col = next(c for c in chunk.columns if "source" in c.lower() and "ip" in c.lower())


    chunk['Timestamp'] = pd.to_datetime(chunk['Timestamp'])
    chunk['temp_sec'] = chunk['Timestamp'].dt.floor('s')
    chunk['packet_frequency'] = chunk.groupby([source_col, 'temp_sec'])[source_col].transform('count')



    chunk["source_count"] = chunk.groupby(source_col)[source_col].transform("count")

    X = chunk[[packet_col, byte_col, "source_count", "packet_frequency"]]

    predictions = model.predict(X)

    for i, row in chunk.iterrows():
    
        is_heavy_data = float(row[byte_col]) > 100000
        is_high_freq = int(row['packet_frequency']) > 1
        
        idx = chunk.index.get_loc(i)
        if predictions[idx] == -1 or (is_heavy_data and is_high_freq):
            decision = "ATTACK"
        else:
            decision = "NORMAL"

        if decision == "NORMAL":
            normal_count += 1
            cursor.execute("""
            INSERT INTO security_logs (
                timestamp, packet_rate, byte_rate,
                source_count, ai_decision,
                mitigation_status, actions
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                float(row[packet_col]),
                float(row[byte_col]),
                int(row["source_count"]),
                "NORMAL",
                "NOT REQUIRED",
                "Traffic within normal threshold"
            ))
            conn.commit()

            print(f"✅ NORMAL | Bytes: {row[byte_col]}")
            time.sleep(0.3)

        else:
            attack_count += 1
            cursor.execute("""
            INSERT INTO security_logs (
                timestamp, packet_rate, byte_rate,
                source_count, ai_decision,
                mitigation_status, actions
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                float(row[packet_col]),
                float(row[byte_col]),
                int(row["source_count"]),
                "ATTACK",
                "STARTED",
                f"Heavy burst detected: {row['packet_frequency']} pkts/s"
            ))

            conn.commit()
            db_id = cursor.lastrowid
            action = mitigate_attack(db_id)


            print(f"\n🚨 ATTACK DETECTED | Bytes: {row[byte_col]}")
            print(f"Mitigation  : {action}")
            print("-" * 40)
            time.sleep(1.0)

conn.close()

print("\n FINAL SUMMARY")
print(f"Normal Traffic Logged : {normal_count}")
print(f"Attacks Logged        : {attack_count}")


try:
    input("\n[!] Simulation complete. Press Enter to shutdown the dashboard and exit...\n")
except KeyboardInterrupt:
    pass