import pandas as pd
import pickle
from sklearn.ensemble import IsolationForest

print(" Training AI model on DrDoS CSV sample...")


df = pd.read_csv("DrDoS_UDP.csv", nrows=50000, low_memory=False)

df.columns = df.columns.str.strip()


df['Timestamp'] = pd.to_datetime(df['Timestamp'])
df['temp_sec'] = df['Timestamp'].dt.floor('s')
df['packet_frequency'] = df.groupby(['Source IP', 'temp_sec'])['Source IP'].transform('count')



df["source_count"] = df.groupby('Source IP')['Source IP'].transform("count")


X = df[['Flow Packets/s', 'Flow Bytes/s', 'source_count', 'packet_frequency']]

model = IsolationForest(n_estimators=100, contamination=0.15, random_state=42)
model.fit(X)


with open("model.pkl", "wb") as f:
    pickle.dump(model, f)

print(" Model trained and saved as model.pkl")