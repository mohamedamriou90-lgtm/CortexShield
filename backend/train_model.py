import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
import joblib
import os

print("📊 Loading dataset...")
df = pd.read_csv('sample_malware_data.csv')

# Features and targets
feature_cols = ['size', 'entropy', 'num_sections', 'imports_count', 'has_debug', 'has_resources']
X = df[feature_cols]
y_bin = df['label']
y_family = df['family']

print("🔄 Scaling features...")
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

print("🏷️ Encoding families...")
le = LabelEncoder()
y_family_encoded = le.fit_transform(y_family)

print("🌲 Training binary classifier (Malware vs Benign)...")
bin_model = RandomForestClassifier(n_estimators=100, random_state=42)
bin_model.fit(X_scaled, y_bin)
print(f"   Binary accuracy: {bin_model.score(X_scaled, y_bin):.2f}")

print("🌲 Training family classifier...")
malware_mask = (y_bin == 1)
X_mal = X_scaled[malware_mask]
y_mal = y_family_encoded[malware_mask]

fam_model = RandomForestClassifier(n_estimators=100, random_state=42)
fam_model.fit(X_mal, y_mal)
print(f"   Family accuracy: {fam_model.score(X_mal, y_mal):.2f}")

# Create models folder if it doesn't exist
os.makedirs('models', exist_ok=True)

print("💾 Saving models...")
joblib.dump(bin_model, 'models/binary_model.pkl')
joblib.dump(fam_model, 'models/family_model.pkl')
joblib.dump(scaler, 'models/scaler.pkl')
joblib.dump(le, 'models/label_encoder.pkl')
joblib.dump(feature_cols, 'models/feature_columns.pkl')

print("✅ All models saved in 'models/' folder!")