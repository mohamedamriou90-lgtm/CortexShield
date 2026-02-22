import pandas as pd
import numpy as np
import os

print("="*50)
print("📊 Generating Sample Dataset for CortexShield")
print("="*50)

# Generate 1000 samples
np.random.seed(42)
n_samples = 1000

# Features: size, entropy, num_sections, imports_count, has_debug, has_resources
features = ['size', 'entropy', 'num_sections', 'imports_count', 'has_debug', 'has_resources']

# Generate random feature values
X = np.random.rand(n_samples, len(features)) * [100000, 8, 10, 200, 1, 1]
X = X.astype(int)
X[:, 1] = X[:, 1] / 100  # Fix entropy to be float

# Labels: 70% benign (0), 30% malware (1)
y_bin = np.random.choice([0, 1], size=n_samples, p=[0.7, 0.3])

# Families (only for malware samples)
families = []
for i in range(n_samples):
    if y_bin[i] == 1:
        families.append(np.random.choice(['ransomware', 'trojan', 'spyware', 'worm']))
    else:
        families.append('benign')

# Create DataFrame
df = pd.DataFrame(X, columns=features)
df['label'] = y_bin
df['family'] = families

# Save to CSV
df.to_csv('sample_malware_data.csv', index=False)
print("\n✅ Sample dataset created: sample_malware_data.csv")
print(f"   Total samples: {len(df)}")
print(f"   Malware samples: {sum(y_bin)}")
print(f"   Benign samples: {len(df) - sum(y_bin)}")
print(f"\n📊 Family distribution:")
print(df['family'].value_counts())
print("\n" + "="*50)