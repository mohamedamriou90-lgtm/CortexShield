import os
import uuid
import joblib
import numpy as np
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import random

app = Flask(__name__, static_folder='../frontend', static_url_path='')
CORS(app)

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Try to load models, but don't crash if they don't exist yet
try:
    bin_model = joblib.load('models/binary_model.pkl')
    fam_model = joblib.load('models/family_model.pkl')
    scaler = joblib.load('models/scaler.pkl')
    le = joblib.load('models/label_encoder.pkl')
    feature_cols = joblib.load('models/feature_columns.pkl')
    MODELS_LOADED = True
    print("✅ Models loaded successfully!")
except Exception as e:
    MODELS_LOADED = False
    print("⚠️ Models not found. Using mock predictions.")
    print(f"   Error: {e}")
    feature_cols = ['size', 'entropy', 'num_sections', 'imports_count', 'has_debug', 'has_resources']

# Family information for simulation and impact
family_info = {
    'ransomware': {
        'description': 'Encrypts files and demands ransom payment.',
        'impact': [
            'Encrypts all documents, photos, and databases',
            'Deletes shadow copies to prevent recovery',
            'Displays ransom note demanding Bitcoin payment',
            'Changes desktop wallpaper to ransom message'
        ],
        'simulation_steps': [
            {'time': 0, 'desc': 'Dropping ransomware payload...'},
            {'time': 1, 'desc': 'Scanning for documents...'},
            {'time': 2, 'desc': 'Encrypting files...'},
            {'time': 3, 'desc': 'Deleting shadow copies...'},
            {'time': 4, 'desc': 'Displaying ransom note'}
        ]
    },
    'trojan': {
        'description': 'Disguises as legitimate software to steal data.',
        'impact': [
            'Installs keylogger to capture keystrokes',
            'Steals saved passwords from browsers',
            'Sends data to remote command & control server',
            'Downloads additional malware'
        ],
        'simulation_steps': [
            {'time': 0, 'desc': 'Installing persistence in registry...'},
            {'time': 1, 'desc': 'Keylogger activated'},
            {'time': 2, 'desc': 'Harvesting saved passwords...'},
            {'time': 3, 'desc': 'Exfiltrating data to C2 server'}
        ]
    },
    'spyware': {
        'description': 'Monitors user activity and collects information.',
        'impact': [
            'Tracks browsing history and search queries',
            'Captures screenshots periodically',
            'Records microphone and webcam',
            'Logs all keystrokes'
        ],
        'simulation_steps': [
            {'time': 0, 'desc': 'Hiding in background processes...'},
            {'time': 1, 'desc': 'Starting screen capture...'},
            {'time': 2, 'desc': 'Recording microphone...'},
            {'time': 3, 'desc': 'Sending logs to attacker'}
        ]
    },
    'worm': {
        'description': 'Self-replicates and spreads across networks.',
        'impact': [
            'Copies itself to network shares and USB drives',
            'Consumes network bandwidth',
            'Opens backdoor for other malware',
            'Slows down system performance'
        ],
        'simulation_steps': [
            {'time': 0, 'desc': 'Activating worm replication...'},
            {'time': 1, 'desc': 'Scanning local network for targets...'},
            {'time': 2, 'desc': 'Copying to vulnerable machines...'},
            {'time': 3, 'desc': 'Opening backdoor port for remote access'}
        ]
    }
}

def extract_features_from_file(file_path):
    """Simulate feature extraction for demo purposes"""
    # For demo, return random features
    # In production, you'd use pefile to extract real features
    return {
        'size': random.randint(10000, 500000),
        'entropy': round(random.uniform(4.0, 8.0), 2),
        'num_sections': random.randint(3, 10),
        'imports_count': random.randint(10, 200),
        'has_debug': random.choice([0, 1]),
        'has_resources': random.choice([0, 1])
    }

@app.route('/')
def index():
    return send_from_directory('../frontend', 'index.html')

@app.route('/scan/file', methods=['POST'])
def scan_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Empty filename'}), 400
    
    # Save file temporarily
    temp_name = str(uuid.uuid4()) + '.exe'
    temp_path = os.path.join(UPLOAD_FOLDER, temp_name)
    file.save(temp_path)
    
    # Extract features
    features = extract_features_from_file(temp_path)
    os.remove(temp_path)
    
    if MODELS_LOADED:
        # Use real models
        X = np.array([[features.get(col, 0) for col in feature_cols]])
        X_scaled = scaler.transform(X)
        bin_pred = bin_model.predict(X_scaled)[0]
        bin_proba = bin_model.predict_proba(X_scaled)[0]
        confidence = float(max(bin_proba))
    else:
        # Use mock prediction
        bin_pred = random.choice([0, 1])
        confidence = random.uniform(0.7, 0.98)
    
    result = {
        'is_malware': bool(bin_pred),
        'confidence': confidence,
        'threat_level': 'HIGH' if confidence > 0.8 else 'MEDIUM' if confidence > 0.5 else 'LOW',
        'features': features,
        'indicators': []
    }
    
    # Add indicators based on feature thresholds
    if features['entropy'] > 7.0:
        result['indicators'].append({
            'name': 'High Entropy', 
            'value': features['entropy'], 
            'verdict': 'suspicious',
            'description': 'File appears compressed or encrypted'
        })
    if features['imports_count'] > 100:
        result['indicators'].append({
            'name': 'Many Imports', 
            'value': features['imports_count'], 
            'verdict': 'suspicious',
            'description': 'Unusually high number of function calls'
        })
    if features['has_debug'] == 0:
        result['indicators'].append({
            'name': 'No Debug Info', 
            'value': 'missing', 
            'verdict': 'suspicious',
            'description': 'Debug symbols removed - common in malware'
        })
    if features['num_sections'] > 8:
        result['indicators'].append({
            'name': 'Many Sections', 
            'value': features['num_sections'], 
            'verdict': 'suspicious',
            'description': 'Unusual number of PE sections'
        })
    
    # If no suspicious indicators, add a normal one
    if len(result['indicators']) == 0:
        result['indicators'].append({
            'name': 'File Statistics', 
            'value': 'Normal', 
            'verdict': 'normal',
            'description': 'No suspicious patterns detected'
        })
    
    # If malware, add family info
    if bin_pred == 1:
        if MODELS_LOADED:
            fam_pred = fam_model.predict(X_scaled)[0]
            family = le.inverse_transform([fam_pred])[0]
        else:
            family = random.choice(['ransomware', 'trojan', 'spyware', 'worm'])
        
        result['family'] = family
        result['family_description'] = family_info.get(family, {}).get('description', 'Unknown malware')
        result['impact'] = family_info.get(family, {}).get('impact', [])
        result['simulation_steps'] = family_info.get(family, {}).get('simulation_steps', [])
    else:
        result['family'] = 'benign'
        result['family_description'] = 'No malware detected'
        result['impact'] = []
        result['simulation_steps'] = []
    
    return jsonify(result)

@app.route('/scan/url', methods=['POST'])
def scan_url():
    data = request.get_json()
    url = data.get('url')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    # Mock features for URL scan
    features = {
        'size': random.randint(10000, 500000),
        'entropy': round(random.uniform(4.0, 8.0), 2),
        'num_sections': random.randint(3, 10),
        'imports_count': random.randint(10, 200),
        'has_debug': random.choice([0, 1]),
        'has_resources': random.choice([0, 1])
    }
    
    if MODELS_LOADED:
        X = np.array([[features.get(col, 0) for col in feature_cols]])
        X_scaled = scaler.transform(X)
        bin_pred = bin_model.predict(X_scaled)[0]
        bin_proba = bin_model.predict_proba(X_scaled)[0]
        confidence = float(max(bin_proba))
    else:
        bin_pred = random.choice([0, 1])
        confidence = random.uniform(0.7, 0.98)
    
    result = {
        'is_malware': bool(bin_pred),
        'confidence': confidence,
        'threat_level': 'HIGH' if confidence > 0.8 else 'MEDIUM' if confidence > 0.5 else 'LOW',
        'features': features,
        'indicators': []
    }
    
    # Add indicators
    if features['entropy'] > 7.0:
        result['indicators'].append({
            'name': 'High Entropy', 
            'value': features['entropy'], 
            'verdict': 'suspicious',
            'description': 'File appears compressed or encrypted'
        })
    if features['imports_count'] > 100:
        result['indicators'].append({
            'name': 'Many Imports', 
            'value': features['imports_count'], 
            'verdict': 'suspicious',
            'description': 'Unusually high number of function calls'
        })
    
    if bin_pred == 1:
        if MODELS_LOADED:
            fam_pred = fam_model.predict(X_scaled)[0]
            family = le.inverse_transform([fam_pred])[0]
        else:
            family = random.choice(['ransomware', 'trojan', 'spyware', 'worm'])
        
        result['family'] = family
        result['family_description'] = family_info.get(family, {}).get('description', 'Unknown malware')
        result['impact'] = family_info.get(family, {}).get('impact', [])
        result['simulation_steps'] = family_info.get(family, {}).get('simulation_steps', [])
    else:
        result['family'] = 'benign'
        result['family_description'] = 'No malware detected'
        result['impact'] = []
        result['simulation_steps'] = []
    
    return jsonify(result)

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🚀 Starting CortexShield Server...")
    print("👤 Created by: Amriou Mohamed")
    print("📁 Backend folder:", os.getcwd())
    print("🌐 Open http://127.0.0.1:5000 in your browser")
    print("📱 Dashboard: CortexShield-by-AmriouMohamed")
    print("="*60 + "\n")
    app.run(debug=True, host='127.0.0.1', port=5000)