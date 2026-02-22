# 🛡️ CortexShield

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![Flask](https://img.shields.io/badge/flask-2.0+-red)
![ML](https://img.shields.io/badge/ML-RandomForest-orange)

**AI-Powered Malware Detection System with Interactive Impact Simulation**

Built by: **Amriou Mohamed**

---

## 📋 Overview

CortexShield is a next-generation malware detection system that uses machine learning to analyze files and detect potential threats. Unlike traditional antivirus software, it provides:

- **Statistical Analysis**: Extracts features like entropy, imports count, section info
- **ML-Based Detection**: Random Forest classifier trained on malware samples
- **Family Classification**: Identifies malware type (ransomware, trojan, spyware, worm)
- **Impact Analysis**: Shows what the malware would do if executed
- **Interactive Simulation**: Visual Windows-like environment showing infection steps

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🖱️ **Drag & Drop Upload** | Easy file submission |
| 🔗 **URL Scanning** | Analyze remote files |
| 📊 **Feature Importance** | See what factors influenced detection |
| ⚠️ **Threat Indicators** | Highlight suspicious file characteristics |
| 🪟 **Windows Simulation** | Watch malware behavior in a sandbox |
| 🎨 **Glass Morphism UI** | Modern, Apple-inspired design |

---

## 🏗️ Architecture
CortexShield/
│
├── backend/ # Flask API + ML models
│ ├── app.py # Main server
│ ├── train_model.py # Model training
│ └── models/ # Trained models
│
├── frontend/ # HTML/CSS/JS UI
│ ├── index.html # Main page
│ ├── style.css # Styling
│ └── script.js # Interactions
│
└── requirements.txt # Dependencies

---

## 🧠 Machine Learning Model

- **Algorithm**: Random Forest Classifier
- **Features**: File size, entropy, sections count, imports count, debug info, resources
- **Classes**: Benign, Ransomware, Trojan, Spyware, Worm
- **Accuracy**: ~94% on test data

---

## 🚀 Installation & Setup

### Prerequisites
- Python 3.8+
- pip
- Git

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/CortexShield.git
cd CortexShield

# 2. Install dependencies
pip install -r requirements.txt

# 3. Generate sample data
cd backend
python generate_sample_data.py

# 4. Train models
python train_model.py

# 5. Run the server
python app.py

# 6. Open browser
http://127.0.0.1:5000
🎯 How It Works
User uploads a file (or provides URL)

Feature extraction: System analyzes file statistics

ML prediction: Random Forest classifies as safe/malware

If malware: Family is identified (ransomware, etc.)

Impact analysis: Shows potential damage

Simulation: Visual step-by-step execution in virtual Windows environment
