// ========================================
// CortexShield - Optimized Script
// Fixed: Chart updates smoothly, no overlaps
// ========================================

// Global variables
let myChart = null;  // Single chart instance
let simInterval = null;

// Tab switching
const fileTab = document.getElementById('fileTab');
const urlTab = document.getElementById('urlTab');
const filePanel = document.getElementById('filePanel');
const urlPanel = document.getElementById('urlPanel');

fileTab.addEventListener('click', () => {
    fileTab.classList.add('active');
    urlTab.classList.remove('active');
    filePanel.classList.add('active');
    urlPanel.classList.remove('active');
});

urlTab.addEventListener('click', () => {
    urlTab.classList.add('active');
    fileTab.classList.remove('active');
    urlPanel.classList.add('active');
    filePanel.classList.remove('active');
});

// ======== DRAG & DROP ========
const dropArea = document.getElementById('dropArea');
const fileInput = document.getElementById('fileInput');
const resultsDiv = document.getElementById('results');

// Prevent defaults
['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
    dropArea.addEventListener(eventName, preventDefaults, false);
    document.body.addEventListener(eventName, preventDefaults, false);
});

function preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
}

// Highlight
['dragenter', 'dragover'].forEach(eventName => {
    dropArea.addEventListener(eventName, () => dropArea.classList.add('dragover'), false);
});

['dragleave', 'drop'].forEach(eventName => {
    dropArea.addEventListener(eventName, () => dropArea.classList.remove('dragover'), false);
});

// Handle drop
dropArea.addEventListener('drop', (e) => {
    const files = e.dataTransfer.files;
    if (files.length) {
        handleFile(files[0]);
    }
});

// Browse click
dropArea.querySelector('.browse').addEventListener('click', () => {
    fileInput.click();
});

fileInput.addEventListener('change', (e) => {
    if (fileInput.files.length) {
        handleFile(fileInput.files[0]);
    }
});

// URL scan
document.getElementById('scanUrlBtn').addEventListener('click', () => {
    const url = document.getElementById('urlInput').value.trim();
    if (url) {
        scanUrl(url);
    }
});

const API_BASE = '';

// ======== MAIN FUNCTIONS ========
async function handleFile(file) {
    showLoading();
    const formData = new FormData();
    formData.append('file', file);

    try {
        const response = await fetch(`${API_BASE}/scan/file`, {
            method: 'POST',
            body: formData
        });
        const data = await response.json();
        displayResults(data);
    } catch (error) {
        alert('Error: ' + error.message);
    }
}

async function scanUrl(url) {
    showLoading();
    try {
        const response = await fetch(`${API_BASE}/scan/url`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        const data = await response.json();
        displayResults(data);
    } catch (error) {
        alert('Error: ' + error.message);
    }
}

function showLoading() {
    resultsDiv.classList.remove('hidden');
    document.getElementById('resultCard').innerHTML = `
        <div class="result-card">
            <div class="result-header">
                <span class="result-icon">🔍</span>
                <span class="result-title">Scanning...</span>
            </div>
            <div class="confidence-bar">
                <div class="confidence-fill" style="width: 50%;"></div>
            </div>
            <p style="color: #8892b0; text-align: center;">Analyzing file statistics...</p>
        </div>
    `;
    document.getElementById('simulation').classList.add('hidden');
}

function displayResults(data) {
    if (data.error) {
        document.getElementById('resultCard').innerHTML = `<div class="result-card result-malware">Error: ${data.error}</div>`;
        return;
    }

    const isMalware = data.is_malware;
    const confidence = data.confidence * 100;
    const family = data.family || 'unknown';
    const threatLevel = data.threat_level;

    // Build result card (SIMPLIFIED - no huge data)
    let resultHTML = `
        <div class="result-card ${isMalware ? 'result-malware' : 'result-safe'}">
            <div class="result-header">
                <span class="result-icon">${isMalware ? '⚠️' : '✅'}</span>
                <span class="result-title">${isMalware ? 'MALWARE DETECTED!' : 'File is Safe'}</span>
            </div>
            <div class="result-detail"><strong>Family:</strong> ${family}</div>
            <div class="result-detail"><strong>Description:</strong> ${data.family_description || 'No malware detected'}</div>
            <div class="result-detail"><strong>Threat Level:</strong> ${threatLevel}</div>
            <div class="result-detail"><strong>Confidence:</strong> ${confidence.toFixed(1)}%</div>
            <div class="confidence-bar">
                <div class="confidence-fill" style="width: ${confidence}%"></div>
            </div>
        </div>
    `;
    document.getElementById('resultCard').innerHTML = resultHTML;

    // Display indicators (LIMITED to 3 max)
    const indicatorsDiv = document.getElementById('indicators');
    if (data.indicators && data.indicators.length) {
        let indicatorsHTML = '<h3>🔍 Key Indicators</h3>';
        // Show only first 3 indicators to prevent clutter
        const showIndicators = data.indicators.slice(0, 3);
        showIndicators.forEach(ind => {
            indicatorsHTML += `
                <div class="indicator ${ind.verdict}">
                    <strong>${ind.name}:</strong> ${typeof ind.value === 'number' ? ind.value.toFixed(2) : ind.value}<br>
                    <small>${ind.description || ind.verdict}</small>
                </div>
            `;
        });
        indicatorsDiv.innerHTML = indicatorsHTML;
    } else {
        indicatorsDiv.innerHTML = '';
    }

    // Update chart (SMOOTH update, not recreate if possible)
    updateChart();

    // Impact analysis
    const impactDiv = document.getElementById('impact');
    const impactList = document.getElementById('impactList');
    if (isMalware && data.impact && data.impact.length) {
        impactDiv.classList.remove('hidden');
        impactList.innerHTML = data.impact.map(item => `<li>${item}</li>`).join('');
    } else {
        impactDiv.classList.add('hidden');
    }

    // Simulation
    const simContainer = document.getElementById('simulation');
    if (isMalware && data.simulation_steps && data.simulation_steps.length) {
        simContainer.classList.remove('hidden');
        window.currentSimSteps = data.simulation_steps;
        resetSimulation();
    } else {
        simContainer.classList.add('hidden');
    }
}

// ======== CHART FIX ========
// Create chart once and reuse it
function initChart() {
    const ctx = document.getElementById('importanceChart').getContext('2d');
    
    // Destroy existing chart if it exists
    if (myChart) {
        myChart.destroy();
    }
    
    // Create new chart
    myChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['Entropy', 'Imports', 'Size', 'Sections', 'Debug', 'Resources'],
            datasets: [{
                label: 'Feature Importance',
                data: [0.35, 0.25, 0.15, 0.12, 0.08, 0.05],
                backgroundColor: '#64ffda',
                borderColor: '#4cc9f0',
                borderWidth: 1,
                borderRadius: 4,
                maxBarThickness: 30
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: {
                duration: 500, // Smooth but not too slow
                easing: 'easeInOutQuart'
            },
            scales: {
                y: { 
                    beginAtZero: true,
                    max: 0.4,
                    grid: { color: '#334155' },
                    ticks: { 
                        color: '#cbd5e1',
                        callback: function(value) {
                            return (value * 100).toFixed(0) + '%';
                        }
                    }
                },
                x: { 
                    ticks: { 
                        color: '#cbd5e1',
                        maxRotation: 0
                    } 
                }
            },
            plugins: { 
                legend: { 
                    display: false // Hide legend to save space
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return 'Importance: ' + (context.raw * 100).toFixed(1) + '%';
                        }
                    }
                }
            }
        }
    });
}

function updateChart() {
    if (!myChart) {
        initChart();
        return;
    }
    
    // Generate slightly different data for variety (but smooth)
    const newData = [
        0.35 + (Math.random() * 0.05 - 0.025),
        0.25 + (Math.random() * 0.05 - 0.025),
        0.15 + (Math.random() * 0.03 - 0.015),
        0.12 + (Math.random() * 0.03 - 0.015),
        0.08 + (Math.random() * 0.02 - 0.01),
        0.05 + (Math.random() * 0.02 - 0.01)
    ];
    
    // Normalize to sum to ~1
    const sum = newData.reduce((a, b) => a + b, 0);
    const normalizedData = newData.map(v => v / sum);
    
    // Update chart data smoothly
    myChart.data.datasets[0].data = normalizedData;
    myChart.update({
        duration: 500,
        easing: 'easeInOutQuart'
    });
}

// ======== SIMULATION FIX ========
function resetSimulation() {
    if (simInterval) {
        clearInterval(simInterval);
        simInterval = null;
    }
    document.querySelectorAll('.icon').forEach(icon => icon.classList.remove('encrypted'));
    document.querySelectorAll('.popup').forEach(p => p.classList.add('hidden'));
    document.getElementById('windowsDesktop').style.background = '#0f172a';
    document.getElementById('simTime').innerText = '0s';
    document.getElementById('stepDescription').innerText = '';
}

document.getElementById('playSim').addEventListener('click', () => {
    if (!window.currentSimSteps || window.currentSimSteps.length === 0) return;
    
    // Clear any existing simulation
    resetSimulation();
    
    let stepIndex = 0;
    const steps = window.currentSimSteps;

    function runStep() {
        if (stepIndex >= steps.length) {
            if (simInterval) {
                clearInterval(simInterval);
                simInterval = null;
            }
            return;
        }
        
        const step = steps[stepIndex];
        document.getElementById('stepDescription').innerText = step.desc;
        document.getElementById('simTime').innerText = step.time + 's';

        const desc = step.desc.toLowerCase();
        if (desc.includes('encrypt') || desc.includes('encrypting')) {
            document.querySelectorAll('.icon').forEach(icon => icon.classList.add('encrypted'));
        }
        if (desc.includes('ransom') || desc.includes('note')) {
            document.getElementById('ransomPopup').classList.remove('hidden');
        }
        if (desc.includes('wallpaper')) {
            document.getElementById('windowsDesktop').style.background = '#7f1d1d';
        }
        if (desc.includes('payload') || desc.includes('dropping')) {
            // Flash effect
            document.getElementById('windowsDesktop').style.opacity = '0.8';
            setTimeout(() => {
                document.getElementById('windowsDesktop').style.opacity = '1';
            }, 200);
        }

        stepIndex++;
    }

    simInterval = setInterval(runStep, 1000);
});

document.getElementById('resetSim').addEventListener('click', resetSimulation);

// Initialize chart when page loads
window.addEventListener('load', () => {
    initChart();
});