# A.I.R.S — Autonomous Intelligent Response System
### AI-Based Network Intrusion Detection with LLM Analysis, Explainability & Threat Intelligence
 
---
 
## What This Project Does
 
A.I.R.S is a next-generation Network Intrusion Detection System that goes beyond simple attack classification. It detects malicious network traffic, **explains its reasoning** using SHAP, **analyzes threats in natural language** using an LLM, maps attacks to the **MITRE ATT&CK framework**, scores **threat severity**, and lets you run **live attack simulations** — all from a real-time dashboard.
 
> "It doesn't just detect attacks. It understands them."
 
---
 
## Innovation Over Standard NIDS
 
| Feature | Standard NIDS | A.I.R.S |
|---|---|---|
| Attack Detection | ✅ | ✅ |
| Model Explainability (SHAP) | ❌ | ✅ |
| LLM Threat Analysis | ❌ | ✅ |
| MITRE ATT&CK Mapping | ❌ | ✅ |
| Threat Severity Scoring | ❌ | ✅ |
| Response Recommendations | ❌ | ✅ |
| Live Attack Simulator | ❌ | ✅ |
 
---
 
## System Architecture
 
```
Network Traffic / Simulated Flows
          │
          ▼
  ┌─────────────────┐
  │  Flask Backend  │
  │                 │
  │  ┌───────────┐  │
  │  │ Isolation │  │  ← Anomaly Detection
  │  │  Forest   │  │
  │  └───────────┘  │
  │  ┌───────────┐  │
  │  │  Random   │  │  ← Attack Classification
  │  │  Forest   │  │
  │  └───────────┘  │
  │  ┌───────────┐  │
  │  │   SHAP    │  │  ← Feature Explainability
  │  │ Explainer │  │
  │  └───────────┘  │
  │  ┌───────────┐  │
  │  │   LLM     │  │  ← Natural Language Threat Report
  │  │ Analyst   │  │
  │  └───────────┘  │
  │  ┌───────────┐  │
  │  │  MITRE +  │  │  ← Severity + Response Suggestion
  │  │ Severity  │  │
  │  └───────────┘  │
  └─────────────────┘
          │
          ▼
  ┌─────────────────┐
  │ React Dashboard │
  │                 │
  │  Live Alerts    │
  │  SHAP Charts    │
  │  Threat Feed    │
  │  Sim Controls   │
  └─────────────────┘
```
 
---
 
## Tech Stack
 
**Backend**
- Python 3.8+
- Flask
- Scikit-learn (Random Forest + Isolation Forest)
- SHAP (model explainability)
- Anthropic Claude API (LLM threat analysis)
- Pandas, NumPy
- SQLite
**Frontend**
- React + Vite
- Recharts (data visualization)
- Axios (API calls)
**Dataset**
- CICIDS2017 (Canadian Institute for Cybersecurity)
---
 
## Project Structure
 
```
AIRS/
│
├── backend/
│   ├── main.py                  # Flask app entry point
│   ├── models/
│   │   ├── random_forest.joblib
│   │   └── isolation_forest.joblib
│   ├── explainer/
│   │   └── shap_explainer.py    # SHAP integration
│   ├── analyst/
│   │   └── llm_analyst.py       # Claude API threat analysis
│   ├── intelligence/
│   │   ├── mitre_mapping.py     # MITRE ATT&CK mapping
│   │   └── severity_scorer.py   # Threat severity engine
│   ├── simulator/
│   │   └── attack_simulator.py  # Live attack replay script
│   ├── database/
│   │   └── db.py
│   └── requirements.txt
│
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   ├── components/
│   │   │   ├── Dashboard.jsx
│   │   │   ├── AlertFeed.jsx        # Live alert panel
│   │   │   ├── ShapChart.jsx        # SHAP feature chart
│   │   │   ├── ThreatReport.jsx     # LLM analysis display
│   │   │   ├── SeverityBadge.jsx    # LOW/MED/HIGH/CRITICAL
│   │   │   ├── MitreBadge.jsx       # ATT&CK technique ID
│   │   │   ├── SimulatorPanel.jsx   # Attack sim controls
│   │   │   └── StatsPanel.jsx       # Network statistics
│   │   └── api/
│   │       └── client.js
│   ├── package.json
│   └── vite.config.js
│
├── MachineLearningCSV/
├── GeneratedLabelledFlows/
└── README.md
```
 
---
 
## Installation & Setup
 
### Prerequisites
- Python 3.8+
- Node.js 18+
- npm
- Anthropic API key (free tier works for demo)
### Backend Setup
 
```bash
cd backend
python -m venv venv
 
# Windows
venv\Scripts\activate
 
# Mac/Linux
source venv/bin/activate
 
pip install -r requirements.txt
```
 
Set your API key:
```bash
# Windows
set ANTHROPIC_API_KEY=your_key_here
 
# Mac/Linux
export ANTHROPIC_API_KEY=your_key_here
```
 
Run the server:
```bash
python main.py
```
Backend runs on: `http://localhost:5000`
 
### Frontend Setup
 
```bash
cd frontend
npm install
npm run dev
```
Frontend runs on: `http://localhost:5173`
 
### Run the Attack Simulator (separate terminal)
 
```bash
cd backend
python simulator/attack_simulator.py --type DDoS --rate 5
```
 
---
 
## API Endpoints
 
| Method | Endpoint | Description |
|---|---|---|
| POST | `/predict` | Classify network traffic flow |
| POST | `/analyze` | Full analysis: SHAP + LLM + MITRE + Severity |
| GET | `/stats` | Aggregate attack statistics |
| GET | `/alerts` | Recent alert history |
| POST | `/simulate` | Trigger attack simulation |
 
### Sample `/analyze` Response
 
```json
{
  "prediction": "DDoS",
  "confidence": 0.94,
  "severity": "CRITICAL",
  "shap_features": [
    { "feature": "Packet Rate", "contribution": 0.42 },
    { "feature": "Flow Duration", "contribution": 0.28 },
    { "feature": "Protocol", "contribution": 0.18 }
  ],
  "mitre": {
    "technique_id": "T1498",
    "technique_name": "Network Denial of Service",
    "tactic": "Impact"
  },
  "llm_report": "This traffic pattern is consistent with a volumetric DDoS attack targeting network bandwidth. The extremely high packet rate (42% contribution) combined with short flow durations indicates a SYN flood attempt. Recommended actions: implement rate limiting on the affected interface, block the source IP range, and alert the SOC team immediately.",
  "recommended_action": "Block source IP + Rate limit endpoint"
}
```
 
---
 
## Models Used
 
### Random Forest (Classification)
Trained on CICIDS2017 to classify traffic into:
- Benign
- DDoS
- PortScan
- Bot
- Brute Force
- Web Attack
### Isolation Forest (Anomaly Detection)
Detects zero-day / unknown attack patterns as anomalies, even if not in the training set.
 
### SHAP (Explainability)
TreeExplainer applied to Random Forest predictions — generates per-prediction feature contribution scores for transparent, auditable decisions.
 
---
 
## Live Demo Flow
 
1. Open dashboard at `http://localhost:5173`
2. Click **"Launch DDoS Simulation"** in the Simulator panel
3. Watch alerts populate in real time on the feed
4. Click any alert to see:
   - SHAP feature chart (why it was flagged)
   - MITRE ATT&CK technique badge
   - Severity level (CRITICAL)
   - LLM-generated threat report with recommended action
---
 
## Future Improvements
 
- Integration with Zeek / Suricata for real packet capture
- Deep learning (LSTM) for sequential traffic pattern analysis
- Federated learning for privacy-preserving multi-node deployment
- Automated firewall rule generation via response actions
- Role-based dashboard with analyst / admin views
---
 
## Dataset
 
CICIDS2017 — Canadian Institute for Cybersecurity  
Contains realistic network traffic with benign and attack scenarios including DoS, DDoS, Brute Force, XSS, SQL Injection, Infiltration, and Botnet traffic.
 
---
 
## License
 
Developed for academic and research purposes.
 
---
