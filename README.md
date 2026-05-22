# A.I.R.S — Autonomous Intelligent Response System
### AI-Based Network Intrusion Detection · LLM Analysis · SHAP Explainability · MITRE ATT&CK · Auto-Block

> "It doesn't just detect attacks. It understands them, explains them, and responds automatically."

---

## What This Project Does

A.I.R.S (v2.0) is a next-generation Network Intrusion Detection System built for the EDI2 final-year project. It processes raw network traffic through a **9-step AI pipeline**, from packet capture to automated IP blocking:

1. **Packet Capture** — Scapy live capture (or demo mode via simulator)
2. **Flow Feature Extraction** — 5-tuple bidirectional flows → 30+ ML features
3. **ML Classification** — Isolation Forest (anomaly) + Random Forest (attack type)
4. **SHAP Explainability** — TreeExplainer explains *why* the model flagged traffic
5. **MITRE ATT&CK Mapping** — Every detection mapped to tactic + technique ID
6. **Severity Scoring** — Multi-factor score (ML confidence × attack weight × tactic weight + rate bonus)
7. **LLM Analysis** — Claude generates a natural language threat report
8. **Response Action** — Auto-block (iptables/netsh) or rate-limit the source IP
9. **Alert Logging** — Stored in SQLite, streamed live via WebSocket

---

## Innovation Over Standard NIDS

| Feature                       | Standard NIDS | A.I.R.S v2 |
|-------------------------------|:---:|:---:|
| Attack Detection               | ✅ | ✅ |
| Model Explainability (SHAP)    | ❌ | ✅ |
| LLM Threat Analysis            | ❌ | ✅ |
| MITRE ATT&CK Mapping           | ❌ | ✅ |
| Multi-Factor Severity Scoring  | ❌ | ✅ |
| Automated IP Blocking          | ❌ | ✅ |
| Live Attack Simulator          | ❌ | ✅ |
| Real-Time WebSocket Dashboard  | ❌ | ✅ |
| Pipeline Flow Visualization    | ❌ | ✅ |

---

## System Architecture

```
Network Traffic / Simulated Flows
          │
          ▼
  ┌──────────────────────────────────────┐
  │         FastAPI Backend (main.py)    │
  │                                      │
  │  PacketCapture → FlowBuilder         │
  │       │                              │
  │  FeatureExtractor                    │
  │       │                              │
  │  MLEngine ──────────────────────┐   │
  │  (IsolationForest + RF + LSTM)  │   │
  │                                 │   │
  │  SHAPExplainer ◄────────────────┘   │
  │  MITREMapper                         │
  │  SeverityScorer                      │
  │  LLMAnalyst (Claude)                 │
  │  ResponseEngine → blocker.py        │
  │       │ (iptables / netsh)           │
  │  PipelineTracker                     │
  │  WebSocket broadcast                 │
  └──────────────────────────────────────┘
          │
          ▼
  ┌──────────────────────────────────────┐
  │     React + Vite Frontend            │
  │                                      │
  │  Dashboard          PipelineFlow     │
  │  ThreatPanel ──────► ThreatDetail    │
  │  ResponsePanel (Blocked IPs)         │
  │  ImpactPanel (With/Without AIRS)     │
  │  SimulatorPanel (Live attack feed)   │
  │  AttackLogs · NetworkGraph           │
  └──────────────────────────────────────┘
```

---

## Tech Stack

**Backend**
- Python 3.11 · FastAPI · Uvicorn
- Scikit-learn (Random Forest + Isolation Forest)
- PyTorch (LSTM sequence model)
- SHAP (TreeExplainer)
- Anthropic Claude API (`claude-3-5-sonnet`)
- Pandas · NumPy · Scapy · psutil · pyarrow
- SQLite + aiosqlite (async)
- WebSockets (real-time streaming)

**Frontend**
- React 18 + Vite 7
- Recharts (SHAP charts, analytics)
- Lucide React (icons)
- Axios (HTTP client)
- CSS-only glassmorphism design (no Tailwind)

**Dataset**
- EDI_Dataset (parquet format, multi-class attack labels)
- Fallback: CICIDS2017 / synthetic demo traffic

---

## Project Structure

```
EDI2/
│
├── backend/
│   ├── main.py                       # FastAPI app + lifecycle + WS server
│   ├── api_routes.py                 # All /api/* endpoints (34 total)
│   ├── ml_engine.py                  # IsolationForest + RF + LSTM predict
│   ├── packet_capture.py             # Scapy live capture / demo mode
│   ├── flow_builder.py               # 5-tuple flow aggregation
│   ├── feature_engineering.py        # Flow → 30+ ML features
│   ├── threat_engine.py              # Per-flow threat orchestration
│   ├── threat_intel.py               # IP reputation blocklist
│   ├── drift_monitor.py              # PSI-based data drift detection
│   ├── database.py                   # SQLite async helpers
│   ├── dl_models.py                  # LSTM definition
│   ├── train_from_edi.py             # Training script (--data-dir or EDI_DATASET_PATH)
│   │
│   ├── analyst/
│   │   └── llm_analyst.py            # Claude Claude threat report generator
│   ├── explainer/
│   │   └── shap_explainer.py         # SHAP TreeExplainer integration
│   ├── intelligence/
│   │   ├── mitre_mapping.py          # ATT&CK technique DB (dos/ddos/port_scan/brute_force/bot/suspicious/blocklist)
│   │   └── severity_scorer.py        # Multi-factor score + recommended_action
│   ├── pipeline/
│   │   └── tracker.py                # 9-step pipeline timing tracker
│   ├── response_engine/
│   │   ├── response_engine.py        # Auto-block / rate-limit decisions
│   │   └── blocker.py                # iptables (Linux) / netsh (Windows) exec
│   ├── simulator/
│   │   └── attack_simulator.py       # Synthetic attack flow generator
│   │
│   ├── tests/
│   │   ├── test_core.py              # 23 unit tests (SeverityScorer, MITREMapper, FlowBuilder)
│   │   └── test_api.py               # 13 FastAPI endpoint smoke tests
│   │
│   ├── models/                       # Trained .joblib / .pth files (not in git)
│   ├── requirements.txt
│   └── .env.example
│
├── frontend/
│   ├── src/
│   │   ├── App.jsx                   # 10-tab router + sidebar + ErrorBoundary
│   │   ├── index.css                 # Glassmorphism design system
│   │   ├── services/
│   │   │   └── api.js                # Axios client + WebSocket manager
│   │   └── components/
│   │       ├── Dashboard.jsx         # Overview stats + quick sim buttons
│   │       ├── PipelineFlow.jsx      # ★ 9-step animated pipeline visualizer
│   │       ├── ThreatPanel.jsx       # Live threat feed (click → detail)
│   │       ├── ThreatDetail.jsx      # ★ SHAP chart + MITRE + LLM modal
│   │       ├── ResponsePanel.jsx     # ★ Blocked IPs + countdown + unblock
│   │       ├── ImpactPanel.jsx       # ★ With/Without AIRS comparison
│   │       ├── SimulatorPanel.jsx    # ★ Attack cards + live WS feed
│   │       ├── AttackLogs.jsx        # Paginated alert history
│   │       ├── AnalyticsCharts.jsx   # Recharts analytics
│   │       ├── NetworkGraph.jsx      # IP connection graph
│   │       ├── TrafficMonitor.jsx    # Real-time packet stats
│   │       └── ErrorBoundary.jsx     # Crash isolation per panel
│   ├── vite.config.js                # Code-split: react/recharts/lucide/axios
│   └── package.json
│
├── generate_plots.py                 # Research paper plot generator
├── research_paper.tex                # LaTeX paper
└── README.md
```

---

## Quick Start

### Prerequisites
- Python 3.11 · Node.js 18+ · npm
- Anthropic API key (for LLM reports; optional — system falls back to rule-based)
- Windows: Npcap (for live packet capture); Linux: libpcap

### 1 — Environment Variables

Copy the example and fill in your values:

```powershell
copy backend\.env.example backend\.env
```

Edit `backend/.env`:

```env
# Required for LLM threat reports
ANTHROPIC_API_KEY=sk-ant-...

# Optional — set to "true" to disable Claude (save API quota)
LLM_ENABLED=true

# Optional — API key for dashboard protection
X_API_KEY=your-demo-key

# Required only for model training (not needed to run the server)
EDI_DATASET_PATH=C:\path\to\EDI_Dataset
```

### 2 — Backend Setup

```powershell
cd backend
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Backend API: `http://localhost:8000`
Swagger docs: `http://localhost:8000/docs`

### 3 — Frontend Setup

```powershell
cd frontend
npm install
npm run dev
```

Dashboard: `http://localhost:5173`

> The Vite dev server proxies `/api` → `localhost:8000` automatically.

### 4 — (Optional) Train Models from EDI Dataset

```powershell
cd backend
python train_from_edi.py --data-dir "C:\path\to\EDI_Dataset"
# or set EDI_DATASET_PATH in .env and just run:
python train_from_edi.py
```

Trained models are saved to `backend/models/`.

---

## API Endpoints (Key Subset)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Liveness check |
| GET | `/api/system-status` | Full system component status |
| GET | `/api/traffic` | Live traffic stats |
| GET | `/api/threats` | Recent threat detections |
| GET | `/api/logs` | Paginated alert log |
| POST | `/api/analyze` | Full 9-step pipeline analysis |
| GET | `/api/explain` | SHAP feature explanations |
| GET | `/api/blocked` | Currently blocked + rate-limited IPs |
| DELETE | `/api/blocked/{ip}` | Manually unblock an IP |
| GET | `/api/impact` | Real-world impact metrics |
| POST | `/api/simulate` | Start continuous simulation |
| POST | `/api/simulate/{type}` | One-shot attack simulation |
| GET | `/api/simulate/stop` | Stop running simulation |
| GET | `/api/drift` | ML model drift status |
| GET | `/api/ip-intel/{ip}` | IP reputation lookup |
| WS | `/api/ws` | WebSocket live stream |

Full API docs at `http://localhost:8000/docs` (Swagger UI).

### Sample `/api/analyze` Response

```json
{
  "prediction": "ddos",
  "confidence": 0.94,
  "pipeline": {
    "steps": [
      { "step_name": "Packet Captured", "status": "completed", "duration_ms": 0.3 },
      { "step_name": "Flow Features Extracted", "status": "completed", "duration_ms": 2.1 },
      { "step_name": "ML Classification", "status": "completed", "duration_ms": 4.7 },
      { "step_name": "SHAP Analysis", "status": "completed", "duration_ms": 12.4 }
    ],
    "total_duration_ms": 47.2
  },
  "severity": {
    "level": "CRITICAL",
    "score": 89.5,
    "color": "#ef4444",
    "recommended_action": "Block source IP range + Engage upstream ISP for traffic scrubbing",
    "factors": [
      { "name": "ML Confidence", "contribution": 94.0 },
      { "name": "Attack Type", "contribution": 47.0 },
      { "name": "MITRE Tactic", "contribution": 18.8 }
    ]
  },
  "mitre": {
    "technique_id": "T1498",
    "technique_name": "Network Denial of Service",
    "tactic": "Impact",
    "tactic_id": "TA0040",
    "reference_url": "https://attack.mitre.org/techniques/T1498"
  },
  "response_action": { "action": "BLOCKED", "reason": "CRITICAL threat auto-blocked" },
  "llm_report": "This traffic is consistent with a volumetric DDoS attack..."
}
```

---

## Running Tests

```powershell
cd backend
pytest tests/ -v
```

| Test File | Coverage |
|-----------|----------|
| `tests/test_core.py` | SeverityScorer (8), MITREMapper (9), FlowBuilder (5), FeatureExtractor (1) |
| `tests/test_api.py` | Health, traffic, threats, blocked, impact, simulator, analyze (13) |

---

## Live Demo Flow (Presentation)

1. Open `http://localhost:5173`
2. Go to **Pipeline Flow** → select "DDoS" → click **Run Analysis**
   - Watch all 9 steps animate with real timing data
3. Go to **Simulator** → click **Launch Attack** 
   - Watch detections appear live in the feed via WebSocket
4. Go to **Response Engine**
   - Show the attacker's IP in the Blocked IPs table with live countdown
5. Go to **Threat Detection** → click any row
   - Show the SHAP chart (why flagged) + MITRE badge + AI report
6. Go to **Impact** 
   - Show "With vs Without A.I.R.S" comparison

---

## Models

### Isolation Forest (Anomaly Detection)
Detects zero-day and novel attack patterns as statistical anomalies, even if unseen during training.

### Random Forest (Attack Classification)
Classifies detected anomalies into: `normal`, `dos`, `ddos`, `port_scan`, `brute_force`, `suspicious`, `blocklist`, `bot`.

### LSTM (Sequential Pattern Detection)
Analyses temporal sequences of flow events per source IP to detect slow-burn attacks and beaconing.

### SHAP (TreeExplainer)
Per-prediction feature contribution scores — makes every classification auditable and explainable.

---

## Key Design Decisions

- **Demo mode** — If model `.joblib`/`.pth` files are absent, the backend auto-switches to rule-based heuristics + synthetic SHAP values. The full UI still works.
- **No hardcoded paths** — `train_from_edi.py` reads `EDI_DATASET_PATH` from `.env` or `--data-dir` CLI arg.
- **Memory safety** — `completed_flows` capped at 1000, `ip_packet_sizes` per IP capped at 1000.
- **IP blocking safety** — `blocker.py` validates IP strings with `ipaddress` before passing to `subprocess`.

---

## Dataset

**EDI_Dataset** — Custom parquet-format dataset used for training.  
Fallback: **CICIDS2017** (Canadian Institute for Cybersecurity) — benign + DDoS, PortScan, Brute Force, Bot, Web Attack traffic.

---

## License

Developed for academic and research purposes — EDI2 Final Year Project, Group K11.

---

*Built with ❤️ by Team K11 · FastAPI + React + scikit-learn + Claude*
