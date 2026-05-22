# AI-Based Network Intrusion Detection System Using Machine Learning

This project implements an **AI-powered Network Intrusion Detection System (NIDS)** that uses machine learning models to analyze network traffic and detect malicious activities such as **DDoS attacks, Port Scans, and Bot traffic**.

The system combines a **Python Flask backend for machine learning inference** with a **React + Vite frontend dashboard** that visualizes network statistics and detected threats in real time.

---

# System Overview

The system follows a multi-stage pipeline:

1. Network traffic data collection
2. Data preprocessing and feature extraction
3. Machine learning model inference
4. Attack classification
5. Real-time visualization on a dashboard

The backend processes traffic data and predicts attack types, while the frontend provides a monitoring interface for network activity and threat alerts.

---

# Features

### Machine Learning-Based Detection

Uses trained models to classify network traffic as **benign or malicious**.

Supported attack types include:

* DDoS
* PortScan
* Bot traffic
* Brute Force attempts

### Real-Time Dashboard

A modern React dashboard displaying:

* Network traffic statistics
* Model predictions
* Attack distribution charts
* Activity logs

### REST API

A Flask backend exposes API endpoints for:

* model predictions
* attack statistics
* visualization data

---

# Machine Learning Models Used

The system uses two types of machine learning approaches:

### Isolation Forest

Used for **anomaly detection** to identify unusual traffic patterns.

### Random Forest

Used for **classification of attack types** based on extracted traffic features.

Both models are trained using network traffic datasets and integrated into the backend for inference.

---

# Dataset Used

The models are trained using the **CICIDS2017 dataset**, which contains realistic network traffic including both normal activity and multiple cyber attack scenarios.

---

# Tech Stack

### Backend

* Python
* Flask
* Scikit-learn
* Pandas
* NumPy
* SQLite

### Frontend

* React
* Vite
* Chart libraries for visualization

---

# Project Structure

```
project-root
│
├── backend/
│   ├── main.py
│   ├── models/
│   ├── database/
│   └── requirements.txt
│
├── frontend/
│   ├── src/
│   ├── components/
│   └── vite.config.js
│
├── MachineLearningCSV/
│   Dataset files used for training
│
├── GeneratedLabelledFlows/
│   Processed network flow data
│
└── README.md
```

---

# Installation & Setup

## Prerequisites

* Python 3.8+
* Node.js
* npm

---

# Backend Setup

Navigate to the backend folder

```
cd backend
```

Create a virtual environment (optional)

```
python -m venv venv
```

Activate environment

```
venv\Scripts\activate
```

Install dependencies

```
pip install -r requirements.txt
```

Run the server

```
python main.py
```

Backend will run on:

```
http://localhost:5000
```

---

# Frontend Setup

Navigate to frontend

```
cd frontend
```

Install dependencies

```
npm install
```

Run the development server

```
npm run dev
```

Frontend will run on:

```
http://localhost:5173
```

---

# Usage

Once both backend and frontend are running:

1. Open the dashboard in your browser.
2. The frontend connects to the backend API.
3. Network traffic data is analyzed using the ML models.
4. Detected attacks and statistics are displayed in real time.

---

# Future Improvements

Possible improvements include:

* Integration with real packet capture tools
* Deep learning models for sequential traffic analysis
* Distributed deployment for enterprise networks
* Enhanced authentication and security for the dashboard

---

# License

This project is developed for educational and research purposes.
