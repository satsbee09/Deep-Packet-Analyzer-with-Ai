# Deep Packet Analyzer with AI

A C++ project for analyzing PCAP files and generating packet summaries, now extended with a FastAPI backend and React dashboard.
# Deep Packet Inspection & Threat Analytics Platform

## Overview

Deep Packet Inspection & Threat Analytics Platform is a cybersecurity application that analyzes network traffic from PCAP files and detects malicious activities using signature-based Deep Packet Inspection (DPI).

The system parses network packets, extracts payload data, applies detection rules, and visualizes threats through a modern web dashboard.

---

## Features

### Network Packet Analysis

* PCAP file processing
* Ethernet frame parsing
* IPv4 packet parsing
* TCP packet parsing
* UDP packet parsing

### Threat Detection

* SQL Injection Detection
* Cross-Site Scripting (XSS) Detection
* Suspicious URL Detection
* FTP Traffic Detection
* Suspicious HTTPS Host Detection

### Logging & Monitoring

* Threat logging
* Timestamped alerts
* Source and destination tracking
* Detection history

### Dashboard

* PCAP Upload Interface
* Threat Visualization
* Severity Classification
* Detection Statistics
* Interactive Charts

---

## Architecture

```text
React Dashboard
        │
        ▼
FastAPI Backend
        │
        ▼
C++ DPI Engine
        │
        ▼
Packet Parser
        │
        ▼
Rule Engine
        │
        ▼
Threat Detection
        │
        ▼
Logs & Reports
```

---

## Technology Stack

### Backend

* C++
* libpcap
* FastAPI
* Python

### Frontend

* React
* TypeScript
* Vite
* Recharts

### Build Tools

* CMake
* GCC/G++

---

## Project Structure

```text
Deep-Packet-Analyzer-with-Ai/
│
├── backend/
│   └── app.py
│
├── frontend/
│   ├── src/
│   └── public/
│
├── src/
│   ├── parser/
│   ├── dpi/
│   ├── capture/
│   └── logger/
│
├── include/
├── config/
│   └── rules.txt
│
├── tests/
│   ├── attack.pcap
│   ├── attack_xss.pcap
│   ├── ftp_demo.pcap
│   └── normal_http.pcap
│
└── build/
```

---

## Installation

### Clone Repository

```bash
git clone <repository-url>
cd Deep-Packet-Analyzer-with-Ai
```

### Build C++ Analyzer

```bash
mkdir build
cd build

cmake ..
cmake --build .
```

---

## Running Backend

```bash
cd backend

pip install -r requirements.txt

uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

API Documentation:

```text
http://localhost:8000/docs
```

---

## Running Frontend

```bash
cd frontend

npm install --legacy-peer-deps

npm run dev
```

Frontend URL:

```text
http://localhost:5173
```

---

## Running Analyzer Directly

```bash
./deep_packet_analyzer \
--offline ../tests/attack.pcap \
--rules ../config/rules.txt \
--log ../tests/attack.log
```

---

## Sample Detection Output

```text
BLOCKED:
10.0.0.1:12345 -> 10.0.0.2:80
Reasons = SQL Injection
Rule = SQL_INJECTION
```

---

## Detection Rules

```text
SQL_INJECTION:' OR 1=1
XSS:<script>
SUSPICIOUS_URL:http://
SUSPICIOUS_URL:https://
FTP_TRAFFIC:ftp
```

---

## Demo Scenarios

### Normal Traffic

* File: normal_http.pcap
* Result: No Threats Detected

### SQL Injection

* File: attack.pcap
* Result: SQL Injection Alert

### Cross Site Scripting

* File: attack_xss.pcap
* Result: XSS Alert

### FTP Traffic

* File: ftp_demo.pcap
* Result: FTP Traffic Alert

---

## Future Enhancements

* Real-time packet capture
* Machine Learning based anomaly detection
* Multi-threaded packet processing
* Threat intelligence integration
* PDF report generation
* SIEM integration
* Cloud deployment

---

## Author

Satyam Singh

B.Tech Computer Science Engineering

GL Bajaj Institute of Technology and Management

GitHub: https://github.com/satsbee09


## Build

Requires CMake and libpcap.

```bash
mkdir -p build
cd build
cmake ..
cmake --build .
```

## Usage

Offline analysis:

```bash
./build/deep_packet_analyzer --offline <pcap-file> [--rules <rule-file>] [--log <log-file>] [--no-log]
```

Live capture (requires privileges):

```bash
./build/deep_packet_analyzer --live <interface> [--rules <rule-file>] [--log <log-file>] [--no-log]
```

## Backend API

A FastAPI backend exposes a PCAP upload endpoint that runs the C++ DPI engine and returns structured threat data.

### Setup

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Run

```bash
cd backend
uvicorn app:app --reload --host 0.0.0.0 --port 8000
```

### API

- `GET /health` — health check
- `POST /upload-pcap` — upload a PCAP file as form data `file`

## Frontend Dashboard

A React dashboard lets users upload PCAP files, view threat summaries, and inspect detection events.

### Setup

```bash
cd frontend
npm install
```

### Run

```bash
cd frontend
npm run dev
```

### Build

```bash
cd frontend
npm run build
```

## Project Structure

- `CMakeLists.txt` - Build configuration
- `src/` - C++ source files
- `backend/` - FastAPI backend wrapper for the C++ analyzer
- `frontend/` - React dashboard
- `tests/` - Sample PCAP and test scripts

## Notes

- Uses `libpcap` for PCAP file parsing.
- The analyzer includes packet source/destination and protocol summaries.
- Frontend and backend are designed so the C++ engine stays unchanged while adding a production-style interface.

## Tests

Place a sample PCAP at `tests/sample.pcap` then run the test script:

```bash
./tests/run_test.sh
```

The script will run the analyzer and produce `tests/test.log`.
