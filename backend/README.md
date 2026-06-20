# Deep Packet Analyzer Backend

This backend exposes a FastAPI endpoint for uploading PCAP files and receiving structured detection metadata from the existing C++ DPI engine.

## Setup

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run

```bash
uvicorn app:app --reload --host 0.0.0.0 --port 8000
```

## API

- `GET /health` — health check
- `POST /upload-pcap` — upload a PCAP file as `file` form data

The endpoint returns JSON with blocked event details, threat counts, and severity statistics.
