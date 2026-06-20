# Deep Packet Analyzer with AI

A C++ project for analyzing PCAP files and generating packet summaries, now extended with a FastAPI backend and React dashboard.

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
