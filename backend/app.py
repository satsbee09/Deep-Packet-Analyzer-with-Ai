from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import re
from typing import List, Dict

from joblib import load
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BACKEND_DIR))

from ai_pattern_store import AIPatternStore
from ai_feature_extractor import build_feature_dataframe

ANALYZER_BINARY = PROJECT_ROOT / "build" / "deep_packet_analyzer"
RULE_FILE = PROJECT_ROOT / "config" / "rules.txt"
AI_PATTERN_FILE = PROJECT_ROOT / "backend" / "data" / "ai_patterns.json"
ML_MODEL_FILE = PROJECT_ROOT / "backend" / "data" / "lightgbm_model.joblib"

pattern_store = AIPatternStore(AI_PATTERN_FILE)
pattern_store.load()

ml_model = None
if ML_MODEL_FILE.exists():
    try:
        ml_model = load(ML_MODEL_FILE)
    except Exception:
        ml_model = None

app = FastAPI(
    title="Deep Packet Analyzer API",
    description="Upload PCAP files and receive structured threat analytics from the C++ DPI engine.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

severity_map = {
    "SQL Injection": "critical",
    "Cross Site Scripting": "high",
    "Suspicious HTTPS Host": "high",
    "FTP Traffic": "medium",
    "Suspicious URL": "medium",
    "HTTPS": "low",
    "HTTP": "low",
}

BLOCKED_LINE_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) BLOCKED: (?P<summary>.*?) reasons=(?P<reasons>.*)$"
)
SUMMARY_RE = re.compile(r"^(?P<src>[^:]+):(?P<src_port>\d+) -> (?P<dst>[^:]+):(?P<dst_port>\d+) \[(?P<protocol>.*?)\]$")


def _parse_event_line(line: str) -> Dict:
    match = BLOCKED_LINE_RE.match(line.strip())
    if not match:
        return {}

    data = match.groupdict()
    summary = data["summary"]
    reasons = [reason.strip() for reason in data["reasons"].split(";") if reason.strip()]
    summary_match = SUMMARY_RE.search(summary)

    event = {
        "timestamp": data["timestamp"],
        "summary": summary,
        "reasons": [],
        "sourceIp": None,
        "sourcePort": None,
        "destinationIp": None,
        "destinationPort": None,
        "protocol": None,
        "severity": "low",
        "hostName": None,
        "serverName": None,
        "applicationProtocol": None,
    }

    if summary_match:
        event.update(
            {
                "sourceIp": summary_match.group("src"),
                "sourcePort": int(summary_match.group("src_port")),
                "destinationIp": summary_match.group("dst"),
                "destinationPort": int(summary_match.group("dst_port")),
                "protocol": summary_match.group("protocol"),
            }
        )

    for reason in reasons:
        if reason.startswith("SNI="):
            event["serverName"] = reason.split("=", 1)[1]
            continue
        if reason.startswith("Host=" ):
            event["hostName"] = reason.split("=", 1)[1]
            continue
        if reason in ("HTTPS", "HTTP"):
            event["applicationProtocol"] = reason
            continue

        if reason.startswith("Rule="):
            rule_name = reason.split("=", 1)[1].upper()
            if rule_name == "SQL_INJECTION":
                reason = "SQL Injection"
            elif rule_name == "XSS":
                reason = "Cross Site Scripting"
            elif rule_name == "SUSPICIOUS_HTTPS_HOST":
                reason = "Suspicious HTTPS Host"
            elif rule_name == "SUSPICIOUS_URL":
                reason = "Suspicious URL"
            elif rule_name == "FTP_TRAFFIC":
                reason = "FTP Traffic"
            else:
                reason = rule_name.replace("_", " ").title()

        event["reasons"].append(reason)

        if reason in severity_map:
            event["severity"] = severity_map[reason]
            continue

    return event


def _parse_analysis_output(log_text: str) -> Dict:
    events = []
    for line in log_text.splitlines():
        event = _parse_event_line(line)
        if event:
            events.append(event)

    threat_counts: Dict[str, int] = {}
    severity_counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for event in events:
        for reason in event["reasons"]:
            threat_counts[reason] = threat_counts.get(reason, 0) + 1
        severity_counts[event["severity"]] += 1

    https_count = sum(1 for event in events if event.get("applicationProtocol") == "HTTPS")

    return {
        "summary": {
            "totalBlocked": len(events),
            "uniqueThreats": len(threat_counts),
            "threatCounts": threat_counts,
            "severityCounts": severity_counts,
            "httpsCount": https_count,
        },
        "events": events,
    }


def _record_ai_patterns(events: List[Dict]) -> None:
    for event in events:
        pattern_store.learn_from_event(event)
    pattern_store.save()


def _build_ai_insights(events: List[Dict]) -> Dict:
    return {
        "predictions": pattern_store.predict_from_events(events),
        "topPatterns": pattern_store.top_patterns(10),
    }


def _score_with_ml(pcap_path: Path) -> Dict:
    if ml_model is None:
        return {
            "modelLoaded": False,
            "suspiciousCount": 0,
            "averageScore": 0.0,
            "topSuspicious": [],
        }

    rows = build_feature_dataframe(pcap_path)
    if not rows:
        return {
            "modelLoaded": True,
            "suspiciousCount": 0,
            "averageScore": 0.0,
            "topSuspicious": [],
        }

    df = pd.DataFrame(rows)
    try:
        scores = ml_model.predict_proba(df)[:, 1]
    except Exception:
        scores = ml_model.predict(df)
    df['score'] = [float(x) for x in scores]
    df['prediction'] = [int(x) for x in (ml_model.predict(df) if hasattr(ml_model, 'predict') else [0] * len(df))]

    top_suspicious = df.sort_values('score', ascending=False).head(5)
    top_list = [
        {
            'packetIndex': int(idx),
            'score': float(row['score']),
            'prediction': int(row['prediction']),
            'srcPort': int(row['src_port']),
            'dstPort': int(row['dst_port']),
            'protocol': int(row['protocol']),
        }
        for idx, row in top_suspicious.iterrows()
    ]

    suspicious_count = int((df['prediction'] == 1).sum())
    average_score = float(df['score'].mean()) if not df['score'].empty else 0.0

    return {
        "modelLoaded": True,
        "suspiciousCount": suspicious_count,
        "averageScore": average_score,
        "topSuspicious": top_list,
    }


@app.get("/health")
async def health() -> Dict[str, str]:
    return {"status": "ok", "analyzer": str(ANALYZER_BINARY)}


@app.post("/upload-pcap")
async def upload_pcap(file: UploadFile = File(...)) -> Dict:
    if not ANALYZER_BINARY.exists() or not ANALYZER_BINARY.is_file():
        raise HTTPException(status_code=500, detail="C++ analyzer binary not found. Build the project first.")

    if not RULE_FILE.exists():
        raise HTTPException(status_code=500, detail="Rule file not found. Make sure config/rules.txt exists.")

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_dir_path = Path(tmp_dir)
        upload_path = tmp_dir_path / file.filename
        analysis_log = tmp_dir_path / "analysis.log"

        with upload_path.open("wb") as out_file:
            shutil.copyfileobj(file.file, out_file)

        command = [
            str(ANALYZER_BINARY),
            "--offline",
            str(upload_path),
            "--rules",
            str(RULE_FILE),
            "--log",
            str(analysis_log),
        ]

        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0:
            raise HTTPException(
                status_code=500,
                detail={
                    "message": "Analyzer failed.",
                    "stderr": result.stderr.strip(),
                    "stdout": result.stdout.strip(),
                },
            )

        log_text = analysis_log.read_text() if analysis_log.exists() else ""
        parsed = _parse_analysis_output(log_text)
        _record_ai_patterns(parsed["events"])
        ml_results = _score_with_ml(upload_path)
        return {
            **parsed,
            "aiInsights": _build_ai_insights(parsed["events"]),
            "mlInsights": ml_results,
        }
