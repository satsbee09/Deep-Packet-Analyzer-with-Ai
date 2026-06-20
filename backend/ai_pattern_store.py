import json
from datetime import datetime
from pathlib import Path

class AIPatternStore:
    def __init__(self, path: Path):
        self.path = path
        self.data = {"patterns": {}}

    def load(self):
        if self.path.exists():
            try:
                with self.path.open("r", encoding="utf-8") as handle:
                    self.data = json.load(handle)
            except (json.JSONDecodeError, OSError):
                self.data = {"patterns": {}}
        else:
            self.save()

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("w", encoding="utf-8") as handle:
            json.dump(self.data, handle, indent=2)

    def _bucket(self, kind: str) -> dict:
        return self.data["patterns"].setdefault(kind, {})

    def record_pattern(self, kind: str, value: str):
        bucket = self._bucket(kind)
        entry = bucket.get(value, {"count": 0, "lastSeen": None})
        entry["count"] += 1
        entry["lastSeen"] = datetime.utcnow().isoformat() + "Z"
        bucket[value] = entry

    def learn_from_event(self, event: dict):
        for reason in event.get("reasons", []):
            if reason == "SQL Injection":
                self.record_pattern("SQL Injection", "sql-injection")
            elif reason == "Cross Site Scripting":
                self.record_pattern("Cross Site Scripting", "xss")
            elif reason == "Suspicious HTTPS Host":
                server_name = event.get("serverName") or event.get("hostName")
                if server_name:
                    self.record_pattern("Suspicious HTTPS Host", server_name)
            elif reason == "Suspicious URL":
                self.record_pattern("Suspicious URL", "suspicious-url")
            elif reason == "FTP Traffic":
                self.record_pattern("FTP Traffic", "ftp-traffic")

        if event.get("applicationProtocol") == "HTTPS" and event.get("serverName"):
            self.record_pattern("HTTPS Host Seen", event["serverName"])

    def top_patterns(self, limit: int = 10) -> list:
        entries = []
        for kind, bucket in self.data.get("patterns", {}).items():
            for value, details in bucket.items():
                entries.append(
                    {
                        "type": kind,
                        "value": value,
                        "count": details.get("count", 0),
                        "lastSeen": details.get("lastSeen"),
                    }
                )
        entries.sort(key=lambda item: item["count"], reverse=True)
        return entries[:limit]

    def predict_from_events(self, events: list) -> list:
        predictions = []
        seen = set()
        suspicious_hosts = self.data.get("patterns", {}).get("Suspicious HTTPS Host", {})
        for event in events:
            host_name = event.get("serverName") or event.get("hostName")
            if host_name and host_name in suspicious_hosts and host_name not in seen:
                predictions.append(
                    {
                        "pattern": "Suspicious HTTPS Host",
                        "value": host_name,
                        "confidence": "90%",
                        "reason": "Seen before in AI pattern store",
                    }
                )
                seen.add(host_name)
        return predictions
