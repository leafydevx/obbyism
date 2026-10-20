import json
import datetime
import hashlib
from pathlib import Path


class Session:
    def __init__(self, config, target, name=None):
        self.config = config
        self.target = target
        self.name = name or self._generate_name(target)
        self.created = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.results = {}
        self.findings = []

        self.path = config.sessions_dir / f"{self.name}.json"
        if self.path.exists():
            self._load()

    def _generate_name(self, target):
        ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        slug = target.replace(".", "-").replace("/", "-").replace(":", "-")[:30]
        return f"{slug}_{ts}"

    def _load(self):
        with open(self.path) as f:
            data = json.load(f)
        self.target = data.get("target", self.target)
        self.created = data.get("created", self.created)
        self.results = data.get("results", {})
        self.findings = data.get("findings", [])

    def save(self):
        data = {
            "name": self.name,
            "target": self.target,
            "created": self.created,
            "updated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "results": self.results,
            "findings": self.findings,
        }
        with open(self.path, "w") as f:
            json.dump(data, f, indent=2, default=str)

    def add_result(self, module_name, data):
        self.results[module_name] = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "data": data,
        }
        self.save()

    def add_finding(self, severity, title, detail="", module="", evidence=""):
        finding_id = hashlib.sha256(
            f"{severity}{title}{module}".encode()
        ).hexdigest()[:12]
        self.findings.append(
            {
                "id": finding_id,
                "severity": severity,
                "title": title,
                "detail": detail,
                "module": module,
                "evidence": evidence,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            }
        )
        self.save()

    def summary(self):
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            sev = f.get("severity", "info").lower()
            counts[sev] = counts.get(sev, 0) + 1
        return {
            "target": self.target,
            "modules_run": list(self.results.keys()),
            "total_findings": len(self.findings),
            "severity_counts": counts,
        }

    @classmethod
    def list_sessions(cls, config):
        sessions = []
        for p in sorted(config.sessions_dir.glob("*.json"), reverse=True):
            try:
                with open(p) as f:
                    data = json.load(f)
                sessions.append(
                    {
                        "name": data.get("name", p.stem),
                        "target": data.get("target", "?"),
                        "created": data.get("created", "?"),
                        "findings": len(data.get("findings", [])),
                    }
                )
            except (json.JSONDecodeError, KeyError):
                continue
        return sessions
