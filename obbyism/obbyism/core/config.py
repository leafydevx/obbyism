import json
from pathlib import Path

DEFAULT_CONFIG = {
    "threads": 100,
    "timeout": 2.0,
    "default_ports": "1-1024",
    "output_format": "html",
    "data_dir": "~/.obbyism",
    "user_agent": "Obbyism/1.0 (Ethical Security Scanner)",
}


class Config:
    def __init__(self, config_path=None):
        self.data_dir = Path(DEFAULT_CONFIG["data_dir"]).expanduser()
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.config_path = config_path or self.data_dir / "config.json"
        self._data = dict(DEFAULT_CONFIG)

        if Path(self.config_path).exists():
            with open(self.config_path) as f:
                self._data.update(json.load(f))

    def get(self, key, default=None):
        return self._data.get(key, default)

    def set(self, key, value):
        self._data[key] = value
        self.save()

    def save(self):
        with open(self.config_path, "w") as f:
            json.dump(self._data, f, indent=2)

    @property
    def sessions_dir(self):
        d = self.data_dir / "sessions"
        d.mkdir(exist_ok=True)
        return d

    @property
    def reports_dir(self):
        d = self.data_dir / "reports"
        d.mkdir(exist_ok=True)
        return d
