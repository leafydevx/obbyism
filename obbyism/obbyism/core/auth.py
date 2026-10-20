import json
import os
import socket
import datetime
from pathlib import Path


CONSENT_TEXT = """
{border}
  AUTHORIZATION REQUIRED
{border}

  Target:  {target}
  Scope:   {scope}
  Time:    {timestamp}

  You are about to perform security testing against the target above.
  Unauthorized access to computer systems is illegal under laws including
  the Computer Fraud and Abuse Act (CFAA), Computer Misuse Act, and
  similar legislation worldwide.

  By proceeding, you confirm that:

    1. You have WRITTEN AUTHORIZATION from the target owner
    2. Your testing is within the agreed scope
    3. You accept full responsibility for your actions

{border}
"""


class AuthorizationError(Exception):
    pass


class Authorization:
    def __init__(self, output, data_dir):
        self.output = output
        self.log_dir = data_dir / "auth_logs"
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def require_consent(self, target, scope="full assessment", no_auth=False):
        if no_auth and self._is_localhost(target):
            self.output.debug("Skipping auth for localhost target")
            self._log(target, scope, "auto-localhost")
            return True

        if no_auth and not self._is_localhost(target):
            raise AuthorizationError(
                "--no-auth is only allowed for localhost/127.0.0.1/::1 targets"
            )

        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        border = "  " + "═" * 60

        print(
            CONSENT_TEXT.format(
                target=target, scope=scope, timestamp=timestamp, border=border
            )
        )

        try:
            answer = input("  Type 'I AUTHORIZE' to proceed: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            raise AuthorizationError("Authorization cancelled")

        if answer != "I AUTHORIZE":
            raise AuthorizationError(
                f"Authorization denied (received: {answer!r})"
            )

        self._log(target, scope, "interactive-consent")
        self.output.success("Authorization confirmed")
        print()
        return True

    def load_auth_file(self, path, target):
        path = Path(path)
        if not path.exists():
            raise AuthorizationError(f"Auth file not found: {path}")

        with open(path) as f:
            doc = json.load(f)

        required = {"target", "authorized_by", "scope", "valid_until"}
        missing = required - set(doc.keys())
        if missing:
            raise AuthorizationError(f"Auth file missing fields: {missing}")

        expiry = datetime.datetime.fromisoformat(doc["valid_until"])
        if expiry < datetime.datetime.now(datetime.timezone.utc):
            raise AuthorizationError(
                f"Authorization expired on {doc['valid_until']}"
            )

        doc_target = doc["target"].lower().strip()
        if target.lower().strip() not in (doc_target, f"*.{doc_target}"):
            if not target.lower().strip().endswith(f".{doc_target}"):
                raise AuthorizationError(
                    f"Auth file target ({doc_target}) does not match {target}"
                )

        self._log(target, doc.get("scope", "unknown"), f"auth-file:{path}")
        self.output.success(
            f"Authorization loaded from {path} (by {doc['authorized_by']})"
        )
        return doc

    def _is_localhost(self, target):
        target = target.lower().strip()
        if target in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            return True
        try:
            resolved = socket.gethostbyname(target)
            return resolved in ("127.0.0.1", "::1")
        except socket.gaierror:
            return False

    def _log(self, target, scope, method):
        entry = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "target": target,
            "scope": scope,
            "method": method,
            "pid": os.getpid(),
        }
        log_file = self.log_dir / f"{datetime.date.today().isoformat()}.jsonl"
        with open(log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")
