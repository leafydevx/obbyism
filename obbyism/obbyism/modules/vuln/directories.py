import urllib.request
import urllib.error
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from obbyism.modules import ModuleRegistry
from obbyism.modules.base import BaseModule

BUILTIN_WORDLIST = Path(__file__).resolve().parent.parent.parent / "data" / "directories.txt"


def _check_path(base_url, path, timeout=5):
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "Obbyism/1.0 (Ethical Security Scanner)"}
        )
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        size = resp.headers.get("Content-Length", "?")
        return path, resp.status, size
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return path, e.code, "restricted"
        return path, e.code, None
    except (urllib.error.URLError, OSError):
        return path, None, None


@ModuleRegistry.register
class DirectoryEnum(BaseModule):
    name = "directories"
    description = "Directory & Path Enumeration"
    category = "vuln"

    def run(self, target, **kwargs):
        base_url = target if target.startswith("http") else f"https://{target}"
        wordlist = kwargs.get("wordlist") or BUILTIN_WORDLIST
        threads = kwargs.get("threads", 20)

        wl_path = Path(wordlist)
        if not wl_path.exists():
            self.output.error(f"Wordlist not found: {wl_path}")
            return {"error": f"wordlist not found: {wl_path}"}

        with open(wl_path) as f:
            paths = [l.strip() for l in f if l.strip() and not l.startswith("#")]

        self.output.info(f"Testing {len(paths)} paths against {base_url}")

        found = []
        restricted = []
        checked = 0
        total = len(paths)

        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {
                pool.submit(_check_path, base_url, path): path for path in paths
            }
            for future in as_completed(futures):
                checked += 1
                if checked % 20 == 0 or checked == total:
                    self.output.progress(checked, total, "Enumerating")

                path, status, size = future.result()
                if status is None:
                    continue

                if status == 200:
                    found.append({"path": path, "status": status, "size": size})
                    self.output.success(f"/{path} -> {status} (size: {size})")
                elif status in (301, 302):
                    found.append({"path": path, "status": status, "size": size})
                    self.output.info(f"/{path} -> {status} (redirect)")
                elif status in (401, 403):
                    restricted.append({"path": path, "status": status})
                    self.output.warning(f"/{path} -> {status} (restricted)")

        if found:
            self.output.info(f"{len(found)} accessible paths found")
            sensitive = [
                p for p in found
                if any(
                    s in p["path"].lower()
                    for s in (".env", "config", "admin", "backup", ".git", "debug", "phpinfo")
                )
            ]
            for s in sensitive:
                self.session.add_finding(
                    "high",
                    f"Sensitive path accessible: /{s['path']}",
                    f"HTTP {s['status']}",
                    module=self.name,
                )
                self.output.finding("high", f"Sensitive path: /{s['path']}")

        return {
            "base_url": base_url,
            "found": found,
            "restricted": restricted,
            "total_checked": total,
        }
