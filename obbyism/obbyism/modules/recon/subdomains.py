import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from obbyism.modules import ModuleRegistry
from obbyism.modules.base import BaseModule

BUILTIN_WORDLIST = Path(__file__).resolve().parent.parent.parent / "data" / "subdomains.txt"


def _check_subdomain(subdomain, timeout=3):
    try:
        ip = socket.gethostbyname(subdomain)
        return subdomain, ip
    except (socket.gaierror, OSError):
        return subdomain, None


@ModuleRegistry.register
class SubdomainEnum(BaseModule):
    name = "subdomains"
    description = "Subdomain Enumeration"
    category = "recon"

    def run(self, target, **kwargs):
        domain = target.split("//")[-1].split("/")[0].split(":")[0]
        wordlist = kwargs.get("wordlist") or BUILTIN_WORDLIST
        threads = kwargs.get("threads", 50)

        wl_path = Path(wordlist)
        if not wl_path.exists():
            self.output.error(f"Wordlist not found: {wl_path}")
            return {"error": f"wordlist not found: {wl_path}"}

        with open(wl_path) as f:
            prefixes = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        self.output.info(f"Testing {len(prefixes)} subdomains against {domain}")

        found = {}
        checked = 0
        total = len(prefixes)

        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {
                pool.submit(_check_subdomain, f"{prefix}.{domain}"): prefix
                for prefix in prefixes
            }
            for future in as_completed(futures):
                checked += 1
                if checked % 25 == 0 or checked == total:
                    self.output.progress(checked, total, "Subdomains")

                sub, ip = future.result()
                if ip:
                    found[sub] = ip
                    self.output.success(f"{sub} -> {ip}")

        self.output.info(f"Found {len(found)} subdomains")
        return {"domain": domain, "found": found, "total_checked": total}
