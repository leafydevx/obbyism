import socket
import subprocess
import shutil

from obbyism.modules import ModuleRegistry
from obbyism.modules.base import BaseModule


def _resolve_basic(domain):
    records = {"A": [], "AAAA": []}
    for family, stype in [(socket.AF_INET, "A"), (socket.AF_INET6, "AAAA")]:
        try:
            results = socket.getaddrinfo(domain, None, family, socket.SOCK_STREAM)
            records[stype] = list({r[4][0] for r in results})
        except (socket.gaierror, OSError):
            pass
    return records


def _dig_query(domain, rtype):
    dig = shutil.which("dig")
    if not dig:
        return []
    try:
        result = subprocess.run(
            [dig, "+short", domain, rtype],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return [l.strip() for l in result.stdout.strip().splitlines() if l.strip()]
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


def _try_dnspython(domain):
    try:
        import dns.resolver

        records = {}
        for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
            try:
                answers = dns.resolver.resolve(domain, rtype)
                records[rtype] = [str(r) for r in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                pass
            except Exception:
                pass
        return records
    except ImportError:
        return None


@ModuleRegistry.register
class DnsEnum(BaseModule):
    name = "dns"
    description = "DNS Enumeration"
    category = "recon"

    def run(self, target, **kwargs):
        domain = target.split("//")[-1].split("/")[0].split(":")[0]
        self.output.info(f"Enumerating DNS records for {domain}")

        dnspy = _try_dnspython(domain)
        if dnspy is not None:
            self.output.debug("Using dnspython for full enumeration")
            records = dnspy
        else:
            self.output.debug("dnspython not found, using socket + dig fallback")
            records = _resolve_basic(domain)
            for rtype in ("MX", "NS", "TXT", "CNAME", "SOA"):
                vals = _dig_query(domain, rtype)
                if vals:
                    records[rtype] = vals

        # Reverse DNS for A records
        reverse = {}
        for ip in records.get("A", []):
            try:
                hostname, _, _ = socket.gethostbyaddr(ip)
                reverse[ip] = hostname
            except (socket.herror, OSError):
                pass

        if reverse:
            records["PTR"] = reverse

        for rtype, vals in sorted(records.items()):
            if isinstance(vals, dict):
                for k, v in vals.items():
                    self.output.success(f"{rtype}: {k} -> {v}")
            elif isinstance(vals, list):
                for v in vals:
                    self.output.success(f"{rtype}: {v}")
            else:
                self.output.success(f"{rtype}: {vals}")

        if not any(records.values()):
            self.output.warning("No DNS records found")

        return records
