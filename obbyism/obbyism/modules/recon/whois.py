import socket

from obbyism.modules import ModuleRegistry
from obbyism.modules.base import BaseModule


IANA_SERVER = "whois.iana.org"
WHOIS_PORT = 43
TIMEOUT = 10


def _query(domain, server, port=WHOIS_PORT, timeout=TIMEOUT):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((server, port))
        sock.send(f"{domain}\r\n".encode())
        buf = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
        return buf.decode(errors="replace")
    finally:
        sock.close()


def _find_referral(response):
    for line in response.splitlines():
        low = line.lower().strip()
        if low.startswith("refer:") or low.startswith("whois:"):
            return line.split(":", 1)[1].strip()
    return None


def _parse_whois(raw):
    info = {}
    key_map = {
        "domain name": "domain",
        "registrar": "registrar",
        "registrar url": "registrar_url",
        "creation date": "created",
        "updated date": "updated",
        "registry expiry date": "expires",
        "registrar abuse contact email": "abuse_email",
        "name server": "nameservers",
    }
    nameservers = []
    for line in raw.splitlines():
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key = key.strip().lower()
        val = val.strip()
        if key in key_map:
            field = key_map[key]
            if field == "nameservers":
                nameservers.append(val.lower())
            else:
                info[field] = val
    if nameservers:
        info["nameservers"] = nameservers
    return info


@ModuleRegistry.register
class WhoisLookup(BaseModule):
    name = "whois"
    description = "WHOIS Domain Lookup"
    category = "recon"

    def run(self, target, **kwargs):
        domain = target.split("//")[-1].split("/")[0].split(":")[0]
        self.output.info(f"Querying WHOIS for {domain}")

        try:
            iana_resp = _query(domain, IANA_SERVER)
        except (socket.timeout, OSError) as e:
            self.output.error(f"WHOIS query failed: {e}")
            return {"error": str(e)}

        referral = _find_referral(iana_resp)
        raw = iana_resp

        if referral:
            self.output.debug(f"Referral server: {referral}")
            try:
                raw = _query(domain, referral)
            except (socket.timeout, OSError):
                self.output.warning(f"Referral query to {referral} failed, using IANA data")

        parsed = _parse_whois(raw)
        parsed["raw_length"] = len(raw)

        if parsed.get("domain"):
            self.output.success(f"Domain: {parsed['domain']}")
        if parsed.get("registrar"):
            self.output.success(f"Registrar: {parsed['registrar']}")
        if parsed.get("created"):
            self.output.success(f"Created: {parsed['created']}")
        if parsed.get("expires"):
            self.output.success(f"Expires: {parsed['expires']}")
        if parsed.get("nameservers"):
            for ns in parsed["nameservers"]:
                self.output.info(f"NS: {ns}")

        return parsed
