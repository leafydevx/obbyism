import socket
import ssl
import re

from obbyism.modules import ModuleRegistry
from obbyism.modules.base import BaseModule

PROBES = {
    "http": (b"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n", 80),
    "https": (None, 443),
    "smtp": (b"", 25),
    "ftp": (b"", 21),
    "ssh": (b"", 22),
    "pop3": (b"", 110),
    "imap": (b"", 143),
    "mysql": (b"", 3306),
    "redis": (b"PING\r\n", 6379),
}

VERSION_PATTERNS = [
    (r"SSH-([\d.]+)-(\S+)", "ssh"),
    (r"Server:\s*(.+)", "http_server"),
    (r"220.*?(\S+\s+\S+)", "banner_service"),
    (r"MySQL|MariaDB", "mysql"),
    (r"Redis", "redis"),
]


def _grab_banner(host, port, timeout=5, use_ssl=False, probe=b""):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)

        if probe:
            sock.send(probe.replace(b"{host}", host.encode()))

        banner = b""
        try:
            banner = sock.recv(4096)
        except (socket.timeout, OSError):
            pass

        cert = None
        if use_ssl and hasattr(sock, "getpeercert"):
            cert = sock.getpeercert()

        sock.close()
        return banner.decode(errors="replace").strip(), cert
    except (socket.timeout, OSError, ssl.SSLError):
        return "", None


@ModuleRegistry.register
class ServiceDetector(BaseModule):
    name = "services"
    description = "Service & Version Detection"
    category = "scan"

    def run(self, target, **kwargs):
        host = target.split("//")[-1].split("/")[0].split(":")[0]
        port_results = self.session.results.get("port_scanner", {}).get("data", {})
        open_ports = port_results.get("open_ports", [])

        if not open_ports:
            self.output.warning("No open ports in session. Run 'scan --ports' first or run a port scan.")
            return {"services": []}

        self.output.info(f"Probing {len(open_ports)} open ports for service versions")

        services = []
        for i, entry in enumerate(open_ports):
            port = entry["port"]
            self.output.progress(i + 1, len(open_ports), "Probing")

            use_ssl = port in (443, 8443, 993, 995, 465)
            probe = b""

            if port in (80, 8080, 8000, 8888):
                probe = PROBES["http"][0]
            elif port == 6379:
                probe = PROBES["redis"][0]

            banner, cert = _grab_banner(host, port, use_ssl=use_ssl, probe=probe)

            svc = {
                "port": port,
                "service": entry.get("service", "unknown"),
                "banner": banner[:200],
                "version": "",
                "ssl": use_ssl,
            }

            for pattern, label in VERSION_PATTERNS:
                m = re.search(pattern, banner, re.IGNORECASE)
                if m:
                    svc["version"] = m.group(1) if m.lastindex else m.group(0)
                    break

            if cert:
                svc["cert_subject"] = str(cert.get("subject", ""))
                svc["cert_issuer"] = str(cert.get("issuer", ""))

            services.append(svc)
            version_info = f" v{svc['version']}" if svc["version"] else ""
            ssl_flag = " [SSL]" if use_ssl else ""
            self.output.success(
                f"Port {port}: {svc['service']}{version_info}{ssl_flag}"
            )
            if banner and banner != svc.get("version", ""):
                self.output.debug(f"  Banner: {banner[:80]}")

        return {"host": host, "services": services}
