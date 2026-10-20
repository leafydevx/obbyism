import socket
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from obbyism.modules import ModuleRegistry
from obbyism.modules.base import BaseModule

PORTS_DB = Path(__file__).resolve().parent.parent.parent / "data" / "ports.json"


def _load_port_db():
    if PORTS_DB.exists():
        with open(PORTS_DB) as f:
            return json.load(f)
    return {}


def _parse_port_range(spec):
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def _scan_port(host, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
        if result == 0:
            banner = ""
            try:
                sock.send(b"\r\n")
                sock.settimeout(2)
                banner = sock.recv(1024).decode(errors="replace").strip()
            except (socket.timeout, OSError):
                pass
            return port, True, banner
        return port, False, ""
    except (socket.timeout, OSError):
        return port, False, ""
    finally:
        sock.close()


@ModuleRegistry.register
class PortScanner(BaseModule):
    name = "port_scanner"
    description = "TCP Port Scanner"
    category = "scan"

    def run(self, target, **kwargs):
        host = target.split("//")[-1].split("/")[0].split(":")[0]
        port_spec = kwargs.get("ports", "1-1024")
        top_ports = kwargs.get("top_ports")
        threads = kwargs.get("threads", 100)
        timeout = kwargs.get("timeout", 1.0)

        try:
            ip = socket.gethostbyname(host)
            self.output.info(f"Resolved {host} -> {ip}")
        except socket.gaierror:
            self.output.error(f"Cannot resolve {host}")
            return {"error": f"cannot resolve {host}"}

        port_db = _load_port_db()

        if top_ports:
            ranked = sorted(port_db.items(), key=lambda x: x[1].get("rank", 9999))
            ports = [int(p) for p, _ in ranked[:top_ports]]
        else:
            ports = _parse_port_range(port_spec)

        self.output.info(f"Scanning {len(ports)} ports on {ip} ({threads} threads, {timeout}s timeout)")

        open_ports = []
        scanned = 0
        total = len(ports)

        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {
                pool.submit(_scan_port, ip, port, timeout): port for port in ports
            }
            for future in as_completed(futures):
                scanned += 1
                if scanned % 50 == 0 or scanned == total:
                    self.output.progress(scanned, total, "Scanning")

                port, is_open, banner = future.result()
                if is_open:
                    service = port_db.get(str(port), {}).get("name", "unknown")
                    entry = {
                        "port": port,
                        "state": "open",
                        "service": service,
                        "banner": banner,
                    }
                    open_ports.append(entry)
                    extra = f" ({banner[:60]})" if banner else ""
                    self.output.success(f"Port {port}/{service} - OPEN{extra}")

        open_ports.sort(key=lambda x: x["port"])
        self.output.info(f"{len(open_ports)} open ports found")

        if open_ports:
            self.output.table(
                ["Port", "Service", "State", "Banner"],
                [
                    [
                        str(p["port"]),
                        p["service"],
                        p["state"],
                        (p["banner"][:40] + "..." if len(p["banner"]) > 40 else p["banner"]) or "-",
                    ]
                    for p in open_ports
                ],
            )

        return {
            "host": ip,
            "hostname": host,
            "ports_scanned": total,
            "open_ports": open_ports,
        }
