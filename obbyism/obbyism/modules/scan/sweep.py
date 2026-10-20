import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

from obbyism.modules import ModuleRegistry
from obbyism.modules.base import BaseModule


def _ping_host(ip_str, port=80, timeout=1):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((ip_str, port))
        if result == 0:
            return ip_str, True
    except (socket.timeout, OSError):
        pass
    finally:
        sock.close()

    for probe_port in (443, 22, 8080):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((ip_str, probe_port))
            if result == 0:
                return ip_str, True
        except (socket.timeout, OSError):
            pass
        finally:
            sock.close()

    return ip_str, False


def _expand_target(target):
    target = target.split("//")[-1].split("/")[0].split(":")[0]
    try:
        network = ipaddress.ip_network(target, strict=False)
        if network.num_addresses > 65536:
            raise ValueError(f"Network too large: {network.num_addresses} hosts (max 65536)")
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        pass

    if "-" in target:
        base, end = target.rsplit("-", 1)
        parts = base.rsplit(".", 1)
        if len(parts) == 2:
            prefix, start = parts
            return [f"{prefix}.{i}" for i in range(int(start), int(end) + 1)]

    return [socket.gethostbyname(target)]


@ModuleRegistry.register
class NetworkSweep(BaseModule):
    name = "sweep"
    description = "Network Host Discovery"
    category = "scan"

    def run(self, target, **kwargs):
        threads = kwargs.get("threads", 100)
        timeout = kwargs.get("timeout", 1.0)

        try:
            hosts = _expand_target(target)
        except (ValueError, socket.gaierror) as e:
            self.output.error(f"Invalid target: {e}")
            return {"error": str(e)}

        self.output.info(f"Sweeping {len(hosts)} hosts")

        alive = []
        checked = 0
        total = len(hosts)

        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {
                pool.submit(_ping_host, ip, timeout=timeout): ip for ip in hosts
            }
            for future in as_completed(futures):
                checked += 1
                if checked % 20 == 0 or checked == total:
                    self.output.progress(checked, total, "Sweeping")

                ip, is_alive = future.result()
                if is_alive:
                    hostname = ""
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except (socket.herror, OSError):
                        pass
                    alive.append({"ip": ip, "hostname": hostname})
                    extra = f" ({hostname})" if hostname else ""
                    self.output.success(f"Host UP: {ip}{extra}")

        self.output.info(f"{len(alive)} hosts alive out of {total}")
        return {"target": target, "alive": alive, "total_scanned": total}
