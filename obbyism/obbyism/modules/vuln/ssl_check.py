import socket
import ssl
import datetime

from obbyism.modules import ModuleRegistry
from obbyism.modules.base import BaseModule

WEAK_CIPHERS = {"RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon"}


@ModuleRegistry.register
class SSLChecker(BaseModule):
    name = "ssl_check"
    description = "SSL/TLS Certificate & Configuration Checker"
    category = "vuln"

    def run(self, target, **kwargs):
        host = target.split("//")[-1].split("/")[0].split(":")[0]
        port = 443
        if ":" in target.split("//")[-1].split("/")[0]:
            port = int(target.split("//")[-1].split("/")[0].split(":")[1])

        results = {
            "host": host,
            "port": port,
            "certificate": {},
            "protocols": {},
            "issues": [],
        }

        self.output.info(f"Checking SSL/TLS on {host}:{port}")

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            sock = socket.create_connection((host, port), timeout=10)
            ssock = ctx.wrap_socket(sock, server_hostname=host)
        except (socket.timeout, OSError, ssl.SSLError) as e:
            self.output.error(f"SSL connection failed: {e}")
            return {"error": str(e)}

        cipher = ssock.cipher()
        if cipher:
            results["cipher"] = {
                "name": cipher[0],
                "version": cipher[1],
                "bits": cipher[2],
            }
            self.output.success(f"Cipher: {cipher[0]} ({cipher[2]} bits)")

            for weak in WEAK_CIPHERS:
                if weak.lower() in cipher[0].lower():
                    issue = f"Weak cipher in use: {cipher[0]}"
                    results["issues"].append(issue)
                    self.session.add_finding("high", issue, module=self.name)
                    break

        cert_bin = ssock.getpeercert(binary_form=True)
        cert = ssock.getpeercert()
        ssock.close()

        if cert:
            subject = dict(x[0] for x in cert.get("subject", ()))
            issuer = dict(x[0] for x in cert.get("issuer", ()))
            not_before = cert.get("notBefore", "")
            not_after = cert.get("notAfter", "")

            results["certificate"] = {
                "subject": subject,
                "issuer": issuer,
                "serial": cert.get("serialNumber", ""),
                "not_before": not_before,
                "not_after": not_after,
                "san": [e[1] for e in cert.get("subjectAltName", ())],
            }

            cn = subject.get("commonName", "N/A")
            issuer_cn = issuer.get("commonName", "N/A")
            self.output.success(f"Subject: {cn}")
            self.output.success(f"Issuer: {issuer_cn}")
            self.output.info(f"Valid: {not_before} - {not_after}")

            if not_after:
                try:
                    expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
                    days_left = (expiry - now).days
                    if days_left < 0:
                        issue = f"Certificate EXPIRED {abs(days_left)} days ago"
                        results["issues"].append(issue)
                        self.session.add_finding(
                            "critical", issue, f"Expired: {not_after}", module=self.name
                        )
                        self.output.finding("critical", issue)
                    elif days_left < 30:
                        issue = f"Certificate expires in {days_left} days"
                        results["issues"].append(issue)
                        self.session.add_finding(
                            "medium", issue, f"Expires: {not_after}", module=self.name
                        )
                        self.output.finding("medium", issue)
                    else:
                        self.output.success(f"Certificate valid for {days_left} days")
                except ValueError:
                    pass

            san = results["certificate"]["san"]
            if san:
                self.output.info(f"SANs: {', '.join(san[:10])}")
                if len(san) > 10:
                    self.output.info(f"  ... and {len(san) - 10} more")

        # Check for self-signed
        if cert:
            subj = dict(x[0] for x in cert.get("subject", ()))
            iss = dict(x[0] for x in cert.get("issuer", ()))
            if subj == iss:
                issue = "Self-signed certificate detected"
                results["issues"].append(issue)
                self.session.add_finding(
                    "medium", issue, "Subject matches issuer", module=self.name
                )
                self.output.finding("medium", issue)

        # Check hostname validation
        try:
            vctx = ssl.create_default_context()
            vsock = socket.create_connection((host, port), timeout=10)
            vctx.wrap_socket(vsock, server_hostname=host)
            vsock.close()
            self.output.success("Hostname verification: PASS")
        except ssl.SSLCertVerificationError as e:
            issue = f"Certificate validation failed: {e.verify_message}"
            results["issues"].append(issue)
            self.session.add_finding("high", issue, str(e), module=self.name)
            self.output.finding("high", issue)
        except (socket.timeout, OSError):
            pass

        if not results["issues"]:
            self.output.success("No SSL/TLS issues found")

        return results
