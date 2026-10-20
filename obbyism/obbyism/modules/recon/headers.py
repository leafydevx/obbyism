import urllib.request
import urllib.error
import ssl

from obbyism.modules import ModuleRegistry
from obbyism.modules.base import BaseModule


@ModuleRegistry.register
class HeaderGrabber(BaseModule):
    name = "headers"
    description = "HTTP Header Analysis"
    category = "recon"

    def run(self, target, **kwargs):
        urls = []
        if target.startswith(("http://", "https://")):
            urls.append(target)
        else:
            urls.append(f"https://{target}")
            urls.append(f"http://{target}")

        all_results = {}
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        for url in urls:
            self.output.info(f"Fetching headers from {url}")
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "Obbyism/1.0 (Ethical Security Scanner)"},
                )
                resp = urllib.request.urlopen(req, timeout=10, context=ctx)
                headers = dict(resp.headers)
                status = resp.status

                result = {
                    "url": url,
                    "status": status,
                    "headers": headers,
                    "server": headers.get("Server", "unknown"),
                    "powered_by": headers.get("X-Powered-By", ""),
                    "content_type": headers.get("Content-Type", ""),
                }

                self.output.success(f"Status: {status}")
                self.output.success(f"Server: {result['server']}")
                if result["powered_by"]:
                    self.output.success(f"X-Powered-By: {result['powered_by']}")
                    self.session.add_finding(
                        "low",
                        "Technology disclosure via X-Powered-By header",
                        f"Value: {result['powered_by']}",
                        module=self.name,
                    )

                interesting = [
                    "Server",
                    "X-Powered-By",
                    "X-AspNet-Version",
                    "X-AspNetMvc-Version",
                    "X-Generator",
                    "Via",
                    "X-Cache",
                    "X-CDN",
                    "Set-Cookie",
                ]
                for h in interesting:
                    val = headers.get(h)
                    if val and h not in ("Server", "X-Powered-By"):
                        self.output.info(f"{h}: {val}")

                all_results[url] = result

            except urllib.error.HTTPError as e:
                self.output.warning(f"{url} returned HTTP {e.code}")
                all_results[url] = {"url": url, "status": e.code, "headers": dict(e.headers)}
            except (urllib.error.URLError, OSError) as e:
                self.output.debug(f"{url} failed: {e}")

        if not all_results:
            self.output.error("Could not connect to any URL")

        return all_results
