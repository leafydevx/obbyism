import urllib.request
import urllib.error
import ssl

from obbyism.modules import ModuleRegistry
from obbyism.modules.base import BaseModule

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "high",
        "detail": "HSTS not set. Vulnerable to protocol downgrade and cookie hijacking.",
    },
    "Content-Security-Policy": {
        "severity": "medium",
        "detail": "No CSP. Increased XSS risk.",
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "detail": "Missing. Browser may MIME-sniff responses.",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "detail": "Missing. Page may be framed (clickjacking risk).",
    },
    "X-XSS-Protection": {
        "severity": "low",
        "detail": "Missing legacy XSS filter header.",
    },
    "Referrer-Policy": {
        "severity": "low",
        "detail": "No referrer policy. May leak URLs to third parties.",
    },
    "Permissions-Policy": {
        "severity": "low",
        "detail": "No permissions policy. Browser features not restricted.",
    },
}

DANGEROUS_HEADERS = {
    "Server": ("info", "Server version disclosure"),
    "X-Powered-By": ("low", "Technology stack disclosure"),
    "X-AspNet-Version": ("low", "ASP.NET version disclosure"),
    "X-AspNetMvc-Version": ("low", "ASP.NET MVC version disclosure"),
}

COOKIE_FLAGS = ["Secure", "HttpOnly", "SameSite"]


@ModuleRegistry.register
class SecurityHeaderAnalyzer(BaseModule):
    name = "security_headers"
    description = "HTTP Security Header Analysis"
    category = "vuln"

    def run(self, target, **kwargs):
        url = target if target.startswith("http") else f"https://{target}"
        self.output.info(f"Analyzing security headers for {url}")

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "Obbyism/1.0 (Ethical Security Scanner)"}
            )
            resp = urllib.request.urlopen(req, timeout=10, context=ctx)
            headers = dict(resp.headers)
        except (urllib.error.URLError, OSError) as e:
            self.output.error(f"Connection failed: {e}")
            return {"error": str(e)}

        results = {"url": url, "present": {}, "missing": [], "issues": []}

        # Check required security headers
        for header, info in SECURITY_HEADERS.items():
            val = headers.get(header)
            if val:
                results["present"][header] = val
                self.output.success(f"{header}: {val[:80]}")
            else:
                results["missing"].append(header)
                title = f"Missing {header} header"
                self.session.add_finding(
                    info["severity"], title, info["detail"], module=self.name
                )
                self.output.finding(info["severity"], title, info["detail"])

        # Check information disclosure
        for header, (severity, detail) in DANGEROUS_HEADERS.items():
            val = headers.get(header)
            if val:
                issue = f"{detail}: {val}"
                results["issues"].append(issue)
                self.session.add_finding(severity, issue, f"{header}: {val}", module=self.name)
                self.output.finding(severity, issue)

        # Cookie analysis
        cookies = resp.headers.get_all("Set-Cookie") or []
        for cookie in cookies:
            name = cookie.split("=")[0].strip()
            missing_flags = [f for f in COOKIE_FLAGS if f.lower() not in cookie.lower()]
            if missing_flags:
                issue = f"Cookie '{name}' missing flags: {', '.join(missing_flags)}"
                results["issues"].append(issue)
                self.session.add_finding("medium", issue, cookie[:100], module=self.name)
                self.output.finding("medium", issue)

        # Score
        total = len(SECURITY_HEADERS)
        present = len(results["present"])
        score = f"{present}/{total}"
        grade = "A" if present == total else "B" if present >= total - 1 else "C" if present >= total - 3 else "D" if present >= total - 5 else "F"

        results["score"] = score
        results["grade"] = grade

        self.output.header(f"Security Headers Score: {score} (Grade: {grade})")

        return results
