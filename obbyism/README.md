# Obbyism

Ethical hacking framework for authorized security assessments.

## Install

```bash
cd obbyism
chmod +x install.sh
./install.sh
```

## Usage

```bash
# List modules
obbyism modules

# Reconnaissance
obbyism recon example.com --all
obbyism recon example.com --dns --whois

# Port scanning
obbyism scan example.com --ports 1-1024
obbyism scan example.com --top-ports 20

# Vulnerability assessment
obbyism vuln example.com --ssl --headers
obbyism vuln example.com --dirs --wordlist custom.txt

# Full pipeline (recon → scan → vuln → report)
obbyism full example.com

# Reports
obbyism report --format html
obbyism report --format json -o results.json

# Session management
obbyism sessions
```

## Modules

| Module | Category | Description |
|--------|----------|-------------|
| whois | recon | WHOIS domain lookup |
| dns | recon | DNS record enumeration |
| headers | recon | HTTP header analysis |
| subdomains | recon | Subdomain discovery |
| port_scanner | scan | TCP port scanner |
| services | scan | Service/version detection |
| sweep | scan | Network host discovery |
| ssl_check | vuln | SSL/TLS analysis |
| security_headers | vuln | Security header audit |
| directories | vuln | Directory/path enumeration |
| report | report | HTML/JSON/TXT reports |

## Authorization

Obbyism requires explicit consent before any scan. You must type `I AUTHORIZE` to proceed, or provide an authorization JSON file:

```json
{
  "target": "example.com",
  "authorized_by": "Security Team Lead",
  "scope": "full assessment",
  "valid_until": "2026-12-31T23:59:59+00:00"
}
```

Use `--no-auth` only for localhost targets.

## Legal

This tool is for **authorized security testing only**. Unauthorized access to computer systems is illegal. You are solely responsible for your actions.
