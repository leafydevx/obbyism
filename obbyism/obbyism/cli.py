import argparse
import sys

from obbyism import __version__
from obbyism.core.output import Output
from obbyism.core.config import Config
from obbyism.core.auth import Authorization, AuthorizationError
from obbyism.core.session import Session
from obbyism.modules import ModuleRegistry, load_all


def _run_modules(category, session, output, target, args, only=None):
    load_all()
    modules = ModuleRegistry.by_category(category)
    for name, cls in modules.items():
        if only and name not in only:
            continue
        mod = cls(session, output)
        kwargs = {
            "threads": getattr(args, "threads", 50),
            "timeout": getattr(args, "timeout", 1.0),
            "ports": getattr(args, "ports", "1-1024"),
            "top_ports": getattr(args, "top_ports", None),
            "wordlist": getattr(args, "wordlist", None),
        }
        mod.execute(target, **kwargs)


def cmd_recon(args, output, config):
    session = Session(config, args.target, name=args.session)
    auth = Authorization(output, config.data_dir)
    try:
        auth.require_consent(args.target, scope="reconnaissance", no_auth=args.no_auth)
    except AuthorizationError as e:
        output.critical(str(e))
        return 1

    selected = set()
    if args.all or not any([args.whois, args.dns, args.headers, args.subdomains]):
        selected = {"whois", "dns", "headers", "subdomains"}
    else:
        if args.whois:
            selected.add("whois")
        if args.dns:
            selected.add("dns")
        if args.headers:
            selected.add("headers")
        if args.subdomains:
            selected.add("subdomains")

    _run_modules("recon", session, output, args.target, args, only=selected)

    output.header("Recon Summary")
    s = session.summary()
    output.info(f"Modules run: {', '.join(s['modules_run'])}")
    output.info(f"Findings: {s['total_findings']}")
    return 0


def cmd_scan(args, output, config):
    session = Session(config, args.target, name=args.session)
    auth = Authorization(output, config.data_dir)
    try:
        auth.require_consent(args.target, scope="port scanning", no_auth=args.no_auth)
    except AuthorizationError as e:
        output.critical(str(e))
        return 1

    selected = set()
    if args.all or not any([args.ports_flag, args.services, args.sweep]):
        selected = {"port_scanner"}
    else:
        if args.ports_flag:
            selected.add("port_scanner")
        if args.services:
            selected.add("services")
        if args.sweep:
            selected.add("sweep")

    _run_modules("scan", session, output, args.target, args, only=selected)

    output.header("Scan Summary")
    s = session.summary()
    output.info(f"Modules run: {', '.join(s['modules_run'])}")
    port_data = session.results.get("port_scanner", {}).get("data", {})
    if port_data:
        output.info(f"Open ports: {len(port_data.get('open_ports', []))}")
    return 0


def cmd_vuln(args, output, config):
    session = Session(config, args.target, name=args.session)
    auth = Authorization(output, config.data_dir)
    try:
        auth.require_consent(args.target, scope="vulnerability assessment", no_auth=args.no_auth)
    except AuthorizationError as e:
        output.critical(str(e))
        return 1

    selected = set()
    if args.all or not any([args.ssl, args.headers, args.dirs]):
        selected = {"ssl_check", "security_headers", "directories"}
    else:
        if args.ssl:
            selected.add("ssl_check")
        if args.headers:
            selected.add("security_headers")
        if args.dirs:
            selected.add("directories")

    _run_modules("vuln", session, output, args.target, args, only=selected)

    output.header("Vulnerability Summary")
    s = session.summary()
    counts = s["severity_counts"]
    output.info(f"Findings: {s['total_findings']}")
    for sev in ("critical", "high", "medium", "low"):
        if counts.get(sev, 0) > 0:
            output.finding(sev, f"{counts[sev]} {sev} finding(s)")
    return 0


def cmd_full(args, output, config):
    session = Session(config, args.target, name=args.session)
    auth = Authorization(output, config.data_dir)
    try:
        auth.require_consent(args.target, scope="full assessment", no_auth=args.no_auth)
    except AuthorizationError as e:
        output.critical(str(e))
        return 1

    load_all()

    output.header("Phase 1: Reconnaissance")
    for name in ("whois", "dns", "headers", "subdomains"):
        mod = ModuleRegistry.get(name)
        if mod:
            mod(session, output).execute(args.target, threads=args.threads, timeout=args.timeout)

    output.header("Phase 2: Scanning")
    for name in ("port_scanner",):
        mod = ModuleRegistry.get(name)
        if mod:
            mod(session, output).execute(
                args.target, threads=args.threads, timeout=args.timeout, ports="1-1024"
            )

    port_data = session.results.get("port_scanner", {}).get("data", {})
    if port_data.get("open_ports"):
        mod = ModuleRegistry.get("services")
        if mod:
            mod(session, output).execute(args.target)

    output.header("Phase 3: Vulnerability Assessment")
    for name in ("ssl_check", "security_headers", "directories"):
        mod = ModuleRegistry.get(name)
        if mod:
            mod(session, output).execute(
                args.target, threads=args.threads, timeout=args.timeout
            )

    output.header("Phase 4: Report Generation")
    fmt = "html"
    out_path = None
    if args.output:
        out_path = args.output
    mod = ModuleRegistry.get("report")
    if mod:
        mod(session, output).execute(args.target, format=fmt, output=out_path)

    output.header("Assessment Complete")
    s = session.summary()
    counts = s["severity_counts"]
    output.info(f"Session: {session.name}")
    output.info(f"Modules run: {', '.join(s['modules_run'])}")
    output.info(f"Total findings: {s['total_findings']}")
    for sev in ("critical", "high", "medium", "low"):
        if counts.get(sev, 0) > 0:
            output.finding(sev, f"{counts[sev]} {sev}")
    return 0


def cmd_report(args, output, config):
    load_all()
    sessions = Session.list_sessions(config)
    if not sessions:
        output.error("No sessions found. Run a scan first.")
        return 1

    session_name = args.session_name
    if not session_name:
        session_name = sessions[0]["name"]
        output.info(f"Using latest session: {session_name}")

    session = Session(config, "", name=session_name)
    mod = ModuleRegistry.get("report")
    if mod:
        mod(session, output).execute(
            session.target, format=args.format, output=args.output
        )
    return 0


def cmd_sessions(args, output, config):
    sessions = Session.list_sessions(config)
    if not sessions:
        output.info("No sessions found")
        return 0

    output.table(
        ["Session", "Target", "Created", "Findings"],
        [
            [s["name"], s["target"], s["created"][:19], str(s["findings"])]
            for s in sessions
        ],
    )
    return 0


def cmd_modules(args, output, config):
    load_all()
    mods = ModuleRegistry.all()
    rows = []
    for name, cls in sorted(mods.items()):
        rows.append([name, cls.category, cls.description])
    output.table(["Module", "Category", "Description"], rows)
    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="obbyism",
        description="Obbyism — Ethical Hacking Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Run 'obbyism <command> -h' for command-specific help.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    parser.add_argument("--no-color", action="store_true", help="Disable colors")
    parser.add_argument("--session", help="Session name to use/resume")
    parser.add_argument(
        "--no-auth",
        action="store_true",
        help="Skip authorization prompt (localhost only)",
    )

    sub = parser.add_subparsers(dest="command")

    # recon
    p = sub.add_parser("recon", help="Reconnaissance modules")
    p.add_argument("target", help="Target domain/IP")
    p.add_argument("--whois", action="store_true", help="WHOIS lookup")
    p.add_argument("--dns", action="store_true", help="DNS enumeration")
    p.add_argument("--headers", action="store_true", help="HTTP headers")
    p.add_argument("--subdomains", action="store_true", help="Subdomain enumeration")
    p.add_argument("--all", action="store_true", help="Run all recon modules")

    # scan
    p = sub.add_parser("scan", help="Scanning modules")
    p.add_argument("target", help="Target host/IP/range")
    p.add_argument("--ports", default="1-1024", help="Port range (default: 1-1024)")
    p.add_argument("--top-ports", type=int, help="Scan top N common ports")
    p.add_argument("--ports-flag", action="store_true", dest="ports_flag", help="Run port scanner")
    p.add_argument("--services", action="store_true", help="Service/version detection")
    p.add_argument("--sweep", action="store_true", help="Host discovery sweep")
    p.add_argument("--threads", type=int, default=100, help="Thread count")
    p.add_argument("--timeout", type=float, default=1.0, help="Timeout in seconds")
    p.add_argument("--all", action="store_true", help="Run all scan modules")

    # vuln
    p = sub.add_parser("vuln", help="Vulnerability assessment")
    p.add_argument("target", help="Target host/URL")
    p.add_argument("--ssl", action="store_true", help="SSL/TLS check")
    p.add_argument("--headers", action="store_true", help="Security headers")
    p.add_argument("--dirs", action="store_true", help="Directory enumeration")
    p.add_argument("--wordlist", help="Custom wordlist path")
    p.add_argument("--threads", type=int, default=20, help="Thread count")
    p.add_argument("--all", action="store_true", help="Run all vuln modules")

    # full
    p = sub.add_parser("full", help="Full assessment pipeline")
    p.add_argument("target", help="Target host/domain")
    p.add_argument("-o", "--output", help="Output file path")
    p.add_argument("--threads", type=int, default=50, help="Thread count")
    p.add_argument("--timeout", type=float, default=1.0, help="Timeout in seconds")

    # report
    p = sub.add_parser("report", help="Generate report from session")
    p.add_argument("session_name", nargs="?", help="Session name (default: latest)")
    p.add_argument("-f", "--format", choices=["json", "html", "txt"], default="html")
    p.add_argument("-o", "--output", help="Output file path")

    # sessions
    sub.add_parser("sessions", help="List saved sessions")

    # modules
    sub.add_parser("modules", help="List available modules")

    args = parser.parse_args()
    output = Output(verbose=args.verbose, quiet=args.quiet, no_color=args.no_color)

    if not args.command:
        output.banner()
        parser.print_help()
        return 0

    output.banner()

    commands = {
        "recon": cmd_recon,
        "scan": cmd_scan,
        "vuln": cmd_vuln,
        "full": cmd_full,
        "report": cmd_report,
        "sessions": cmd_sessions,
        "modules": cmd_modules,
    }

    handler = commands.get(args.command)
    if not handler:
        parser.print_help()
        return 1

    config = Config()
    try:
        return handler(args, output, config)
    except KeyboardInterrupt:
        print()
        output.warning("Interrupted by user")
        return 130


if __name__ == "__main__":
    sys.exit(main())
