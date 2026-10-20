import sys
import shutil


class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"
    RESET = "\033[0m"


BANNER = r"""
  ___  ____  ____  _  _ ___ ____ _  _
 / _ \| __ )| __ )| \/ |_ _/ ___| \/ |
| | | |  _ \|  _ \| |\/| || |\___ | |\/| |
| |_| | |_) | |_) | |  | || |___) | |  | |
 \___/|____/|____/|_|  |_|___|____/|_|  |_|
"""


class Output:
    def __init__(self, verbose=False, quiet=False, no_color=False):
        self.verbose = verbose
        self.quiet = quiet
        self.no_color = no_color
        self.width = shutil.get_terminal_size().columns

    def _c(self, color, text):
        if self.no_color:
            return str(text)
        return f"{color}{text}{Colors.RESET}"

    def banner(self):
        from obbyism import __version__, __codename__

        print(self._c(Colors.CYAN + Colors.BOLD, BANNER))
        print(
            self._c(Colors.DIM, f"    v{__version__} ({__codename__})")
            + "  |  "
            + self._c(Colors.DIM, "Authorized Assessments Only")
        )
        print()

    def info(self, msg):
        if not self.quiet:
            print(f"  {self._c(Colors.BLUE, '[*]')} {msg}")

    def success(self, msg):
        if not self.quiet:
            print(f"  {self._c(Colors.GREEN, '[+]')} {msg}")

    def warning(self, msg):
        print(f"  {self._c(Colors.YELLOW, '[!]')} {msg}")

    def error(self, msg):
        print(f"  {self._c(Colors.RED, '[-]')} {msg}", file=sys.stderr)

    def critical(self, msg):
        print(f"  {self._c(Colors.RED + Colors.BOLD, '[!!]')} {msg}", file=sys.stderr)

    def debug(self, msg):
        if self.verbose:
            print(f"  {self._c(Colors.DIM, '[D]')} {msg}")

    def header(self, title):
        print()
        w = min(len(title) + 6, self.width - 4)
        line = "─" * w
        print(f"  {self._c(Colors.CYAN + Colors.BOLD, line)}")
        print(f"  {self._c(Colors.CYAN + Colors.BOLD, '  ' + title)}")
        print(f"  {self._c(Colors.CYAN + Colors.BOLD, line)}")
        print()

    def table(self, headers, rows):
        if not rows:
            return
        widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                if i < len(widths):
                    widths[i] = max(widths[i], len(str(cell)))

        hdr = "  "
        for i, h in enumerate(headers):
            hdr += self._c(Colors.BOLD + Colors.UNDERLINE, h.ljust(widths[i] + 3))
        print(hdr)

        for row in rows:
            line = "  "
            for i, cell in enumerate(row):
                line += str(cell).ljust(widths[i] + 3)
            print(line)
        print()

    def progress(self, current, total, prefix=""):
        if self.quiet:
            return
        bar_w = 30
        filled = int(bar_w * current / total) if total > 0 else 0
        bar = "█" * filled + "░" * (bar_w - filled)
        pct = f"{100 * current / total:.0f}%" if total > 0 else "0%"
        end = "\n" if current >= total else ""
        print(
            f"\r  {self._c(Colors.CYAN, prefix)} [{bar}] {pct} ({current}/{total})",
            end=end,
            flush=True,
        )

    def finding(self, severity, title, detail=""):
        colors = {
            "critical": Colors.RED + Colors.BOLD,
            "high": Colors.RED,
            "medium": Colors.YELLOW,
            "low": Colors.BLUE,
            "info": Colors.DIM,
        }
        color = colors.get(severity.lower(), Colors.WHITE)
        label = f"[{severity.upper()}]"
        print(f"  {self._c(color, label.ljust(12))} {title}")
        if detail:
            print(f"  {' ' * 12} {self._c(Colors.DIM, detail)}")

    def separator(self):
        print(f"  {self._c(Colors.DIM, '─' * (self.width - 4))}")
