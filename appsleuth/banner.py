"""Start-up banner: logo, version, links. Shown on a terminal only, on stderr, so piped output and
--json stay clean. Hide it with --no-banner or NO_BANNER=1."""
import os
import sys
import time

_FONT = {
    "A": [" ███ ", "█   █", "█████", "█   █", "█   █"], "P": ["████ ", "█   █", "████ ", "█    ", "█    "],
    "S": [" ████", "█    ", " ███ ", "    █", "████ "], "L": ["█    ", "█    ", "█    ", "█    ", "█████"],
    "E": ["█████", "█    ", "████ ", "█    ", "█████"], "U": ["█   █", "█   █", "█   █", "█   █", " ███ "],
    "T": ["█████", "  █  ", "  █  ", "  █  ", "  █  "], "H": ["█   █", "█   █", "█████", "█   █", "█   █"],
    "G": [" ████", "█    ", "█  ██", "█   █", " ███ "], "I": ["█████", "  █  ", "  █  ", "  █  ", "█████"],
    "K": ["█   █", "█  █ ", "███  ", "█  █ ", "█   █"],
}
_GRADIENT = (51, 45, 39, 33, 27)         # 256-colour cyan -> blue, top to bottom
_shown = False


def strip_flag(argv=None) -> bool:
    """Remove --no-banner from argv (in place) and say whether banners are suppressed."""
    argv = sys.argv if argv is None else argv
    off = bool(os.environ.get("NO_BANNER"))
    while "--no-banner" in argv:
        argv.remove("--no-banner")
        off = True
    return off


def _logo_rows(name: str):
    letters = [c for c in name.upper() if c in _FONT]
    return [" ".join(_FONT[c][r] for c in letters) for r in range(5)]


def show(*args, **kw) -> None:
    try:
        _show(*args, **kw)
    except Exception:          # a banner must never break a command (e.g. a console that cannot print block characters)
        pass


def _show(name: str, version: str, github: str, tagline: str, *, suppress: bool = False,
          website: str = "https://rudranetra.com/tools") -> None:
    global _shown
    out = sys.stderr
    try:
        tty = out.isatty()
    except Exception:
        tty = False
    if _shown or suppress or not tty:
        return
    _shown = True
    color = not os.environ.get("NO_COLOR")

    def c(text, code):
        return f"\033[{code}m{text}\033[0m" if color else text

    anim = color and not os.environ.get("NO_ANIM")
    out.write("\n")
    for i, row in enumerate(_logo_rows(name)):
        out.write("  " + c(row, f"1;38;5;{_GRADIENT[i]}") + "\n")
        if anim:
            out.flush()
            time.sleep(0.05)
    lines = [
        c(name, "1") + c(f"  v{version}", "1;36") + c("  ·  " + tagline, "2"),
        c("GitHub      ", "2") + c(github, "36"),
        c("Website     ", "2") + c(website, "36"),
        c("Authorised testing only: use it on apps and devices you own or have permission to test.", "2;33"),
    ]
    out.write("\n")
    for ln in lines:
        out.write("  " + ln + "\n")
        if anim:
            out.flush()
            time.sleep(0.04)
    out.write("\n")
    out.flush()
