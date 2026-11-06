"""Terminal colour, shared by every command. Off when stdout is not a terminal or NO_COLOR is set."""
import os
import sys


class Term:
    on = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    codes = {"HIGH": "1;31", "MEDIUM": "33", "LOW": "34", "INFO": "90", "bold": "1", "dim": "2", "ok": "32",
             "good": "1;32", "bad": "1;31", "warn": "33", "head": "1;36", "label": "2", "id": "1;37", "link": "36"}

    @classmethod
    def c(cls, text: str, kind: str) -> str:
        return f"\033[{cls.codes[kind]}m{text}\033[0m" if cls.on else text


def good(t): return Term.c(str(t), "good")
def bad(t): return Term.c(str(t), "bad")
def warn(t): return Term.c(str(t), "warn")
def dim(t): return Term.c(str(t), "dim")
def head(t): return Term.c(str(t), "head")
