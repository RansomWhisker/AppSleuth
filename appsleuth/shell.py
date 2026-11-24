"""`appsleuth shell`: an interactive prompt with tab completion (like objection's REPL), and `appsleuth completion`
which prints bash / zsh completion for the normal command line. Standard library only (readline).

Inside the shell every line is an AppSleuth command without the `appsleuth` prefix. `use app.ipa` sets the current
target so later commands need no file argument; TAB completes commands, flags, flag values, files, paths inside the
package (for `files`) and, for Android, installed package names.
"""
from __future__ import annotations

import argparse
import glob
import os
import shlex
import sys
import zipfile
from typing import Any, Dict, List, Optional

TARGET_CMDS = {"scan", "info", "sbom", "endpoints", "links", "cloud", "files"}
BUILTINS = ["use", "help", "exit", "quit", "clear", "pwd", "ls", "cd"]
APP_EXT = (".ipa", ".apk", ".apks", ".xapk", ".aab")
HISTORY = os.path.expanduser("~/.appsleuth_history")


def introspect(ap: argparse.ArgumentParser) -> Dict[str, Dict[str, Any]]:
    """{command: {"flags": {flag: choices|None}, "takes_value": set(flags)}} from the argparse tree."""
    out: Dict[str, Dict[str, Any]] = {}
    for action in ap._actions:
        if isinstance(action, argparse._SubParsersAction):
            for name, sp in action.choices.items():
                flags: Dict[str, Any] = {}
                takes = set()
                for a in sp._actions:
                    for o in a.option_strings:
                        flags[o] = list(a.choices) if a.choices else None
                        if a.nargs != 0 and not isinstance(a, (argparse._StoreTrueAction, argparse._StoreFalseAction,
                                                               argparse._HelpAction)):
                            takes.add(o)
                out[name] = {"flags": flags, "takes_value": takes, "help": sp.format_usage().strip()}
    return out


class Completer:
    def __init__(self, ap: argparse.ArgumentParser, state: Dict[str, Any]):
        self.tree = introspect(ap)
        self.state = state
        self._pkgs: Optional[List[str]] = None
        self._names: Dict[str, List[str]] = {}
        self.matches: List[str] = []

    # -- sources --------------------------------------------------------------
    def packages(self) -> List[str]:
        if self._pkgs is None:
            try:
                from . import devdata
                serials = devdata.android_devices()
                self._pkgs = devdata.android_list_packages(serials[0] if len(serials) == 1 else None) if serials else []
            except Exception:
                self._pkgs = []
        return self._pkgs

    def package_files(self, target: str) -> List[str]:
        """Archive entries of the current app (a cheap zip listing, no unpacking), plus bare file names."""
        if target not in self._names:
            names: List[str] = []
            try:
                with zipfile.ZipFile(target) as z:
                    names = [n for n in z.namelist() if not n.endswith("/")]
            except Exception:
                pass
            base = sorted({n.rsplit("/", 1)[-1] for n in names})
            self._names[target] = base + names
        return self._names[target]

    @staticmethod
    def paths(text: str) -> List[str]:
        out = []
        for p in sorted(glob.glob(os.path.expanduser(text) + "*")):
            out.append(p + "/" if os.path.isdir(p) else p)
        return out

    # -- readline hook --------------------------------------------------------
    def complete(self, text: str, state: int) -> Optional[str]:
        if state == 0:
            import readline
            line = readline.get_line_buffer()[:readline.get_begidx()]
            self.matches = self._candidates(line, text)
        return self.matches[state] if state < len(self.matches) else None

    def _candidates(self, before: str, text: str) -> List[str]:
        try:
            words = shlex.split(before)
        except ValueError:
            words = before.split()
        if not words:
            return [c + " " for c in sorted(set(self.tree) | set(BUILTINS)) if c.startswith(text)]
        cmd, args = words[0], words[1:]
        if cmd in ("help",):
            return [c + " " for c in sorted(self.tree) if c.startswith(text)]
        if cmd == "use":
            return [p for p in self.paths(text) if p.endswith("/") or p.lower().endswith(APP_EXT)]
        if cmd == "cd":
            return [p for p in self.paths(text) if p.endswith("/")]
        if cmd == "ls":
            return self.paths(text)
        info = self.tree.get(cmd)
        if not info:
            return []
        prev = args[-1] if args else ""
        if prev in info["flags"] and info["flags"][prev]:                    # flag with fixed choices
            return [c + " " for c in info["flags"][prev] if c.startswith(text)]
        if prev in ("-p", "--package") and cmd == "data":
            return [p + " " for p in self.packages() if p.startswith(text)]
        if prev in info["takes_value"]:
            return self.paths(text)
        flags = [f + " " for f in sorted(info["flags"]) if f.startswith(text) and f not in args]
        if text.startswith("-"):
            return flags
        target = self.state.get("target")
        if cmd == "files" and target:
            names = self.package_files(target)
            return [(shlex.quote(n) if " " in n else n) + " " for n in names if n.lower().startswith(text.lower())][:200] + flags
        if cmd == "runtime" and "--android" in args and not any(not x.startswith("-") for x in args):
            return [p + " " for p in self.packages() if p.startswith(text)]
        if cmd in TARGET_CMDS or cmd == "diff":
            apps = [p for p in self.paths(text) if p.endswith("/") or p.lower().endswith(APP_EXT)]
            return apps + ([] if apps and text else flags)
        return self.paths(text) + flags


def expand(argv: List[str], state: Dict[str, Any]) -> List[str]:
    """Insert the `use`d target after the command when the line does not name a file itself."""
    if not argv or argv[0] not in TARGET_CMDS or not state.get("target"):
        return argv
    first = next((a for a in argv[1:] if not a.startswith("-")), None)
    if argv[0] != "files" and first and (os.path.isfile(first) or first.lower().endswith(APP_EXT)):
        return argv
    if argv[0] == "files" and first and first.lower().endswith(APP_EXT):
        return argv
    return [argv[0], state["target"]] + argv[1:]


def run(build_parser, dispatch) -> None:
    """The REPL. `dispatch(argv)` runs one command (and may raise SystemExit)."""
    try:
        import readline
    except ImportError:                                  # Windows without pyreadline: still works, no completion
        readline = None
    ap = build_parser()
    state: Dict[str, Any] = {"target": None}
    if readline:
        comp = Completer(ap, state)
        readline.set_completer(comp.complete)
        readline.set_completer_delims(" \t\n")
        readline.parse_and_bind("bind ^I rl_complete" if "libedit" in (readline.__doc__ or "") else "tab: complete")
        try:
            readline.read_history_file(HISTORY)
        except OSError:
            pass
    print("AppSleuth shell. TAB completes commands, flags and files; `use app.ipa` sets the target; `help` lists "
          "commands; `exit` quits.")
    try:
        while True:
            t = os.path.basename(state["target"]) if state["target"] else ""
            try:
                line = input(f"appsleuth{' (' + t + ')' if t else ''}> ").strip()
            except EOFError:
                print()
                break
            except KeyboardInterrupt:
                print()
                continue
            if not line:
                continue
            try:
                argv = shlex.split(line)
            except ValueError as e:
                print(f"error: {e}")
                continue
            cmd = argv[0]
            if cmd in ("exit", "quit"):
                break
            if cmd == "clear":
                print("\033[2J\033[H", end="")
                continue
            if cmd == "pwd":
                print(os.getcwd())
                continue
            if cmd == "cd":
                try:
                    os.chdir(os.path.expanduser(argv[1] if len(argv) > 1 else "~"))
                except OSError as e:
                    print(f"error: {e}")
                continue
            if cmd == "ls":
                for p in sorted(glob.glob(os.path.join(os.path.expanduser(argv[1] if len(argv) > 1 else "."), "*"))):
                    print(p + ("/" if os.path.isdir(p) else ""))
                continue
            if cmd == "use":
                if len(argv) < 2:
                    print(f"target: {state['target'] or '(none)'}")
                elif not os.path.isfile(os.path.expanduser(argv[1])):
                    print(f"error: file not found: {argv[1]}")
                else:
                    state["target"] = os.path.abspath(os.path.expanduser(argv[1]))
                    print(f"target: {state['target']}")
                continue
            if cmd == "help":
                tree = introspect(ap)
                if len(argv) > 1 and argv[1] in tree:
                    print(tree[argv[1]]["help"])
                    print("flags: " + " ".join(sorted(tree[argv[1]]["flags"])))
                else:
                    print("commands: " + ", ".join(sorted(tree)))
                    print("shell:    " + ", ".join(BUILTINS))
                continue
            if cmd not in introspect(ap):
                print(f"unknown command '{cmd}' (TAB or `help` lists them)")
                continue
            try:
                argv = expand(argv, state)
                if argv[0] == "files" and "--no-prompt" not in argv:
                    argv.append("--no-prompt")          # the shell is the prompt
                dispatch(argv)
            except SystemExit:
                pass                                     # a command's own error/exit must not close the shell
            except KeyboardInterrupt:
                print("\ninterrupted")
            except Exception as e:
                print(f"error: {type(e).__name__}: {e}")
    finally:
        if readline:
            try:
                readline.set_history_length(1000)
                readline.write_history_file(HISTORY)
                os.chmod(HISTORY, 0o600)
            except OSError:
                pass


def completion_script(shell: str, ap: argparse.ArgumentParser) -> str:
    tree = introspect(ap)
    cmds = " ".join(sorted(set(tree) | {"shell", "completion", "version"}))
    cases = "\n".join(f'    {c}) opts="{" ".join(sorted(i["flags"]))}" ;;' for c, i in sorted(tree.items()))
    body = f'''_appsleuth() {{
  local cur prev cmd opts
  COMPREPLY=()
  cur="${{COMP_WORDS[COMP_CWORD]}}"
  prev="${{COMP_WORDS[COMP_CWORD-1]}}"
  cmd="${{COMP_WORDS[1]}}"
  if [ "$COMP_CWORD" -eq 1 ]; then
    COMPREPLY=( $(compgen -W "{cmds}" -- "$cur") )
    return
  fi
  case "$cmd" in
{cases}
    *) opts="" ;;
  esac
  case "$prev" in
    --show|--min-severity) COMPREPLY=( $(compgen -W "HIGH MEDIUM LOW INFO" -- "$cur") ); return ;;
    --method) COMPREPLY=( $(compgen -W "auto root run-as backup" -- "$cur") ); return ;;
  esac
  if [[ "$cur" == -* ]]; then
    COMPREPLY=( $(compgen -W "$opts" -- "$cur") )
  else
    COMPREPLY=( $(compgen -f -- "$cur") )
  fi
}}
complete -o filenames -F _appsleuth appsleuth
'''
    if shell == "zsh":
        return "autoload -U +X bashcompinit && bashcompinit\n" + body
    return body
