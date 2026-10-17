#!/usr/bin/env python3
"""PreToolUse hook for Bash: refuse commits that skip the git hooks, and force-pushes.

Glob permission rules cannot parse git options (`git commit -n`, `--no-veri`, `-anm x`, `git -C . push -f`,
`git push origin +main` all slip past patterns such as `git commit * --no-verify*`), so this hook splits the
command line with shlex and looks at the options of every git invocation, including ones nested in
`sh -c '...'`. Exit 2 blocks the call and hands the reason back to Claude; anything else is silent.
Standard library only, like the rest of the project.
"""

import json
import os
import shlex
import sys

SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}
SEPARATORS = {";", "&&", "||", "|", "&", "|&", "(", ")", "{", "}", "\n"}
# git's own options before the subcommand that take a separate value
GIT_VALUE_OPTIONS = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--config-env",
                     "--super-prefix", "--list-cmds", "--attr-source"}
# options of `git commit` / `git push` that take a separate value, so the token after them is data
COMMIT_VALUE_OPTIONS = {"-m", "--message", "-F", "--file", "-C", "--reuse-message", "-c", "--reedit-message",
                        "--author", "--date", "-t", "--template", "--cleanup", "--fixup", "--squash",
                        "--trailer", "--pathspec-from-file", "-S", "--gpg-sign"}
COMMIT_SHORT_WITH_VALUE = set("mFCct")  # in a group such as -am, the rest of the group is that option's value
PUSH_VALUE_OPTIONS = {"-o", "--push-option", "--repo", "--receive-pack", "--exec"}
PUSH_SHORT_WITH_VALUE = set("o")
FORCE_OPTIONS = ("--force", "--force-with-lease", "--force-if-includes", "--mirror")  # --mirror force-updates


def _words(command):
    lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|()")
    lexer.whitespace_split = True
    lexer.commenters = ""
    return list(lexer)


def _simple_commands(words):
    current = []
    for word in words:
        if word in SEPARATORS:
            if current:
                yield current
            current = []
        else:
            current.append(word)
    if current:
        yield current


def _short_group_has(token, letter, takes_value):
    """True if the short-option group ``token`` (such as ``-anm``) sets ``letter`` as a flag."""
    if not token.startswith("-") or token.startswith("--") or len(token) < 2:
        return False
    for char in token[1:]:
        if char == letter:
            return True
        if char in takes_value:
            return False  # the rest of the group is that option's value
    return False


def _hooks_path_override(value):
    return value.split("=", 1)[0].strip().lower() == "core.hookspath"


def _check_git(args):
    """``args`` follows the word ``git``; returns a reason to block, or None."""
    index = 0
    while index < len(args) and args[index].startswith("-"):
        option = args[index]
        name = option.split("=", 1)[0]
        if option.startswith("-c") and not option.startswith("--"):  # -c key=value or -ckey=value
            value = option[2:] if len(option) > 2 else (args[index + 1] if index + 1 < len(args) else "")
            if _hooks_path_override(value):
                return "overriding core.hooksPath skips the project's git hooks"
        if name in GIT_VALUE_OPTIONS and "=" not in option and len(option) == len(name):
            index += 1
        index += 1
    if index >= len(args):
        return None
    subcommand, rest = args[index], args[index + 1:]
    if subcommand == "commit":
        return _check_options(rest, COMMIT_VALUE_OPTIONS, COMMIT_SHORT_WITH_VALUE, _commit_reason)
    if subcommand == "push":
        return _check_options(rest, PUSH_VALUE_OPTIONS, PUSH_SHORT_WITH_VALUE, _push_reason)
    return None


def _check_options(args, value_options, short_with_value, judge):
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            for operand in args[index + 1:]:
                reason = judge(operand, short_with_value, operand_only=True)
                if reason:
                    return reason
            return None
        reason = judge(token, short_with_value, operand_only=False)
        if reason:
            return reason
        if token in value_options:
            index += 1  # skip the option's value: a commit message may well contain "-n" or "--force"
        index += 1
    return None


def _commit_reason(token, short_with_value, operand_only):
    if operand_only:
        return None
    if len(token) >= len("--no-v") and "--no-verify".startswith(token):
        return "git commit --no-verify skips the pre-commit hook"
    if _short_group_has(token, "n", short_with_value):
        return "git commit -n is --no-verify and skips the pre-commit hook"
    return None


def _push_reason(token, short_with_value, operand_only):
    if token.startswith("+") and len(token) > 1:
        return "a '+refspec' force-pushes"
    if operand_only:
        return None
    name = token.split("=", 1)[0]
    # git accepts any unambiguous abbreviation of a long option, so match prefixes, not exact names
    if len(name) >= len("--for") and any(full.startswith(name) for full in FORCE_OPTIONS):
        return "git push %s force-pushes" % name
    if _short_group_has(token, "f", short_with_value):
        return "git push -f force-pushes"
    return None


def reason_to_block(command, depth=0):
    try:
        words = _words(command)
    except ValueError:
        return None  # unbalanced quotes: the shell will refuse it anyway
    for simple in _simple_commands(words):
        # skip leading VAR=value assignments and common wrappers
        while simple and ("=" in simple[0] and not simple[0].startswith("-") or simple[0] in ("env", "command",
                                                                                               "exec", "nohup",
                                                                                               "time", "sudo")):
            simple = simple[1:]
        if not simple:
            continue
        program = os.path.basename(simple[0])
        if program == "git":
            reason = _check_git(simple[1:])
            if reason:
                return reason
        elif program in SHELLS and depth < 3:
            for index, word in enumerate(simple[1:-1], 1):
                if word == "-c" or (word.startswith("-") and not word.startswith("--") and "c" in word):
                    reason = reason_to_block(simple[index + 1], depth + 1)
                    if reason:
                        return reason
                    break
        elif program == "eval" and depth < 3:
            reason = reason_to_block(" ".join(simple[1:]), depth + 1)
            if reason:
                return reason
    return None


def main():
    try:
        event = json.load(sys.stdin)
    except ValueError:
        return 0
    if not isinstance(event, dict):
        return 0
    command = (event.get("tool_input") or {}).get("command")
    if not isinstance(command, str):
        return 0
    reason = reason_to_block(command)
    if reason:
        sys.stderr.write("Blocked by .claude/hooks/guard_git.py: %s. CLAUDE.md: never --no-verify, never "
                         "force-push. Fix the failing hook or ask the owner instead.\n" % reason)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
