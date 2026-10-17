"""Tests for the Claude Code hooks in this directory (run by `make check`).

    python3 -m unittest discover -s .claude/hooks -t .claude/hooks
"""

import json
import os
import subprocess
import sys
import unittest

import guard_git

HERE = os.path.dirname(os.path.abspath(__file__))


class GuardGitTests(unittest.TestCase):

    BLOCKED = [
        "git commit --no-verify -m x",
        "git commit -m x --no-verify",
        "git commit --no-veri -m x",
        "git commit --no-v -m x",
        "git commit -n -m x",
        "git commit -m x -n",
        "git commit -nm x",
        "git commit -anm x",
        "git commit -an",
        "git -c core.hooksPath=/dev/null commit -m x",
        "git -c core.hookspath=/dev/null commit -m x",
        "git -ccore.hooksPath=/dev/null commit -m x",
        "git -C . commit -n -m x",
        "/usr/bin/git commit -n -m x",
        "cd repo && git commit --no-verify -m x",
        "make check; git commit -n -m x",
        "GIT_AUTHOR_NAME=x git commit -n -m x",
        "env FOO=1 git commit -n -m x",
        "sh -c 'git commit -n -m x'",
        "bash -lc \"git push --force\"",
        "eval git push -f",
        "git push --force",
        "git push --force origin main",
        "git push origin main --force",
        "git push --force-with-lease origin main",
        "git push --force-with-lease=main:abc origin main",
        "git push --force-w origin main",
        "git push --force-if-includes --force-with-lease",
        "git push --mirror",
        "git push -f",
        "git push -uf origin main",
        "git push origin +main",
        "git push origin +HEAD:main",
        "git -C . push --force",
        "git push origin -- +main",
    ]

    ALLOWED = [
        "git commit -m 'Handle the -n flag in tests'",
        "git commit -m \"Deny git commit --no-verify in settings\"",
        "git commit -m x",
        "git commit -am x",
        "git commit -m -n",
        "git commit -F msg.txt",
        "git commit --amend --no-edit",
        "git commit -S -m x",
        "git commit --verbose -m x",
        "git commit -mn",
        "git push",
        "git push origin main",
        "git push -u origin main",
        "git push --tags origin",
        "git push origin v1.1.0",
        "git push -o ci.skip origin main",
        "git push --dry-run origin main",
        "git -c user.name=x commit -m x",
        "git log --oneline -n 5",
        "git status",
        "echo git push --force",
        "grep -n -- '--force' README.md",
        "python3 -m unittest discover -s tests -t .",
        "git show HEAD:proxy.py | grep -n force",
        "git commit -m 'unbalanced",
    ]

    def test_hook_skipping_and_force_pushing_commands_are_blocked(self):
        for command in self.BLOCKED:
            with self.subTest(command=command):
                self.assertIsNotNone(guard_git.reason_to_block(command))

    def test_ordinary_git_and_other_commands_pass(self):
        for command in self.ALLOWED:
            with self.subTest(command=command):
                self.assertIsNone(guard_git.reason_to_block(command))

    def run_hook(self, payload):
        return subprocess.run([sys.executable, os.path.join(HERE, "guard_git.py")], input=payload,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                              timeout=30)

    def test_the_hook_exits_2_with_a_reason_for_a_blocked_command(self):
        result = self.run_hook(json.dumps({"tool_input": {"command": "git push -f"}}))
        self.assertEqual(result.returncode, 2)
        self.assertIn("force-push", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_the_hook_is_silent_for_allowed_and_malformed_input(self):
        for payload in (json.dumps({"tool_input": {"command": "git status"}}), "not json", "[1, 2]",
                        json.dumps({"tool_input": None}), json.dumps({"tool_input": {"command": 5}}), ""):
            with self.subTest(payload=payload):
                result = self.run_hook(payload)
                self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "", ""))


class PostEditCheckTests(unittest.TestCase):

    def test_non_object_json_is_ignored_silently(self):
        for payload in ("[1, 2]", "5", "null"):
            with self.subTest(payload=payload):
                result = subprocess.run([sys.executable, os.path.join(HERE, "post_edit_check.py")],
                                        input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        universal_newlines=True, timeout=30)
                self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "", ""))


if __name__ == "__main__":
    unittest.main()
