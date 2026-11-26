# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 Jay Morris
"""Exercise image refresh behavior without contacting a container engine."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ImageRefreshTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        shutil.copy2(ROOT / "blacksite", self.root / "blacksite")
        shutil.copy2(ROOT / ".env.example", self.root / ".env")
        self.bin = self.root / "bin"
        self.bin.mkdir()
        docker = self.bin / "docker"
        docker.write_text(
            f"#!{sys.executable}\n"
            "import json, os, sys\n"
            "with open(os.environ['COMMAND_LOG'], 'a') as log:\n"
            "    log.write(json.dumps({'args': sys.argv[1:], "
            "'refresh': os.environ.get('UPSTREAM_REFRESH', '')}) + '\\n')\n"
        )
        docker.chmod(0o755)
        self.log = self.root / "commands.jsonl"
        self.env = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}", COMMAND_LOG=str(self.log))

    def run_cli(self, *args):
        subprocess.run(
            [str(self.root / "blacksite"), *args],
            env=self.env, check=True, capture_output=True, text=True,
        )
        return [
            entry for line in self.log.read_text().splitlines()
            if (entry := json.loads(line))["args"] != ["compose", "version"]
        ]

    def test_build_pulls_applications_and_refreshes_sources(self):
        calls = self.run_cli("build")
        self.assertEqual(len(calls), 2)
        self.assertIn("pull", calls[0]["args"])
        self.assertIn("proxyscotch", calls[0]["args"])
        self.assertIn("open-webui-tools-deploy", calls[0]["args"])
        self.assertNotIn("ollama", calls[0]["args"])
        self.assertEqual(calls[1]["args"][-2:], ["build", "--pull"])
        self.assertTrue(calls[1]["refresh"])

    def test_up_refreshes_before_starting(self):
        calls = self.run_cli("up")
        self.assertIn("pull", calls[0]["args"])
        self.assertIn("build", calls[1]["args"])
        self.assertEqual(calls[2]["args"][-2:], ["up", "-d"])

    def test_local_llm_build_refreshes_ollama(self):
        calls = self.run_cli("build", "--local-llm")
        self.assertIn("ollama", calls[0]["args"])
        self.assertIn("compose.ollama.yaml", calls[0]["args"])
        self.assertIn("compose.ollama.yaml", calls[1]["args"])

    def test_old_proxy_flag_remains_compatible(self):
        calls = self.run_cli("pull", "--hoppscotch-proxy")
        self.assertIn("proxyscotch", calls[0]["args"])
        self.assertNotIn("--profile", calls[0]["args"])

    def test_pull_failure_prevents_build_and_start(self):
        docker = self.bin / "docker"
        docker.write_text("#!/bin/sh\ncase \"$*\" in *pull*) exit 1;; esac\n")
        result = subprocess.run([str(self.root / "blacksite"), "up"], env=self.env, capture_output=True)
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
