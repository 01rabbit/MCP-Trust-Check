"""Tests for mcp_trust_check.py. Run with: python3 -m unittest discover -s tests"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOL = HERE.parent / "mcp_trust_check.py"
FX = HERE / "fixtures"


def run(path):
    p = subprocess.run([sys.executable, str(TOOL), str(path), "--json"], capture_output=True, text=True)
    return p.returncode, json.loads(p.stdout)


def kinds(result, level=None):
    return sorted(f["kind"] for f in result["findings"] if level is None or f["level"] == level)


class CheckerTest(unittest.TestCase):
    def test_upgraded_but_issuer_missing_is_high(self):
        code, r = run(FX / "upgraded")
        self.assertEqual(code, 1)
        self.assertEqual(kinds(r, "high"), ["issuer-not-set"])
        self.assertNotIn("outdated-sdk", kinds(r))  # 1.30.0 is the fixed release

    def test_fixed_and_configured_is_clean(self):
        code, r = run(FX / "good")
        self.assertEqual(code, 0)
        self.assertEqual(r["findings"], [])

    def test_bad_project(self):
        code, r = run(FX / "bad")
        self.assertEqual(code, 1)
        self.assertEqual(kinds(r, "high"), ["issuer-not-set", "issuer-not-set"])
        for k in ("audience-not-checked", "http-all-interfaces", "outdated-sdk"):
            self.assertIn(k, kinds(r, "medium"))
        found = {(v["pkg"], v["version"]) for v in r["versions"]}
        self.assertIn(("go:github.com/modelcontextprotocol/go-sdk", "1.3.0"), found)
        self.assertIn(("npm:@modelcontextprotocol/sdk", "1.30.1"), found)

    def test_version_alone_is_never_high(self):
        _, r = run(FX / "bad")
        for f in r["findings"]:
            if f["kind"] == "outdated-sdk":
                self.assertEqual(f["level"], "medium")

    def test_variable_named_transport_is_not_a_server(self):
        _, r = run(FX / "falsepos")
        self.assertNotIn("http-transport", kinds(r))
        # 1.8.0 predates the first release affected by the OAuth advisory
        self.assertFalse(any("GHSA-qx49" in f["ref"] for f in r["findings"]))

    def test_interactive_provider_is_reported(self):
        _, r = run(FX / "interactive")
        self.assertEqual(kinds(r), ["oauth-client-in-use"])

    def test_sdk_copy_is_not_treated_as_user_code(self):
        with tempfile.TemporaryDirectory() as d:
            sdk = Path(d) / "mcp"
            (sdk / "client" / "auth" / "extensions").mkdir(parents=True)
            (sdk / "client" / "auth" / "oauth2.py").write_text("# mcp\n")
            (sdk / "client" / "auth" / "extensions" / "client_credentials.py").write_text(
                "import mcp\nclass X(ClientCredentialsOAuthProvider(\n  server_url=u, storage=s)):\n  pass\n")
            _, r = run(d)
            self.assertEqual(r["findings"], [])


if __name__ == "__main__":
    unittest.main()
