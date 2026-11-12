#!/usr/bin/env python3
"""mcp-trust-check: find MCP SDK setups where "upgraded" does not mean "fixed".

Read-only. Standard library only. It never connects to anything.

It looks for three things under the paths you give it:
  1. installed or pinned MCP SDK versions older than the releases that fixed the
     2025-12 .. 2026-10 transport/auth advisories
  2. code that uses a fixed SDK but leaves the fix switched off
     (OAuth providers without an expected issuer, bearer auth without an audience, ...)
  3. MCP servers configured for HTTP rather than stdio

Usage:
  python3 mcp_trust_check.py PATH [PATH ...] [--json] [--claude-config] [--include-tests]
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Advisory table. "fixed" is the first release containing the fix for that line.
# src: G = checked against the GitHub advisory text, C = taken from the CSA research
# note of 2026-11-09 (its table of fixed releases) and not re-checked here.
# ---------------------------------------------------------------------------
ADVISORIES = [
    # Python: package "mcp"
    {"pkg": "py:mcp", "line": 1, "fixed": "1.23.0", "id": "GHSA-9h52-p55h-vw2f",
     "what": "DNS rebinding protection off by default (localhost HTTP servers)", "src": "C"},
    {"pkg": "py:mcp", "line": 1, "from": "1.9.1", "fixed": "1.30.0", "id": "GHSA-qx49-fqc8-xw99",
     "what": "OAuth client sends credentials to an AS the MCP server picks", "src": "G"},
    {"pkg": "py:mcp", "line": 2, "from": "2.0.0a1", "fixed": "2.2.0", "id": "GHSA-qx49-fqc8-xw99",
     "what": "OAuth client sends credentials to an AS the MCP server picks", "src": "G"},
    # TypeScript 1.x: "@modelcontextprotocol/sdk"
    {"pkg": "npm:@modelcontextprotocol/sdk", "line": 1, "fixed": "1.24.0", "id": "GHSA-w48q-cv73-mx4w",
     "what": "DNS rebinding protection off by default (localhost HTTP servers)", "src": "G"},
    {"pkg": "npm:@modelcontextprotocol/sdk", "line": 1, "fixed": "1.26.0", "id": "GHSA-345p-7cg4-v4c7",
     "what": "shared server/transport instance leaks responses across clients", "src": "C"},
    {"pkg": "npm:@modelcontextprotocol/sdk", "line": 1, "from": "1.12.0", "fixed": "1.31.0", "id": "GHSA-6qxp-vccf-f47h",
     "what": "OAuth client sends credentials to an AS the MCP server picks", "src": "G"},
    {"pkg": "npm:@modelcontextprotocol/sdk", "line": 1, "fixed": "1.32.0", "id": "GHSA-rvq5-wwqv-78pq",
     "what": "bearer auth accepts tokens issued for another service", "src": "C"},
    {"pkg": "npm:@modelcontextprotocol/sdk", "line": 1, "fixed": "1.32.0", "id": "GHSA-6prh-2h8m-c8cw",
     "what": "client follows cross-origin redirects and re-sends headers/body", "src": "G"},
    {"pkg": "npm:@modelcontextprotocol/sdk", "line": 1, "fixed": "1.32.0", "id": "GHSA-22jm-h49p-29qw",
     "what": "experimental tasks not tied to the creating session", "src": "C"},
    # TypeScript 2.x split packages
    {"pkg": "npm:@modelcontextprotocol/client", "line": 2, "from": "2.0.0", "fixed": "2.2.0", "id": "GHSA-6qxp-vccf-f47h",
     "what": "OAuth client sends credentials to an AS the MCP server picks", "src": "G"},
    {"pkg": "npm:@modelcontextprotocol/client", "line": 2, "from": "2.0.0", "fixed": "2.3.0", "id": "GHSA-6prh-2h8m-c8cw",
     "what": "client follows cross-origin redirects and re-sends headers/body", "src": "G"},
    {"pkg": "npm:@modelcontextprotocol/server", "line": 2, "fixed": "2.3.0", "id": "GHSA-jm63-cq47-j5jp",
     "what": "shared server/transport instance leaks messages across clients", "src": "C"},
    {"pkg": "npm:@modelcontextprotocol/server", "line": 2, "fixed": "2.3.0", "id": "GHSA-rvq5-wwqv-78pq",
     "what": "bearer auth accepts tokens issued for another service", "src": "C"},
    {"pkg": "npm:@modelcontextprotocol/express", "line": 2, "fixed": "2.0.2", "id": "GHSA-rvq5-wwqv-78pq",
     "what": "bearer auth accepts tokens issued for another service", "src": "C"},
    # Go
    {"pkg": "go:github.com/modelcontextprotocol/go-sdk", "line": 1, "fixed": "1.4.0", "id": "GHSA-xw59-hvm2-8pj6",
     "what": "DNS rebinding protection off by default (localhost HTTP servers)", "src": "C"},
    {"pkg": "go:github.com/modelcontextprotocol/go-sdk", "line": 1, "fixed": "1.4.1", "id": "GHSA-89xv-2j6f-qhc8",
     "what": "cross-site text/plain POST reaches HTTP servers without authorization", "src": "C"},
]

# ---------------------------------------------------------------------------
# Code patterns: the fix exists but is off unless you turn it on.
# ---------------------------------------------------------------------------
PY_PROVIDERS = ("ClientCredentialsOAuthProvider", "PrivateKeyJWTOAuthProvider")
TS_PROVIDERS = ("ClientCredentialsProvider", "PrivateKeyJwtProvider",
                "StaticPrivateKeyJwtProvider", "CrossAppAccessProvider")
SKIP_DIRS = {"node_modules", "site-packages", "dist-packages", ".git", ".venv", "venv",
             "__pycache__", "dist", "build", ".tox", ".mypy_cache", "archive-v0", ".cache"}


def is_sdk_copy(path):
    """A vendored or cached copy of the Python SDK itself (its own code is not 'your code')."""
    return path.name == "mcp" and (path / "client" / "auth" / "oauth2.py").is_file()


def vtuple(v):
    nums = re.findall(r"\d+", v.split("+")[0])[:3]
    if not nums:
        return None
    t = [int(n) for n in nums] + [0] * (3 - len(nums))
    pre = bool(re.search(r"(a|b|rc|alpha|beta|dev)\d*", v.split("+")[0][len(".".join(nums)):]))
    return tuple(t) + ((0,) if pre else (1,))


def call_args(text, start):
    """Text of the argument list for the call whose name ends at `start`."""
    i = text.find("(", start)
    if i < 0 or i - start > 3:
        return None
    depth = 0
    for j in range(i, min(len(text), i + 4000)):
        c = text[j]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return text[i + 1:j]
    return None


def line_of(text, pos):
    return text.count("\n", 0, pos) + 1


class Report:
    def __init__(self):
        self.versions = []   # {pkg, version, where}
        self.findings = []   # {level, kind, where, detail, ref}

    def add(self, level, kind, where, detail, ref=""):
        self.findings.append({"level": level, "kind": kind, "where": str(where), "detail": detail, "ref": ref})


# ----------------------------- version discovery ----------------------------

def find_versions(root, rep):
    for dirpath, dirnames, filenames in os.walk(root):
        p = Path(dirpath)
        # installed Python package
        if p.name.startswith("mcp-") and p.name.endswith(".dist-info"):
            rep.versions.append({"pkg": "py:mcp", "version": p.name[4:-10], "where": str(p)})
            dirnames[:] = []
            continue
        # installed npm package
        if p.parent.name == "@modelcontextprotocol" and "package.json" in filenames:
            try:
                d = json.loads((p / "package.json").read_text())
                rep.versions.append({"pkg": f"npm:{d.get('name')}", "version": d.get("version", "?"), "where": str(p)})
            except (OSError, ValueError):
                pass
            dirnames[:] = []
            continue
        if p.name in (".git", "__pycache__"):
            dirnames[:] = []
            continue
        for f in filenames:
            fp = p / f
            if f == "go.mod":
                for m in re.finditer(r"github\.com/modelcontextprotocol/go-sdk\s+v([\w.\-+]+)", fp.read_text(errors="ignore")):
                    rep.versions.append({"pkg": "go:github.com/modelcontextprotocol/go-sdk", "version": m.group(1), "where": str(fp)})
            elif f in ("requirements.txt", "uv.lock", "poetry.lock", "pylock.toml") or (f.startswith("requirements") and f.endswith(".txt")):
                text = fp.read_text(errors="ignore")
                if f.endswith(".lock") or f == "pylock.toml":
                    for m in re.finditer(r'name\s*=\s*"mcp"\s*\n\s*version\s*=\s*"([^"]+)"', text):
                        rep.versions.append({"pkg": "py:mcp", "version": m.group(1), "where": str(fp)})
                else:
                    for m in re.finditer(r"^\s*mcp(?:\[[^\]]*\])?\s*==\s*([\w.\-+]+)", text, re.M):
                        rep.versions.append({"pkg": "py:mcp", "version": m.group(1), "where": str(fp)})
            elif f == "package-lock.json":
                try:
                    d = json.loads(fp.read_text())
                except (OSError, ValueError):
                    continue
                for key, info in (d.get("packages") or {}).items():
                    name = key.split("node_modules/")[-1]
                    if name.startswith("@modelcontextprotocol/") and isinstance(info, dict) and "version" in info:
                        rep.versions.append({"pkg": f"npm:{name}", "version": info["version"], "where": f"{fp} ({key})"})


def check_versions(rep):
    for v in rep.versions:
        vt = vtuple(v["version"])
        if vt is None:
            continue
        for a in ADVISORIES:
            if a["pkg"] != v["pkg"] or vt[0] != a["line"]:
                continue
            if a.get("from") and vt < vtuple(a["from"]):
                continue  # older than the first affected release
            if vt < vtuple(a["fixed"]):
                # A version alone is not a hole: every advisory here is about the HTTP transport
                # or HTTP OAuth, and stdio use is out of scope. Code findings carry the weight.
                rep.add("medium", "outdated-sdk", v["where"],
                        f"{v['pkg'][v['pkg'].index(':') + 1:]} {v['version']} < {a['fixed']}: {a['what']}"
                        " (matters only if this copy is used over HTTP; stdio is not affected)",
                        f"{a['id']} [{'GitHub advisory' if a['src'] == 'G' else 'per CSA note'}]")


# ------------------------------- code patterns ------------------------------

def scan_code(root, rep, include_tests=False):
    skip = SKIP_DIRS if include_tests else SKIP_DIRS | {"tests", "test", "__tests__"}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip and not d.endswith(".dist-info")
                       and not is_sdk_copy(Path(dirpath) / d)]
        for f in filenames:
            if not f.endswith((".py", ".ts", ".tsx", ".js", ".mjs", ".cjs")):
                continue
            fp = Path(dirpath) / f
            try:
                text = fp.read_text(errors="ignore")
            except OSError:
                continue
            if "mcp" not in text and "modelcontextprotocol" not in text:
                continue
            is_py = f.endswith(".py")
            providers = PY_PROVIDERS if is_py else TS_PROVIDERS
            key = "issuer" if is_py else "expectedIssuer"
            for name in providers:
                for m in re.finditer(rf"\b(?:new\s+)?{name}\b", text):
                    args = call_args(text, m.end())
                    if args is None:
                        continue
                    if re.search(rf"\b{key}\s*[=:]", args):
                        continue
                    if "**" in args or (not is_py and re.fullmatch(r"\s*\w+\s*", args)):
                        rep.add("info", "issuer-unknown", f"{fp}:{line_of(text, m.start())}",
                                f"{name}(...) gets its options indirectly; confirm {key} is set")
                    else:
                        rep.add("high", "issuer-not-set", f"{fp}:{line_of(text, m.start())}",
                                f"{name}(...) without {key}: the MCP server still chooses where the client secret goes",
                                "GHSA-qx49-fqc8-xw99" if is_py else "GHSA-6qxp-vccf-f47h")
            if is_py and re.search(r"\bRFC7523OAuthClientProvider\b", text):
                m = re.search(r"\bRFC7523OAuthClientProvider\b", text)
                rep.add("high", "no-issuer-option", f"{fp}:{line_of(text, m.start())}",
                        "RFC7523OAuthClientProvider has no issuer option; move to PrivateKeyJWTOAuthProvider(issuer=...)",
                        "GHSA-qx49-fqc8-xw99")
            for m in re.finditer(r"skipIssuerMetadataValidation\s*:\s*true", text):
                rep.add("high", "issuer-check-disabled", f"{fp}:{line_of(text, m.start())}",
                        "skipIssuerMetadataValidation: true turns the issuer check back off", "GHSA-6qxp-vccf-f47h")
            for m in re.finditer(r"redirectPolicy\s*:\s*['\"]follow['\"]", text):
                rep.add("medium", "redirect-follow", f"{fp}:{line_of(text, m.start())}",
                        "redirectPolicy 'follow' can re-send session headers and request bodies cross-origin",
                        "GHSA-6prh-2h8m-c8cw")
            for m in re.finditer(r"\brequireBearerAuth\s*\(", text):
                args = call_args(text, m.end() - 1) or ""
                if "expectedResource" not in args:
                    rep.add("medium", "audience-not-checked", f"{fp}:{line_of(text, m.start())}",
                            "requireBearerAuth(...) without expectedResource accepts tokens minted for other services",
                            "GHSA-rvq5-wwqv-78pq")
            # HTTP exposure of a server
            m = re.search(r"from\s+mcp\.client\.auth(?:\.oauth2)?\s+import\s+[^\n]*\bOAuthClientProvider\b", text) if is_py else None
            if m:
                rep.add("info", "oauth-client-in-use", f"{fp}:{line_of(text, m.start())}",
                        "interactive OAuthClientProvider: needs mcp >= 1.30.0 / 2.2.0, then clear stored client "
                        "registrations once so they are re-bound to an issuer", "GHSA-qx49-fqc8-xw99")
            # Only actual server-side transports, not variables that happen to be named "transport"
            http_hit = re.search(r"\bnew\s+(?:StreamableHTTPServerTransport|SSEServerTransport)\b|"
                                 r"\b(?:StreamableHTTPServerTransport|SseServerTransport)\s*\(|"
                                 r"\.(?:streamable_http_app|sse_app)\s*\(|"
                                 r"\.run\([^)]*transport\s*=\s*['\"](?:streamable-http|sse|http)['\"]|"
                                 r"\bcreateMcpExpressApp\s*\(", text)
            if http_hit:
                where = f"{fp}:{line_of(text, http_hit.start())}"
                if re.search(r"host\s*[=:]\s*['\"]0\.0\.0\.0['\"]|listen\([^)]*['\"]0\.0\.0\.0['\"]", text):
                    rep.add("medium", "http-all-interfaces", where,
                            "MCP server over HTTP bound to 0.0.0.0: reachable from the network, not just this machine")
                else:
                    rep.add("info", "http-transport", where,
                            "MCP server over HTTP: check Origin validation, authentication, and one server/transport per session")


# ---------------------------- Claude Desktop config -------------------------

def scan_claude_config(rep):
    cands = [Path.home() / "Library/Application Support/Claude/claude_desktop_config.json",
             Path.home() / ".config/Claude/claude_desktop_config.json",
             Path.home() / ".claude.json"]
    for c in cands:
        if not c.is_file():
            continue
        try:
            d = json.loads(c.read_text())
        except (OSError, ValueError):
            continue
        for name, s in (d.get("mcpServers") or {}).items():
            if isinstance(s, dict) and ("url" in s or s.get("type") in ("http", "sse", "streamable-http")):
                rep.add("info", "remote-mcp-server", f"{c} [{name}]",
                        "HTTP MCP server: the OAuth issues above apply to this connection")


# ----------------------------------- main -----------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--claude-config", action="store_true", help="also read Claude Desktop / Claude Code MCP config")
    ap.add_argument("--include-tests", action="store_true", help="also scan tests/ directories (skipped by default)")
    a = ap.parse_args()
    rep = Report()
    for p in a.paths:
        find_versions(p, rep)
        scan_code(p, rep, a.include_tests)
    if a.claude_config:
        scan_claude_config(rep)
    check_versions(rep)
    order = {"high": 0, "medium": 1, "info": 2}
    rep.findings.sort(key=lambda f: (order[f["level"]], f["kind"], f["where"]))
    if a.json:
        print(json.dumps({"versions": rep.versions, "findings": rep.findings}, ensure_ascii=False, indent=2))
    else:
        print(f"MCP SDK copies found: {len(rep.versions)}")
        for v in rep.versions:
            print(f"  {v['pkg']:42} {v['version']:10} {v['where']}")
        print(f"\nFindings: {len(rep.findings)}")
        for f in rep.findings:
            print(f"  [{f['level'].upper():6}] {f['kind']:22} {f['where']}\n           {f['detail']}" + (f"  ({f['ref']})" if f["ref"] else ""))
    return 1 if any(f["level"] == "high" for f in rep.findings) else 0


if __name__ == "__main__":
    sys.exit(main())
