# MCP-Trust-Check

**English** | [日本語](README.ja.md)

A checker that finds MCP projects where the official SDK has been upgraded to a patched version but the fix is still not in effect, plus a lab that reproduces the underlying issue locally.

Between December 2025 and October 2026, the official MCP SDKs (Python, TypeScript, Go) received a series of advisories on transport and authorization. For some of them, upgrading alone changes nothing: you also have to pass a new argument or recreate stored credentials. This repository checks for exactly that gap.

- Write-up (Japanese, Qiita): [MCPのOAuthは更新だけでは塞がらない――手元で再現して点検ツールを作った](https://qiita.com/01rabbit/items/a916d76895b43e19503f) ("Upgrading alone does not close the MCP OAuth hole")

## Features

- Runs on the Python 3.8+ standard library only. Nothing to install.
- Read-only. It never modifies files and never touches the network.
- An outdated version alone is never reported as HIGH. All the advisories covered here concern the HTTP path, so stdio-only use is not affected. HIGH is reserved for code that is on a patched version but still does not get the fix.

## Contents

| Path | Purpose |
|---|---|
| `mcp_trust_check.py` | The checker |
| `tests/` | Tests and deliberately vulnerable fixtures (`fixtures/`) |
| `lab/` | A lab that reproduces GHSA-qx49-fqc8-xw99 entirely on 127.0.0.1 |
| `results/` | Raw reproduction results used in the write-up (JSONL) |

## Usage

```bash
# Check a project directory
python3 mcp_trust_check.py ~/src/my-agent

# Also read Claude Desktop / Claude Code configuration; output JSON
python3 mcp_trust_check.py ~/src/my-agent --claude-config --json

# Include test code (tests/ etc., excluded by default)
python3 mcp_trust_check.py ~/src/my-agent --include-tests
```

The exit code is 1 if there is at least one HIGH finding, so it can be dropped into CI as is.

## What it checks

| Finding | Severity | Description |
|---|---|---|
| `issuer-not-set` | HIGH | `ClientCredentialsOAuthProvider` / `PrivateKeyJWTOAuthProvider` (Python), or a bundled provider such as `ClientCredentialsProvider` (TypeScript), is constructed without an expected issuer (`issuer=` / `expectedIssuer`) |
| `no-issuer-option` | HIGH | Python's `RFC7523OAuthClientProvider` is used. This class has no way to pass an issuer |
| `issuer-check-disabled` | HIGH | Issuer validation is turned off with `skipIssuerMetadataValidation: true` |
| `audience-not-checked` | MEDIUM | `requireBearerAuth(...)` has no `expectedResource`, so tokens issued for other services are accepted |
| `redirect-follow` | MEDIUM | `redirectPolicy: 'follow'` re-sends headers and body to cross-origin redirect targets |
| `http-all-interfaces` | MEDIUM | An HTTP MCP server listens on 0.0.0.0 |
| `outdated-sdk` | MEDIUM | An SDK older than the fixed version is present (lock files, installed packages, go.mod) |
| `oauth-client-in-use` | INFO | The interactive `OAuthClientProvider` is used. Besides upgrading, stored client registrations must be cleared once and re-bound to the issuer |
| `issuer-unknown` | INFO | Arguments are passed indirectly (e.g. `**kwargs`), so whether an issuer is set cannot be determined |
| `http-transport` | INFO | An HTTP MCP server exists. Verify Origin validation, authentication and per-session instance isolation |

The version table is at the top of `mcp_trust_check.py`. Rows whose `src` is `G` were verified against the GitHub advisory text; rows marked `C` come from the table in the Cloud Security Alliance research note (2026-11-09) and have not been re-verified here.

## Lab

Reproduces GHSA-qx49-fqc8-xw99 (the OAuth client sends its credentials to an authorization server chosen by the MCP server) across several versions of the Python SDK.

```bash
cd lab
bash run_all.sh            # tries 1.29.1 / 1.30.0 / 2.3.0; fetches from PyPI on first run
VERSIONS="1.30.0" bash run_all.sh
```

- Uses only 127.0.0.1 ports 9100 (legitimate authorization server), 9200 (malicious MCP server) and 9300 (malicious authorization server). No external traffic.
- The client secret is a lab-only fake (`LAB-ONLY-not-a-real-secret`).
- The malicious authorization server only records the field names that arrive in the token request. It never uses or forwards the received values.

Results from 2026-11-12 (raw data in `results/`):

| mcp | `issuer=` | Constructed in | Warning shown | Secret reached the malicious AS |
|---|---|---|---|---|
| 1.29.1 | no | app module | none | yes |
| 1.29.1 | no | `__main__` | none | yes |
| 1.30.0 | no | app module | none | yes |
| 1.30.0 | no | `__main__` | DeprecationWarning | yes |
| 1.30.0 | yes | app module | none | no |
| 2.3.0 | no | app module | MCPDeprecationWarning | yes |
| 2.3.0 | no | `__main__` | MCPDeprecationWarning | yes |
| 2.3.0 | yes | app module | none | no |

In 1.30.0 the warning is a `DeprecationWarning` with `stacklevel=3`, which Python hides by default unless it is attributed to `__main__` (PEP 565). In 2.x it is `MCPDeprecationWarning`, a `UserWarning` subclass, and is always shown.

## Limitations

- Code checks are regex-based. Providers wrapped in another function or built from configuration files may be missed (`issuer-unknown` is reported when it cannot decide).
- Only the Python SDK is reproduced. The TypeScript and Go items rely on the advisory text and the CSA research note.
- SDKs other than the official Python, TypeScript and Go ones (e.g. the Rust SDK or custom implementations) are out of scope.
- No findings does not mean the project is safe.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## References

- [Write-up (Japanese, Qiita): MCPのOAuthは更新だけでは塞がらない――手元で再現して点検ツールを作った](https://qiita.com/01rabbit/items/a916d76895b43e19503f)
- [GHSA-qx49-fqc8-xw99 (Python SDK)](https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-qx49-fqc8-xw99)
- [GHSA-6qxp-vccf-f47h (TypeScript SDK)](https://github.com/modelcontextprotocol/typescript-sdk/security/advisories/GHSA-6qxp-vccf-f47h)
- [MCP Specification 2026-07-28: Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
- [Cloud Security Alliance: MCP's Transport Trust Gap (2026-11-09)](https://labs.cloudsecurityalliance.org/research/csa-research-note-mcp-transport-trust-gap-20261109-csa-style/)

## License

MIT License (Copyright (c) 2026 Mr.Rabbit)
