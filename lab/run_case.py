"""Run one case: python run_case.py [--issuer] [--construct-in-main]

Prints a JSON line describing what reached the rogue authorization server.
Warnings use Python's default filters (nothing is forced on), so what is shown
here is what an application would show.
"""

import asyncio
import importlib.metadata
import inspect
import json
import sys
import warnings

try:
    import httpx
except ImportError:  # mcp 2.x ships httpx2
    import httpx2 as httpx

import servers
from app_client import LAB_SECRET, MemoryStorage, make_provider

USE_ISSUER = "--issuer" in sys.argv
IN_MAIN = "--construct-in-main" in sys.argv


def build():
    if not IN_MAIN:
        return make_provider(f"{servers.ROGUE_MCP}/mcp", servers.LEGIT_AS if USE_ISSUER else None)
    # Same construction, but written directly in __main__
    from mcp.client.auth.extensions.client_credentials import ClientCredentialsOAuthProvider
    kwargs = {"issuer": servers.LEGIT_AS} if USE_ISSUER else {}
    return ClientCredentialsOAuthProvider(
        server_url=f"{servers.ROGUE_MCP}/mcp", storage=MemoryStorage(),
        client_id="lab-client", client_secret=LAB_SECRET, **kwargs,
    )


async def main():
    servers.start()
    shown = []
    orig = warnings.showwarning
    warnings.showwarning = lambda m, c, *a, **k: (shown.append(c.__name__), orig(m, c, *a, **k))
    supports_issuer = "issuer" in inspect.signature(
        __import__("mcp.client.auth.extensions.client_credentials", fromlist=["x"]).ClientCredentialsOAuthProvider.__init__
    ).parameters
    if USE_ISSUER and not supports_issuer:
        print(json.dumps({"skipped": "issuer= not supported in this version"}))
        return
    provider = build()
    error = None
    try:
        async with httpx.AsyncClient(auth=provider, timeout=5) as client:
            await client.post(f"{servers.ROGUE_MCP}/mcp", json={"jsonrpc": "2.0", "id": 0, "method": "ping"})
    except Exception as e:  # the flow is expected to fail one way or another
        error = f"{type(e).__name__}: {str(e)[:120]}"
    leaked = any(r["client_secret"] == LAB_SECRET for r in servers.received)
    print(json.dumps({
        "mcp": importlib.metadata.version("mcp"),
        "issuer_passed": USE_ISSUER,
        "constructed_in": "__main__" if IN_MAIN else "app module",
        "warnings_shown": shown,
        "secret_reached_rogue_as": leaked,
        "rogue_token_requests": [{k: v for k, v in r.items() if k != "client_secret"} for r in servers.received],
        "legit_as_requests": servers.legit_hits,
        "error": error,
    }, ensure_ascii=False))


asyncio.run(main())
