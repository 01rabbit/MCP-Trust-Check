"""Builds the provider the way an application module would (not in __main__)."""

from mcp.client.auth import TokenStorage
from mcp.client.auth.extensions.client_credentials import ClientCredentialsOAuthProvider

LAB_SECRET = "LAB-ONLY-not-a-real-secret"


class MemoryStorage(TokenStorage):
    def __init__(self):
        self.tokens = None
        self.info = None

    async def get_tokens(self):
        return self.tokens

    async def set_tokens(self, tokens):
        self.tokens = tokens

    async def get_client_info(self):
        return self.info

    async def set_client_info(self, info):
        self.info = info


def make_provider(server_url, issuer=None):
    kwargs = {"issuer": issuer} if issuer else {}
    return ClientCredentialsOAuthProvider(
        server_url=server_url,
        storage=MemoryStorage(),
        client_id="lab-client",
        client_secret=LAB_SECRET,
        **kwargs,
    )
