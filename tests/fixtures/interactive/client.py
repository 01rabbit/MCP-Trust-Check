from mcp.client.auth import OAuthClientProvider
provider = OAuthClientProvider(server_url=url, client_metadata=meta, storage=s, redirect_handler=r, callback_handler=c)
