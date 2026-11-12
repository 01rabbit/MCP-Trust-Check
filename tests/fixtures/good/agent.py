from mcp.client.auth.extensions.client_credentials import ClientCredentialsOAuthProvider
p = ClientCredentialsOAuthProvider(
    server_url="https://mcp.example.com/mcp", storage=s,
    client_id="x", client_secret=os.environ["SECRET"],
    issuer="https://auth.example.com",
)
