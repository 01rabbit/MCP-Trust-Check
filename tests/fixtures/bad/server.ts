import { ClientCredentialsProvider } from "@modelcontextprotocol/client";
const p = new ClientCredentialsProvider({ clientId: "x", clientSecret: s });
app.use("/mcp", requireBearerAuth({ verifier }));
const t = new StreamableHTTPServerTransport({});
app.listen(3000, "0.0.0.0");
