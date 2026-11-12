import { ClientCredentialsProvider } from "@modelcontextprotocol/client";
const p = new ClientCredentialsProvider({ clientId: "x", clientSecret: s, expectedIssuer: "https://auth.example.com" });
app.use("/mcp", requireBearerAuth({ verifier, expectedResource: "https://mcp.example.com/mcp" }));
