from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x", host="0.0.0.0")
mcp.run(transport="streamable-http")
