# mentions mcp but only describes config
def summary(cfg):
    transport = "http" if cfg.get("url") else "stdio"
    return transport
