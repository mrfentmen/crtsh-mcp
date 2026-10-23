# crtsh-mcp

MCP server for [crt.sh](https://crt.sh) — the public Certificate Transparency log search. Find every TLS certificate ever logged for a domain: live and expired, who issued them, which subdomains they cover, and what is about to expire. No key, no account.

## Tools

| Tool | What it does |
|---|---|
| `search_certificates` | Search CT logs by domain or `%`-wildcard pattern; optional expired filter |
| `get_subdomains` | Discover subdomains from SAN entries across all logged certs |
| `get_issuers` | Which CAs issued certs for a domain, with counts |
| `get_certificate` | One log entry by crt.sh id |
| `get_expiring_certs` | Certs expiring within N days |
| `get_expired_certs` | Already-expired certs |
| `get_cert_history` | One-shot summary: totals, first/last seen, unique names, top issuers |
| `get_wildcard_certs` | Certs with wildcard SANs covering the domain |

## Usage

```bash
pip install -e ".[dev]"
pytest
crtsh-mcp            # stdio (Claude Desktop / Claude Code)
crtsh-mcp --sse      # SSE transport on 127.0.0.1:8000
crtsh-mcp --http     # streamable HTTP on 127.0.0.1:8000/mcp
```

Claude Desktop config:

```json
{
  "mcpServers": {
    "crtsh": {
      "command": "crtsh-mcp",
      "args": []
    }
  }
}
```

## Honest limits

- crt.sh is a free community service and often slow or overloaded; the server retries 5xx/timeout responses with backoff and says so when the search queue is saturated.
- CT logs only show what was logged — an unlogged internal cert will never appear.
- `get_subdomains` caps output at 200 names; results reflect certificate SANs, not a live DNS scan.
- Everything is read-only public data.

## Gap note

Verified 2026-10-23: no MCP server for crt.sh exists on npm or GitHub (checked `crtsh-mcp`, `crt-sh-mcp`, GitHub repo search) — this is the first.

## License

MIT.
