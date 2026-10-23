"""crtsh-mcp — MCP server over the crt.sh certificate-transparency log search.

crt.sh indexes every certificate logged to public Certificate Transparency
logs. This server exposes that index to LLM clients: certificate lookups by
domain or log id, subdomain discovery from SAN entries, issuer breakdowns,
expiry tracking and a one-shot domain history summary. Keyless, read-only.
"""

from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime, timedelta, timezone

import html as _html

import httpx
from mcp import types
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent
from starlette.applications import Starlette
from starlette.routing import Mount, Route
from mcp.server.sse import SseServerTransport
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager

BASE_URL = "https://crt.sh"
USER_AGENT = "crtsh-mcp/0.1 (MCP server; public CT log search)"
TIMEOUT = 60.0

app = Server("crtsh-mcp")

_NAME_RE = re.compile(r"^[A-Za-z0-9*._-]+\.[A-Za-z]{2,}$")


# ----- fetching ----------------------------------------------------------------


async def fetch_certs(query: str, exclude_expired: bool = False, max_results: int = 100) -> list[dict]:
    """Query crt.sh JSON output and return decoded cert records.

    crt.sh is frequently overloaded; retry a couple of times on 5xx/timeouts.
    """
    params = {"q": query, "output": "json"}
    if exclude_expired:
        params["exclude"] = "expired"
    last_error = ""
    async with httpx.AsyncClient(timeout=TIMEOUT, headers={"User-Agent": USER_AGENT}, follow_redirects=True) as client:
        for attempt in range(3):
            try:
                r = await client.get(f"{BASE_URL}/", params=params)
                if r.status_code in (502, 503, 504):
                    last_error = f"crt.sh returned {r.status_code} (search queue overloaded)"
                elif r.status_code == 200:
                    text = r.text.strip()
                    if not text:
                        return []
                    try:
                        data = json.loads(text)
                    except json.JSONDecodeError:
                        last_error = "crt.sh returned a non-JSON body (usually overload or rate limiting)"
                        await asyncio.sleep(3 * (attempt + 1))
                        continue
                    if not isinstance(data, list):
                        last_error = "unexpected crt.sh response shape"
                    else:
                        return data[:max_results]
                elif r.status_code == 404:
                    return []
                else:
                    last_error = f"HTTP {r.status_code}"
            except (httpx.TimeoutException, httpx.TransportError) as e:
                last_error = f"{type(e).__name__}: {e}"
            await asyncio.sleep(3 * (attempt + 1))
    raise ValueError(f"crt.sh query failed after retries: {last_error}")


# ----- parsing -----------------------------------------------------------------


def clean(s: str | None) -> str:
    return re.sub(r"\s+", " ", (s or "")).strip()


def parse_record(raw: dict) -> dict:
    return {
        "id": raw.get("id"),
        "common_name": clean(raw.get("common_name")),
        "names": [n for n in clean(raw.get("name_value", "")).replace("\n", " ").split(" ") if n],
        "issuer": clean(raw.get("issuer_name")),
        "not_before": clean(raw.get("not_before")),
        "not_after": clean(raw.get("not_after")),
        "serial_number": clean(raw.get("serial_number")),
    }


def _parse_dt(value: str) -> datetime | None:
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def valid_domains(names: list[str]) -> list[str]:
    """Names from SAN entries that look like real domains (drops wildcards, empties)."""
    out = []
    for n in names:
        n = n.lstrip("*.").strip()
        if n and _NAME_RE.fullmatch(n) and n not in out:
            out.append(n)
    return out


# ----- certificate-page (HTML) parsing ------------------------------------------


def parse_cert_page(html: str, cert_id: str) -> dict:
    """Extract the details block of a crt.sh cert detail page (?id=<n>, HTML).

    The page is pre-formatted text dumped inside <PRE>-ish segments with '\n'
    as <BR> and nbsp spacing. We unescape, normalise, then slice labeled
    sections.
    """
    text = _html.unescape(html).replace("<BR>", "\n").replace("<br>", "\n")
    text = text.replace("\xa0", " ")
    text = re.sub(r"[ \t]+", " ", text)
    plain = re.sub(r"<[^>]+>", "", text)  # tag-free copy for field parsing

    def section(start_label: str, end_labels: list[str]) -> str:
        i = plain.find(start_label)
        if i < 0:
            return ""
        rest = plain[i + len(start_label):]
        end = len(rest)
        for e in end_labels:
            j = rest.find(e)
            if 0 <= j < end:
                end = j
        return rest[:end]

    def kv(block: str) -> dict[str, str]:
        out = {}
        for line in block.split("\n"):
            m = re.match(r"\s*(\w+)\s*=\s*(.+?)\s*$", line)
            if m:
                out[m.group(1)] = m.group(2)
        return out

    subject_block = section("Subject:\n", ["Subject Public Key", "Validity"])
    issuer_block = section("Issuer:", ["Validity", "Subject Public Key", "X509v3", "CT "])
    sans = re.findall(r"DNS:([^\s<\r\n]+)", plain)
    m = re.search(r"Not Before\s*:\s*([^\n<]+)", plain)
    not_before = _clean_openssl_date(m.group(1)) if m else ""
    m = re.search(r"Not After\s*:\s*([^\n<]+)", plain)
    not_after = _clean_openssl_date(m.group(1)) if m else ""
    m = re.search(r"Serial Number\s*:\s*([\dA-Fa-f:\s]+)", plain)
    serial = re.sub(r"[\s:]", "", m.group(1)).lower() if m else ""
    m = re.search(r"Signature Algorithms?:\s*([^\n<]+)", plain)
    sig_alg = m.group(1).strip() if m else ""

    scts = []
    for m in re.finditer(r"Signed Certificate Timestamp:\s*Version\s*:\s*([^\n]*)\s*Log Name\s*:\s*([^\n]*)", plain):
        scts.append({"version": m.group(1).strip(), "log_name": " ".join(m.group(2).split())})

    entries = []
    for m in re.finditer(
            r"<TD>(\d{4}-\d\d-\d\d)\s*(?:<FONT[^>]*>)?([\d:]+ UTC)?(?:</FONT>)?</TD>\s*"
            r"<TD>(\d+)</TD>\s*<TD>([^<]+)</TD>\s*<TD>([^<]+)</TD>", text):
        entries.append({"date": m.group(1), "time": (m.group(2) or "").replace("UTC", "").strip(),
                        "entry_no": int(m.group(3)), "log_operator": m.group(4).strip(),
                        "log_url": m.group(5).strip()})

    return {
        "id": int(cert_id) if cert_id.isdigit() else cert_id,
        "subject": kv(subject_block),
        "issuer": kv(issuer_block),
        "names": list(dict.fromkeys(sans)),
        "not_before": not_before,
        "not_after": not_after,
        "serial_number": serial,
        "signature_algorithm": sig_alg,
        "ct_logs": scts,
        "log_entries": entries,
    }


def _clean_openssl_date(raw: str) -> str:
    return re.sub(r"\s+", " ", raw).strip()


def format_cert_page(cert: dict) -> str:
    lines = [f"## Certificate log {cert['id']}", ""]
    sub = cert["subject"]
    lines.append(f"- Subject CN: {sub.get('commonName', '?')}")
    lines.append(f"- Issuer CN: {cert['issuer'].get('commonName', '?')}")
    lines.append(f"- Valid: {cert['not_before']} → {cert['not_after']}")
    lines.append(f"- Serial: {cert['serial_number'] or '?'}")
    lines.append(f"- Signature: {cert['signature_algorithm'] or '?'}")
    if cert["names"]:
        lines.append(f"- SANs ({len(cert['names'])}): {', '.join(cert['names'][:15])}{' …' if len(cert['names']) > 15 else ''}")
    for e in cert["log_entries"][:5]:
        lines.append(f"- Logged: {e['date']} {e['time']} UTC  entry #{e['entry_no']}  {e['log_operator']}")
    if cert["ct_logs"]:
        lines.append(f"- SCTs: {', '.join(l['log_name'] for l in cert['ct_logs'][:5])}")
    return "\n".join(lines)


# ----- formatting ---------------------------------------------------------------


def format_records(title: str, records: list[dict], show_names: bool = True) -> str:
    lines = [f"## {title} ({len(records)} shown)", ""]
    if not records:
        lines.append("No certificates found.")
        return "\n".join(lines)
    for rec in records:
        lines.append(f"{rec['id']}  {rec['common_name']}")
        if show_names and len(rec["names"]) > 1:
            lines.append(f"   SANs: {', '.join(rec['names'][:8])}{' …' if len(rec['names']) > 8 else ''}")
        lines.append(f"   issuer: {rec['issuer']}")
        lines.append(f"   valid: {rec['not_before']} → {rec['not_after']}")
    return "\n".join(lines)


# ----- tool spec -----------------------------------------------------------------

LIST_TOOLS_SPEC = [
    ("search_certificates", "Search CT logs for certificates matching a domain (optionally subdomains via a % wildcard).",
     {"domain": {"type": "string", "description": "Domain or pattern, e.g. 'example.com' or '%.example.com'."},
      "exclude_expired": {"type": "boolean", "description": "Drop expired certs (crt.sh server-side filter).", "default": False},
      "max_results": {"type": "integer", "description": "Cap the returned records (default 50).", "default": 50}}),
    ("get_subdomains", "Discover subdomains for a domain from SAN entries across all logged certificates.",
     {"domain": {"type": "string", "description": "Base domain, e.g. 'example.com'."}}),
    ("get_issuers", "Break down which CAs issued certificates for a domain, with counts.",
     {"domain": {"type": "string", "description": "Domain to analyse."}}),
    ("get_certificate", "Fetch one certificate log entry by its crt.sh log id.",
     {"cert_id": {"type": "string", "description": "crt.sh log id (from search_certificates)."}}),
    ("get_expiring_certs", "Certificates for a domain expiring within N days.",
     {"domain": {"type": "string", "description": "Domain to check."},
      "days": {"type": "integer", "description": "Window in days (default 30).", "default": 30}}),
    ("get_expired_certs", "Already-expired certificates for a domain.",
     {"domain": {"type": "string", "description": "Domain to check."}}),
    ("get_cert_history", "One-shot summary: total logged certs, first/last seen, unique names, issuer counts.",
     {"domain": {"type": "string", "description": "Domain to summarise."}}),
    ("get_wildcard_certs", "Certificates whose SAN includes wildcard names (*.<domain>).",
     {"domain": {"type": "string", "description": "Domain to check for wildcard coverage."}}),
]


@app.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(name=name, description=description, inputSchema={"type": "object", "properties": props})
        for name, description, props in LIST_TOOLS_SPEC
    ]


async def call_tool_implementation(name: str, arguments: dict) -> str:
    if name == "search_certificates":
        domain = (arguments.get("domain") or "").strip()
        if not domain:
            return "Error: domain is required."
        records = [parse_record(r) for r in await fetch_certs(
            domain, bool(arguments.get("exclude_expired")), _to_int(arguments.get("max_results"), 50))]
        return format_records(f"CT log entries for '{domain}'", records)

    if name == "get_subdomains":
        domain = (arguments.get("domain") or "").strip()
        if not domain:
            return "Error: domain is required."
        raw = await fetch_certs(f"%.{domain}")
        found: list[str] = []
        for r in raw:
            for n in valid_domains(parse_record(r)["names"]):
                if n != domain and n.endswith("." + domain) and n not in found:
                    found.append(n)
        found.sort()
        lines = [f"## Subdomains seen in CT logs for '{domain}' ({len(found)} found)", ""]
        lines.extend(found[:200])
        if not found:
            lines.append("No subdomains found in logged certificates.")
        return "\n".join(lines)

    if name == "get_issuers":
        domain = (arguments.get("domain") or "").strip()
        if not domain:
            return "Error: domain is required."
        records = [parse_record(r) for r in await fetch_certs(domain)]
        counts: dict[str, int] = {}
        for r in records:
            counts[r["issuer"]] = counts.get(r["issuer"], 0) + 1
        lines = [f"## Issuing CAs for '{domain}' ({len(counts)} distinct)", ""]
        for issuer, n in sorted(counts.items(), key=lambda kv: -kv[1]):
            lines.append(f"{n:4d}  {issuer}")
        if not counts:
            lines.append("No certificates found.")
        return "\n".join(lines)

    if name == "get_certificate":
        cert_id = (arguments.get("cert_id") or "").strip()
        if not re.fullmatch(r"\d+", cert_id):
            return "Error: cert_id must be a numeric crt.sh log id."
        async with httpx.AsyncClient(timeout=TIMEOUT, headers={"User-Agent": USER_AGENT}, follow_redirects=True) as client:
            r = await client.get(f"{BASE_URL}/", params={"id": cert_id})
            r.raise_for_status()
            ctype = r.headers.get("content-type", "")
        if "json" in ctype:
            data = json.loads(r.text)
            if isinstance(data, list) and data:
                return format_records(f"Certificate log {cert_id}", [parse_record(data[0])])
            return f"No log entry {cert_id} found."
        cert = parse_cert_page(r.text, cert_id)
        if not (cert["subject"] or cert["issuer"] or cert["names"]):
            return f"No log entry {cert_id} found."
        return format_cert_page(cert)

    if name == "get_expiring_certs":
        domain = (arguments.get("domain") or "").strip()
        if not domain:
            return "Error: domain is required."
        days = _to_int(arguments.get("days"), 30)
        now = datetime.now(timezone.utc)
        horizon = now + timedelta(days=days)
        soon = []
        for r in (parse_record(x) for x in await fetch_certs(domain)):
            end = _parse_dt(r["not_after"])
            if end and now <= end <= horizon:
                soon.append(r)
        return format_records(f"'{domain}' certs expiring within {days} days", soon)

    if name == "get_expired_certs":
        domain = (arguments.get("domain") or "").strip()
        if not domain:
            return "Error: domain is required."
        now = datetime.now(timezone.utc)
        expired = []
        for r in (parse_record(x) for x in await fetch_certs(domain)):
            end = _parse_dt(r["not_after"])
            if end and end < now:
                expired.append(r)
        return format_records(f"Expired CT log entries for '{domain}'", expired, show_names=False)

    if name == "get_cert_history":
        domain = (arguments.get("domain") or "").strip()
        if not domain:
            return "Error: domain is required."
        records = [parse_record(r) for r in await fetch_certs(domain)]
        if not records:
            return f"No certificates logged for '{domain}'."
        dates = sorted(d for d in (_parse_dt(r["not_before"]) for r in records) if d)
        issuers: dict[str, int] = {}
        for r in records:
            issuers[r["issuer"]] = issuers.get(r["issuer"], 0) + 1
        names = set()
        for r in records:
            names.update(valid_domains(r["names"]))
        top_issuers = sorted(issuers.items(), key=lambda kv: -kv[1])[:5]
        lines = [
            f"## CT history for '{domain}'",
            "",
            f"- Total logged entries: {len(records)}",
            f"- First certificate seen: {dates[0].date().isoformat()}",
            f"- Most recent: {dates[-1].date().isoformat()}",
            f"- Unique DNS names: {len(names)}",
            f"- Distinct issuing CAs: {len(issuers)}",
            "- Top issuers: " + ", ".join(f"{i} ({n})" for i, n in top_issuers),
        ]
        return "\n".join(lines)

    if name == "get_wildcard_certs":
        domain = (arguments.get("domain") or "").strip()
        if not domain:
            return "Error: domain is required."
        wild = [r for r in (parse_record(x) for x in await fetch_certs(f"%.{domain}"))
                if any(n.startswith("*.") for n in r["names"])]
        return format_records(f"Wildcard certificates covering '*.{domain}'", wild)

    return f"Unknown tool: {name}"


def _to_int(value, default: int) -> int:
    try:
        return max(1, min(int(value), 200))
    except (TypeError, ValueError):
        return default


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    try:
        text = await call_tool_implementation(name, arguments or {})
    except httpx.HTTPStatusError as e:
        text = f"HTTP error: {e.response.status_code} {e.response.reason_phrase}"
    except ValueError as e:
        text = f"Error: {e}"
    except Exception as e:
        text = f"Error: {type(e).__name__}: {e}"
    return [TextContent(type="text", text=text)]


async def _serve_stdio() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


def build_sse_app(message_path: str = "/messages/", sse_path: str = "/sse") -> Starlette:
    """Serve the MCP server over SSE (for remote clients)."""
    sse = SseServerTransport(message_path)

    async def handle_sse(request):
        async with sse.connect_sse(request.scope, request.receive, request._send) as streams:
            await app.run(streams[0], streams[1], app.create_initialization_options())

    return Starlette(
        routes=[Route(sse_path, handle_sse), Mount(message_path, app=sse.handle_post_message)],
    )


def build_streamable_http_app(mount_path: str = "/mcp") -> Starlette:
    """Serve the MCP server over Streamable HTTP (for remote clients)."""
    manager = StreamableHTTPSessionManager(app=app)

    async def handle_streamable_http(request):
        await manager.handle_request(request.scope, request.receive, request._send)

    return Starlette(
        routes=[Mount(mount_path, app=handle_streamable_http)],
        lifespan=lambda s: manager.run(),
    )


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="crtsh-mcp: crt.sh certificate transparency MCP server")
    parser.add_argument("--sse", action="store_true", help="serve over SSE instead of stdio")
    parser.add_argument("--http", action="store_true", help="serve over streamable HTTP instead of stdio")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    if args.http:
        import uvicorn

        uvicorn.run(build_streamable_http_app(), host=args.host, port=args.port)
    elif args.sse:
        import uvicorn

        uvicorn.run(build_sse_app(), host=args.host, port=args.port)
    else:
        asyncio.run(_serve_stdio())


if __name__ == "__main__":
    main()
