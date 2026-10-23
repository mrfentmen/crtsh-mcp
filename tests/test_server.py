import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import server

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def load(name: str):
    return json.loads((FIXTURES / name).read_text())


def test_list_tools_exposes_all_tools():
    names = {t[0] for t in server.LIST_TOOLS_SPEC}
    assert names == {
        "search_certificates",
        "get_subdomains",
        "get_issuers",
        "get_certificate",
        "get_expiring_certs",
        "get_expired_certs",
        "get_cert_history",
        "get_wildcard_certs",
    }


def test_parse_record_fixture():
    raw = load("certs.json")
    assert raw
    rec = server.parse_record(raw[0])
    assert rec["id"]
    assert rec["common_name"]
    assert "example.com" in rec["names"]
    assert rec["not_before"] and rec["not_after"]
    assert rec["issuer"]


def test_valid_domains_drops_wildcards_and_junk():
    names = ["*.example.com", "example.com", "api.example.com", "", "not a domain"]
    assert server.valid_domains(names) == ["example.com", "api.example.com"]


def test_valid_domains_dedupes():
    assert server.valid_domains(["a.com", "a.com", "b.com"]) == ["a.com", "b.com"]


def test_format_records_header_and_count():
    recs = [server.parse_record(r) for r in load("certs.json")[:2]]
    out = server.format_records("test", recs)
    assert out.startswith("## test (2 shown)")
    assert "issuer:" in out


def test_format_records_empty():
    assert "No certificates found." in server.format_records("empty", [])


def test_parse_dt():
    assert server._parse_dt("2026-09-26T22:49:11") is not None
    assert server._parse_dt("garbage") is None
    assert server._parse_dt("") is None


def test_to_int_bounds():
    assert server._to_int("10", 50) == 10
    assert server._to_int(None, 50) == 50
    assert server._to_int("999", 50) == 200  # clamped
    assert server._to_int("0", 50) == 1


# ----- cert detail page (HTML) parsing -------------------------------------------


def test_parse_cert_page_fixture():
    html = (FIXTURES / "cert_page.html").read_text(encoding="utf-8", errors="replace")
    cert = server.parse_cert_page(html, "29581274041")
    assert cert["id"] == 29581274041
    assert cert["subject"].get("commonName") == "example.com"
    assert cert["issuer"].get("commonName")
    assert "example.com" in cert["names"]
    assert any(n.startswith("*.") for n in cert["names"])
    assert cert["not_before"] and "GMT" in cert["not_before"]
    assert cert["not_after"] and "GMT" in cert["not_after"]
    assert cert["serial_number"]
    assert cert["signature_algorithm"]
    assert cert["ct_logs"]
    assert cert["log_entries"]


def test_format_cert_page():
    html = (FIXTURES / "cert_page.html").read_text(encoding="utf-8", errors="replace")
    out = server.format_cert_page(server.parse_cert_page(html, "29581274041"))
    assert out.startswith("## Certificate log 29581274041")
    assert "Subject CN:" in out


def test_parse_cert_page_garbage_returns_empty_fields():
    cert = server.parse_cert_page("<html>nothing here</html>", "123")
    assert cert["names"] == []
    assert cert["subject"] == {}


# ----- transports (smoke tests) -------------------------------------------------


def test_build_sse_app_routes():
    app_ = server.build_sse_app(sse_path="/sse", message_path="/messages/")
    paths = {getattr(r, "path", None) for r in app_.routes}
    assert "/sse" in paths


def test_build_streamable_http_app_routes():
    app_ = server.build_streamable_http_app(mount_path="/mcp")
    assert any(getattr(r, "path", "").startswith("/mcp") for r in app_.routes)


def test_main_stdio_dispatch(monkeypatch):
    called = {}

    def fake_run(coro):
        called["ran"] = True
        coro.close()

    monkeypatch.setattr(server.asyncio, "run", fake_run)
    monkeypatch.setattr("sys.argv", ["crtsh-mcp"])
    server.main()
    assert called["ran"]
