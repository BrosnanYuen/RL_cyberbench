#!/usr/bin/env python3
"""nmap XML (-oX) -> markdown digest for LLM agents.

Reads an nmap XML output file and renders a compact markdown digest:
scan metadata, hosts (status / OS guess / ports + service+version), and every
NSE script output verbatim in fenced code blocks. stdlib ``xml.etree`` only.

Usage: parse_nmap_xml.py <scan.xml> [-o digest.md]
"""

from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


class NmapXmlError(ValueError):
    """Raised when the input is not a parseable nmap XML document."""


def _fence_for(text: str) -> str:
    """Return a code fence longer than any backtick run inside *text*."""
    longest = 0
    run = 0
    for ch in text:
        if ch == "`":
            run += 1
            longest = max(longest, run)
        else:
            run = 0
    return "`" * max(3, longest + 1)


def _service_cell(service: ET.Element | None) -> str:
    if service is None:
        return ""
    name = service.get("name", "")
    tunnel = service.get("tunnel", "")
    full_name = f"{tunnel}/{name}" if tunnel and name else (name or tunnel)
    product = service.get("product", "")
    version = service.get("version", "")
    pv = " ".join(p for p in (product, version) if p)
    extra = service.get("extrainfo", "")
    if extra:
        pv = f"{pv} ({extra})" if pv else f"({extra})"
    return " ".join(p for p in (full_name, pv) if p)


def _script_block(script: ET.Element, level: int) -> list[str]:
    sid = script.get("id", "unknown-script")
    output = (script.get("output") or "").rstrip("\n")
    lines = [f"{'#' * (level + 1)} {sid}", ""]
    if output:
        fence = _fence_for(output)
        lines += [fence, output, fence, ""]
    else:
        lines += ["_no output_", ""]
    return lines


def _ports_md(ports: ET.Element) -> list[str]:
    rows: list[str] = []
    sections: list[str] = []
    open_count = 0
    for port in ports.findall("port"):
        portid = port.get("portid", "?")
        proto = port.get("protocol", "?")
        state_el = port.find("state")
        state = state_el.get("state", "?") if state_el is not None else "?"
        if state == "open":
            open_count += 1
        service = _service_cell(port.find("service"))
        rows.append(f"| {portid} | {proto} | {state} | {service} |")
        scripts = port.findall("script")
        if scripts:
            sections.append(f"### Port {portid}/{proto} — script results")
            sections.append("")
            for script in scripts:
                sections += _script_block(script, 3)

    extra = ports.find("extraports")
    if not rows and extra is None:
        return []

    lines = [
        f"**Open ports: {open_count}**",
        "",
        "| Port | Proto | State | Service / Version |",
        "|---|---|---|---|",
    ]
    lines += rows
    if extra is not None:
        count = extra.get("count", "?")
        reason = extra.get("state", "filtered")
        lines.append(f"| … | … | _{reason} ({count} ports)_ | |")
    lines.append("")
    return lines + sections


def _host_md(host: ET.Element) -> list[str]:
    addrs = host.findall("address")
    ipv4 = next((a.get("addr") for a in addrs if a.get("addrtype") == "ipv4"), None)
    ipv6 = next((a.get("addr") for a in addrs if a.get("addrtype") == "ipv6"), None)
    mac = next((a for a in addrs if a.get("addrtype") == "mac"), None)
    names = [h.get("name") for h in host.findall("hostnames/hostname") if h.get("name")]
    label = ipv4 or ipv6 or "unknown-host"
    if names:
        label = f"{label} ({names[0]})"

    lines = [f"## Host {label}", ""]
    status_el = host.find("status")
    if status_el is not None:
        reason = status_el.get("reason", "")
        lines += [
            f"Status: **{status_el.get('state', '?')}**"
            + (f" ({reason})" if reason else ""),
            "",
        ]

    if mac is not None:
        mac_line = f"MAC: {mac.get('addr')}"
        vendor = mac.get("vendor")
        if vendor:
            mac_line += f" ({vendor})"
        lines += [mac_line, ""]

    os_el = host.find("os")
    if os_el is not None:
        matches = os_el.findall("osmatch")
        for m in matches[:3]:
            lines += [f"OS guess: {m.get('name')} ({m.get('accuracy')}%)"]
        if matches:
            lines.append("")

    ports_el = host.find("ports")
    if ports_el is not None:
        lines += _ports_md(ports_el)

    host_scripts = host.findall("hostscript/script")
    if host_scripts:
        lines += ["### Host script results", ""]
        for script in host_scripts:
            lines += _script_block(script, 3)
    return lines


def digest_md(xml_path: Path) -> str:
    """Render *xml_path* (nmap -oX output) as a markdown digest string."""
    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError as e:
        msg = f"invalid XML: {e}"
        raise NmapXmlError(msg) from e
    if root.tag != "nmaprun":
        msg = f"not an nmap XML file (root element <{root.tag}>)"
        raise NmapXmlError(msg)

    lines = [f"# nmap scan digest — {xml_path.name}", ""]

    args = root.get("args", "")
    if args:
        lines += [f"- **Command**: `{args}`"]
    if root.get("version"):
        lines += [f"- **Nmap version**: {root.get('version')}"]
    if root.get("startstr"):
        lines += [f"- **Started**: {root.get('startstr')}"]

    finished = root.find("runstats/finished")
    if finished is not None:
        elapsed = finished.get("elapsed", "")
        if elapsed:
            lines += [f"- **Elapsed**: {elapsed}s"]
    stats = root.find("runstats/hosts")
    if stats is not None:
        lines += [
            f"- **Hosts**: {stats.get('up', '?')} up, {stats.get('down', '?')} down"
        ]
    if len(lines) > 2:
        lines.append("")

    for tag, title in (
        ("prescript", "Pre-scan scripts"),
        ("postscript", "Post-scan scripts"),
    ):
        scripts = root.findall(f"{tag}/script")
        if scripts:
            lines += [f"## {title}", ""]
            for script in scripts:
                lines += _script_block(script, 2)

    hosts = root.findall("host")
    if not hosts:
        lines += ["No hosts reported.", ""]
    for host in hosts:
        lines += _host_md(host)

    return "\n".join(lines).rstrip() + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="parse_nmap_xml",
        description="Convert nmap -oX XML output to a markdown digest.",
    )
    parser.add_argument("xml", type=Path, help="nmap XML file (-oX output)")
    parser.add_argument(
        "-o",
        "--out",
        type=Path,
        default=None,
        help="write digest here (default: stdout)",
    )
    opts = parser.parse_args(argv)

    if not opts.xml.is_file():
        print(f"parse_nmap_xml: file not found: {opts.xml}", file=sys.stderr)
        return 1
    try:
        md = digest_md(opts.xml)
    except NmapXmlError as e:
        print(f"parse_nmap_xml: {e}", file=sys.stderr)
        return 2

    if opts.out is None:
        sys.stdout.write(md)
    else:
        opts.out.parent.mkdir(parents=True, exist_ok=True)
        opts.out.write_text(md, encoding="utf-8")
        print(f"wrote {opts.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
