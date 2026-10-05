#!/usr/bin/env python3
"""Backward-compat shim: the MCP server now lives in :mod:`pcap_to_md.server`.

Kept so ``python server.py`` / ``uv run mcp dev server.py`` keep working from
this directory. The installed entry point is ``pcap2md-server`` ->
``pcap_to_md.server:main``; the old top-level ``server`` module name collided
with the metasploit package's ``server`` module in shared venvs (whichever
editable install won silently served the wrong tools).
"""

from pcap_to_md.server import main, mcp

__all__ = ["main", "mcp"]

if __name__ == "__main__":
    main()
