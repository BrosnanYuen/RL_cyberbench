#!/usr/bin/env python3
"""Backward-compat shim: the MCP server now lives in :mod:`metasploit_mcp.server`.

Kept so ``python server.py`` / ``uv run mcp dev server.py`` keep working from
this directory. The installed entry point is ``msf-mcp-server`` ->
``metasploit_mcp.server:main``; the old top-level ``server`` module name
collided with the pcap2md package's ``server`` module in shared venvs
(whichever editable install won silently served the wrong tools).
"""

from metasploit_mcp.server import main, mcp

__all__ = ["main", "mcp"]

if __name__ == "__main__":
    main()
