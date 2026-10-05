"""metasploit_mcp — hardened Metasploit Framework (msfrpcd) RPC client + helpers.

Library used by the ``metasploit`` MCP server (``server.py``). Wire protocol
is msgpack over HTTP POST (Metasploit RPC). The client speaks both the
legacy v1 encoding (HTTP 200 + ``["success", ...]`` / ``["error", msg, ...]``
arrays) and the modern v10 encoding (HTTP 200 + result maps, HTTP 4xx/5xx +
``{"error": true, ...}`` maps) so it works against old and new metasploit
framework installations alike.
"""

__version__ = "0.1.0"
