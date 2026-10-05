"""pcap_to_md — convert pcap/tcpdump capture files to Markdown.

Library used by the ``pcap2md`` CLI and the ``pcap2md`` MCP server.
All external processes are run through :mod:`pcap_to_md.tshark_runner`
(a hardened asyncio wrapper around ``tshark``/``capinfos``).
"""

__version__ = "0.1.0"
