"""
OSINT MCP Client

A Model Context Protocol client that connects to the OSINT MCP server
and orchestrates queries using Claude.

This client:
1. Connects to the MCP server
2. Discovers available tools
3. Processes user queries using Claude
4. Executes tool calls and returns results
5. Provides real-time progress updates via callbacks

Usage:
    client = OSINTMCPClient()
    await client.connect()
    result = await client.process_query("Find accounts for john_doe")
    await client.disconnect()
"""

import asyncio
import json
import httpx
from typing import Optional, Callable, Any
from contextlib import AsyncExitStack
from dataclasses import dataclass, field

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client
from anthropic import Anthropic

import os
from dotenv import load_dotenv

load_dotenv()

# Per-server connection timeout. One slow/unavailable server (e.g. npx not
# installed in the production container) must never block the whole runtime.
_SERVER_CONNECT_TIMEOUT = 30.0

@dataclass
class ServerConfig:
    """Configuration for an MCP server connection."""
    name: str
    server_type: str  # "stdio", or "http"
    # For stdio
    script_path: Optional[str] = None
    command: Optional[str] = None  # e.g., "python", "npx", "node"
    args: Optional[list[str]] = None  # e.g., ["-y", "@burtthecoder/mcp-shodan"]
    # For SSE/HTTP
    url: Optional[str] = None
    headers: Optional[dict] = None
    # For environment variables passed to stdio subprocess
    env: Optional[dict[str, str]] = None
    description: str = ""
    enabled: bool = True

@dataclass
class ProgressUpdate:
    """Represents a progress update during query processing."""
    stage: str 
    message: str
    details: Optional[dict] = None
    progress_percent: Optional[int] = None

@dataclass 
class QueryResult:
    """Result of processing a query."""
    success: bool
    action: Optional[str] = None
    params: Optional[dict] = None
    raw_results: Optional[dict] = None
    formatted_response: Optional[str] = None
    error: Optional[str] = None
    tool_calls_made: list = field(default_factory=list)
    server_used: Optional[str] = None
    answer_source: Optional[str] = None


class MCPServerConnection:
    """Manages a single MCP server connection."""
    
    def __init__(self, config: ServerConfig, exit_stack: AsyncExitStack = None):
        self.config = config
        # Kept as an attribute for backwards compatibility; actual resources
        # are registered on our own per-connection stack.
        self._shared_exit_stack = exit_stack
        self.exit_stack = AsyncExitStack()
        self.session: Optional[ClientSession] = None
        self.tools: list[dict] = []
        self.connected = False

    async def disconnect(self) -> None:
        """Tear down this connection. Safe to call when not connected.

        We swallow the "cancel scope" RuntimeError that anyio raises when
        an MCP transport's internal task group is closed in a task other
        than the one it was opened in. This is a known cosmetic issue
        with AsyncExitStack + anyio — the underlying resources do close,
        the error is just noisy.
        """
        try:
            await self.exit_stack.aclose()
        except RuntimeError as e:
            msg = str(e).lower()
            if "cancel scope" in msg or "different task" in msg:
                # Known cosmetic anyio issue; resources still released.
                pass
            else:
                print(f"[{self.config.name}] Error during disconnect: {e}")
        except Exception as e:
            print(f"[{self.config.name}] Error during disconnect: {e}")
        self.session = None
        self.tools = []
        self.connected = False
        self.exit_stack = AsyncExitStack()
    
    async def connect(self) -> bool:
        """Connect to this MCP server."""
        try:
            if self.config.server_type == "stdio":
                # Local server via stdio
                if self.config.command and self.config.args:
                    # Custom command (e.g., npx for Shodan)
                    cmd = self.config.command
                    args = self.config.args
                elif self.config.script_path:
                    # Python script (default)
                    cmd = "python"
                    args = [self.config.script_path]
                else:
                    raise ValueError(f"Server {self.config.name}: script_path or command+args required for stdio")
                
                # Build env dict if needed (for API keys etc.)
                import os as _os
                env = dict(_os.environ)
                if self.config.env:
                    env.update(self.config.env)
                
                server_params = StdioServerParameters(
                    command=cmd,
                    args=args,
                    env=env
                )
                
                stdio_transport = await self.exit_stack.enter_async_context(
                    stdio_client(server_params)
                )
                read_stream, write_stream = stdio_transport
                
                
            elif self.config.server_type == "http":
                # HTTP-based MCP using Streamable HTTP transport
                if not self.config.url:
                    raise ValueError(f"Server {self.config.name}: url required for http")
                
                # Create httpx client with headers
                http_client = httpx.AsyncClient(
                    headers=self.config.headers or {},
                    timeout=httpx.Timeout(30.0, read=300.0)
                )
                
                http_transport = await self.exit_stack.enter_async_context(
                    streamable_http_client(
                        url=self.config.url,
                        http_client=http_client
                    )
                )
                read_stream, write_stream, _ = http_transport
            else:
                raise ValueError(f"Unknown server type: {self.config.server_type}")
            
            # Create and initialize session
            self.session = await self.exit_stack.enter_async_context(
                ClientSession(read_stream, write_stream)
            )
            await self.session.initialize()
            
            # Discover tools
            tools_response = await self.session.list_tools()
            self.tools = [
                {
                    "name": tool.name,
                    "description": tool.description,
                    "input_schema": tool.inputSchema,
                    "server": self.config.name  # Track which server owns this tool
                }
                for tool in tools_response.tools
            ]
            
            self.connected = True
            return True
            
        except Exception as e:
            print(f"[{self.config.name}] Connection failed: {e}")
            self.connected = False
            return False
    
    async def call_tool(self, tool_name: str, arguments: dict) -> Any:
        """Call a tool on this server."""
        if not self.connected or not self.session:
            raise RuntimeError(f"Server {self.config.name} not connected")
        return await self.session.call_tool(tool_name, arguments)


class OSINTMCPClient:
    """
    MCP Client for OSINT research tools.
    
    Connects to an MCP server, discovers tools, and uses Claude
    to process natural language queries into tool calls.
    """

    def __init__(
        self,
        servers: Optional[list[ServerConfig]] = None,
        progress_callback: Optional[Callable[[ProgressUpdate], None]] = None,
        # Legacy single-server support
        server_script_path: Optional[str] = None,
        sse_url: Optional[str] = None,
    ):
        """
        Initialize the MCP client.
        
        Args:
            servers: List of ServerConfig objects defining MCP servers to connect to
            progress_callback: Optional callback for progress updates
            server_script_path: (Legacy) Path to single MCP server script
            sse_url: (Legacy) URL of single SSE MCP server
        """
        self.progress_callback = progress_callback
        self.exit_stack = AsyncExitStack()
        self.anthropic = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
        
        # Build server list
        self.servers: list[ServerConfig] = []
        
        if servers:
            self.servers = [s for s in servers if s.enabled]
        else:
            # Legacy: single server mode
            if server_script_path:
                self.servers.append(ServerConfig(
                    name="local",
                    server_type="stdio",
                    script_path=server_script_path,
                    description="Local OSINT server"
                ))
            elif sse_url:
                self.servers.append(ServerConfig(
                    name="local",
                    server_type="sse",
                    url=sse_url,
                    description="Local OSINT server"
                ))
        
        self._connections: dict[str, MCPServerConnection] = {}
        self._tool_to_server: dict[str, str] = {}  # Maps tool name -> server name
        self._all_tools: list[dict] = []
        self._connected = False

        self._whoisxml_backup_attempted = False

    def _emit_progress(self, stage: str, message: str, details: dict = None, progress: int = None):
        """Emit a progress update if callback is set."""
        if self.progress_callback:
            update = ProgressUpdate(
                stage=stage,
                message=message,
                details=details,
                progress_percent=progress
            )
            self.progress_callback(update)

    @staticmethod
    def _is_shodan_reverse_dns_tool(tool_name: str) -> bool:
        """Return True for known Shodan reverse-DNS tool names/aliases."""
        return tool_name in {
            "reverse_dns_lookup",
            "reverse-dns",
            "shodan_reverse_dns",
        }

    @staticmethod
    def _normalize_ip_list(value: Any) -> list[str]:
        """Normalize MCP/registry IP list variants to a non-empty string list."""
        if isinstance(value, str):
            ips = [part.strip() for part in value.split(",")]
        elif isinstance(value, list):
            ips = [str(part).strip() for part in value]
        else:
            ips = []
        return [ip for ip in ips if ip]

    async def _call_shodan_reverse_dns_direct(self, arguments: dict) -> dict:
        """Direct fallback for @burtthecoder/mcp-shodan reverse DNS.

        Version 1.0.22 assumes every Shodan response value is a list and
        crashes when the API returns null for an IP with no hostnames.
        """
        ips = self._normalize_ip_list(arguments.get("ips"))
        if not ips:
            raise ValueError("Missing required argument: ips")

        api_key = os.getenv("SHODAN_API_KEY")
        if not api_key:
            raise RuntimeError("SHODAN_API_KEY environment variable is required.")

        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.get(
                "https://api.shodan.io/dns/reverse",
                params={"ips": ",".join(ips), "key": api_key},
            )
            response.raise_for_status()
            raw_result = response.json()

        if not isinstance(raw_result, dict):
            raise RuntimeError("Unexpected Shodan reverse DNS response format.")

        resolutions = []
        ips_with_results = 0
        for ip in ips:
            hostnames = raw_result.get(ip)
            if isinstance(hostnames, list) and hostnames:
                display_hostnames = hostnames
                ips_with_results += 1
            else:
                display_hostnames = ["No hostnames found"]

            resolutions.append({
                "IP Address": ip,
                "Hostnames": display_hostnames,
            })

        return {
            "Reverse DNS Resolutions": resolutions,
            "Summary": {
                "Total IPs Queried": len(ips),
                "IPs with Results": ips_with_results,
                "Queried IP Addresses": ips,
            },
        }

    async def _connect_one(
        self, config: ServerConfig
    ) -> "tuple[str, MCPServerConnection | None]":
        """Connect to one MCP server with a per-server timeout.

        Returns (name, connection) on success, (name, None) on any failure
        so callers can use asyncio.gather() without catching exceptions.
        """
        self._emit_progress("connecting", f"Connecting to {config.name}...", {"server": config.name})
        connection = MCPServerConnection(config)
        try:
            success = await asyncio.wait_for(
                connection.connect(),
                timeout=_SERVER_CONNECT_TIMEOUT,
            )
            if success:
                return config.name, connection
            # connect() returned False — already printed inside
            try:
                await connection.disconnect()
            except Exception:
                pass
            return config.name, None
        except asyncio.TimeoutError:
            print(
                f"[{config.name}] Connection timed out after "
                f"{_SERVER_CONNECT_TIMEOUT:.0f}s — skipping"
            )
            try:
                await connection.disconnect()
            except Exception:
                pass
            return config.name, None
        except Exception as exc:
            print(f"[{config.name}] Connection error: {exc} — skipping")
            try:
                await connection.disconnect()
            except Exception:
                pass
            return config.name, None

    async def connect(self, target_servers: list[str] | None = None) -> bool:
        """
        Connect to configured MCP servers and discover tools.

        Servers are connected concurrently so one slow or missing server
        (e.g. npx not installed in the production container) never blocks
        the rest. Each individual connection has a _SERVER_CONNECT_TIMEOUT
        deadline before it is skipped.

        Args:
            target_servers: If provided, only connect to these servers by name.
                           If None, connect to all configured servers.
        """
        if not self.servers:
            self._emit_progress("error", "No MCP servers configured")
            return False

        # Filter servers if target_servers specified
        if target_servers:
            servers_to_connect = [s for s in self.servers if s.name in target_servers]
            if not servers_to_connect:
                self._emit_progress(
                    "error",
                    f"None of the target servers {target_servers} are configured"
                )
                return False
        else:
            servers_to_connect = self.servers

        try:
            self._emit_progress(
                "connecting",
                f"Connecting to {len(servers_to_connect)} MCP server(s)..."
            )

            # All connections run concurrently. Wall-clock time = slowest
            # individual server that succeeds (or _SERVER_CONNECT_TIMEOUT for
            # servers that hang/fail). This prevents one broken server from
            # blocking the whole runtime startup.
            results = await asyncio.gather(
                *[self._connect_one(config) for config in servers_to_connect]
            )

            connected_count = 0
            for name, connection in results:
                if connection is None:
                    continue
                self._connections[name] = connection
                connected_count += 1

                # Register tools from this server
                for tool in connection.tools:
                    tool_name = tool["name"]
                    if tool_name in self._tool_to_server:
                        original_server = self._tool_to_server[tool_name]
                        print(f"Warning: Tool '{tool_name}' exists on both "
                              f"'{original_server}' and '{name}'. "
                              f"Using version from '{original_server}'.")
                    else:
                        self._tool_to_server[tool_name] = name
                        self._all_tools.append(tool)

                print(f"[{name}] Connected - {len(connection.tools)} tools")

            if connected_count == 0:
                self._emit_progress("error", "Failed to connect to any MCP servers")
                return False

            self._connected = True
            self._emit_progress(
                "connected",
                f"Connected to {connected_count}/{len(servers_to_connect)} servers. "
                f"Discovered {len(self._all_tools)} tools.",
                {
                    "servers": list(self._connections.keys()),
                    "tools": [t["name"] for t in self._all_tools],
                }
            )

            return True

        except Exception as e:
            self._emit_progress("error", f"Connection failed: {str(e)}")
            return False

    async def disconnect(self):
        """Disconnect from all MCP servers.

        Each connection owns its own AsyncExitStack, so we tear them
        down individually rather than relying on a single shared stack.
        """
        if self._connected:
            for name, conn in list(self._connections.items()):
                try:
                    await conn.disconnect()
                except Exception as e:
                    print(f"Error disconnecting {name}: {e}")
            try:
                await self.exit_stack.aclose()
            except Exception:
                pass
            self._connected = False
            self._connections.clear()
            self._tool_to_server.clear()
            self._all_tools.clear()
            self._emit_progress("disconnected", "Disconnected from all MCP servers")
    
    def get_tools_for_claude(self) -> list[dict]:
        """
        Convert all MCP tools to Claude's tool format.
        
        Returns:
            List of tools in Claude's expected format
        """
        return [
            {
                "name": tool["name"],
                "description": tool["description"],
                "input_schema": tool["input_schema"]
            }
            for tool in self._all_tools
        ]
    
    def get_server_for_tool(self, tool_name: str) -> Optional[str]:
        """Get the server name that owns a specific tool."""
        return self._tool_to_server.get(tool_name)

    # Patterns that indicate a WhoisXML auth or rate-limit failure.
    # Matched case-insensitively against the error string or raw result.
    _WHOISXML_KEY_FAILURE_MARKERS = (
        "unauthorized",
        "invalid api key",
        "invalid_api_key",
        "api key",
        "authentication",
        "rate limit",
        "rate_limit",
        "quota",
        "too many requests",
        "credit",
        "403",
        "429",
    )

    def _looks_like_whoisxml_key_failure(
        self,
        parsed: Any,
        is_error: bool,
        exception: Optional[BaseException] = None,
    ) -> bool:
        """Heuristic: does this tool call look like it failed because of
        the WhoisXML API key (bad credentials / rate limited / out of credits)?

        Covers both shapes of failure:
         - Tool returned an error-looking response body (is_error + parsed)
         - Tool call raised an exception (exception is not None)

        We keep this broad on purpose — false positives just trigger one
        extra retry with the backup key, which is cheap. False negatives
        mean we burn the user's primary key on an error we could have
        worked around, which is worse.
        """
        blob = ""
        if is_error and isinstance(parsed, dict):
            for k in ("error", "message", "raw", "detail"):
                v = parsed.get(k)
                if v:
                    blob += f" {v}"
        elif is_error and parsed is not None:
            blob += f" {parsed}"
        if exception is not None:
            blob += f" {exception}"
        blob = blob.lower()
        if not blob.strip():
            return False
        return any(marker in blob for marker in self._WHOISXML_KEY_FAILURE_MARKERS)

    async def _reconnect_whoisxml_with_backup(self) -> bool:
        """Swap the whoisxml server to use WHOISXML_API_KEY_BACKUP.

        Returns True if the swap succeeded and whoisxml is usable again,
        False otherwise (backup key missing, connection failed, etc.).

        Only swaps once per client lifetime — sets
        self._whoisxml_backup_attempted so the same client won't try
        again even if the backup also fails.
        """
        if self._whoisxml_backup_attempted:
            return False
        self._whoisxml_backup_attempted = True

        backup_key = os.getenv("WHOISXML_API_KEY_BACKUP")
        if not backup_key:
            print("[whoisxml] Backup-key swap requested but WHOISXML_API_KEY_BACKUP not set")
            return False

        old_conn = self._connections.get("whoisxml")
        old_tools = [t["name"] for t in old_conn.tools] if old_conn else []

        self._emit_progress(
            "tool_call",
            "WhoisXML tool failed — swapping to backup API key and retrying...",
            {"reason": "whoisxml_key_failure"},
        )

        # Drop old whoisxml tools from the client's tool map
        for tname in old_tools:
            if self._tool_to_server.get(tname) == "whoisxml":
                self._tool_to_server.pop(tname, None)
        self._all_tools = [t for t in self._all_tools if t.get("server") != "whoisxml"]

        # Tear down the old connection (if any)
        if old_conn is not None:
            self._connections.pop("whoisxml", None)
            old_conn.connected = False

        # Build a fresh connection with the backup key
        new_config = ServerConfig(
            name="whoisxml",
            server_type="http",
            url="https://mcp-hosted.whoisxmlapi.com/mcp",
            headers={"Authorization": f"Bearer {backup_key}"},
            description="WhoisXML API (backup key)",
            enabled=True,
        )
        new_conn = MCPServerConnection(new_config)
        ok = await new_conn.connect()
        if not ok:
            print("[whoisxml] Backup-key reconnection failed")
            return False

        # Re-register tools
        self._connections["whoisxml"] = new_conn
        for tool in new_conn.tools:
            tname = tool["name"]
            if tname not in self._tool_to_server:
                self._tool_to_server[tname] = "whoisxml"
                self._all_tools.append(tool)

        print(f"[whoisxml] Reconnected with backup key — {len(new_conn.tools)} tools available")
        return True
    
    async def call_tool(self, tool_name: str, arguments: dict) -> Any:
        """
        Call a tool, automatically routing to the correct server.
        """
        server_name = self._tool_to_server.get(tool_name)
        if not server_name:
            raise ValueError(f"Unknown tool: {tool_name}")
        
        connection = self._connections.get(server_name)
        if not connection:
            raise RuntimeError(f"Server '{server_name}' not connected")
        
        return await connection.call_tool(tool_name, arguments)
    
    # Maximum number of tool-calling turns before the loop bails.
    # Each turn = one Claude call + zero-or-more tool executions.
    MAX_AGENT_TURNS = 8

    _PLANNER_SYSTEM_PROMPT = """You are an OSINT research assistant with access to specialized tools from multiple sources.

AVAILABLE TOOL CATEGORIES:

1. Username / Social Media (Local Server):
   - username_search: Find social media accounts across 600+ platforms

2. Domain Intelligence (WhoisXML API):
   - whois, whois_history, reverse_whois
   - dns_lookup, dns_history, reverse_dns, reverse_ip, reverse_mx, reverse_ns
   - subdomains_lookup

3. IP Intelligence (WhoisXML API):
   - ip_geolocation, ip_netblocks

4. Security & Verification (WhoisXML API):
   - threat_intelligence, ssl_certificates, email_verification, categorization

5. Network Reconnaissance (Shodan):
   - host, dns-lookup, reverse-dns, cve-lookup

6. Technology Detection (BuiltWith):
   - free-api, trends-api

RULES FOR TOOL USE:
- For technology stack lookups, ALWAYS use 'free-api', NEVER 'domain-api' or 'domain-lookup'.
- You may call multiple tools across multiple turns to answer complex queries.
- If the user's question needs several pieces of information, call tools one at a time, read the results, then decide what to call next.
- When you have enough information to fully answer the user's question, stop calling tools and respond with a final text answer.

RULES FOR WHEN NO TOOL FITS:
- If the user's query does not map to any available tool, DO NOT call a tool.
- Respond with plain text explaining what you cannot do and, if possible, what you CAN help with.
- Do NOT fabricate results. Do NOT guess. Do NOT call an unrelated tool as a consolation.

RULES FOR THE FINAL ANSWER:
- Be concise and factual.
- Only report data actually present in the tool results.
- Do NOT invent URLs, profile links, counts, dates, or identifiers.
- Do NOT include "Key Insights" or "Recommended Next Steps" sections.
- Do NOT give advice, recommendations, or suggested workarounds.
- Group related findings when presenting multiple tool results.
"""

    async def process_query(
        self,
        user_query: str,
        progress_callback: Optional[Callable[[ProgressUpdate], None]] = None,
        history: Optional[list[dict]] = None,
    ) -> QueryResult:
        """
        Process a natural language query using Claude and MCP tools.

        Agentic loop: Claude may call zero or more tools across multiple turns.
        Terminates when Claude responds with text only, when MAX_AGENT_TURNS
        is reached, or on error.

        Returns a QueryResult whose:
        - .action is the FIRST tool called (None if no tools were used)
        - .server_used is the server of the first tool (None if no tools)
        - .tool_calls_made is the full list of tool calls across all turns
        - .raw_results is {"tool_calls": [...]} with per-call details
        - .formatted_response is Claude's final text answer to the user
        """
        if not self._connected:
            return QueryResult(
                success=False,
                error="Not connected to any MCP servers. Call connect() first."
            )

        result = QueryResult(success=True, tool_calls_made=[])

        # Use a request-local callback. Mutating self.progress_callback here
        # races under concurrent team queries and can route progress events to
        # the wrong SSE stream.
        active_callback = progress_callback or self.progress_callback

        def emit_progress(stage: str, message: str, details: dict = None, progress: int = None):
            if active_callback:
                active_callback(ProgressUpdate(
                    stage=stage,
                    message=message,
                    details=details,
                    progress_percent=progress,
                ))

        try:
            try:
                emit_progress("parsing", "Analyzing your query...", progress=5)

                tools = self.get_tools_for_claude()
                messages: list[dict] = list(history) if history else []
                messages.append({"role": "user", "content": user_query})

                # Collect per-tool-call records here. Shape matches what views
                # will write into ToolCall rows.
                executed_calls: list[dict] = []

                final_text: Optional[str] = None
                turn = 0
                hit_cap = False

                while turn < self.MAX_AGENT_TURNS:
                    turn += 1
                    base_progress = 5 + int(85 * (turn - 1) / self.MAX_AGENT_TURNS)

                    emit_progress(
                        "planning",
                        f"Turn {turn}: deciding next step...",
                        {"turn": turn},
                        progress=base_progress,
                    )

                    response = await asyncio.to_thread(
                        self.anthropic.messages.create,
                        model="claude-sonnet-4-5-20250929",
                        max_tokens=2048,
                        system=self._PLANNER_SYSTEM_PROMPT,
                        tools=tools,
                        messages=messages,
                    )

                    # Collect all tool_use blocks from this turn (Claude may
                    # request several in parallel) and any text Claude emitted.
                    tool_uses = [b for b in response.content if b.type == "tool_use"]
                    text_blocks = [b.text for b in response.content if b.type == "text"]

                    # Always append the assistant turn to history — required
                    # so subsequent turns can reference prior tool_use IDs.
                    messages.append({"role": "assistant", "content": response.content})

                    # Terminal case: no tool calls. Claude is done (or refused).
                    if not tool_uses:
                        final_text = "\n\n".join(t for t in text_blocks if t).strip()
                        if not final_text:
                            final_text = "(No response from model.)"
                        break

                    # Execute each tool call on this turn and gather results
                    # as a single user-turn of tool_result blocks.
                    tool_result_blocks: list[dict] = []

                    for tu in tool_uses:
                        tool_name = tu.name
                        tool_args = tu.input or {}
                        server_name = self.get_server_for_tool(tool_name)

                        emit_progress(
                            "tool_call",
                            f"Calling {tool_name} on {server_name or '?'}...",
                            {
                                "turn": turn,
                                "tool": tool_name,
                                "server": server_name,
                                "args": tool_args,
                            },
                            progress=min(90, base_progress + 5),
                        )

                        call_record = {
                            "tool": tool_name,
                            "server": server_name,
                            "args": tool_args,
                            "success": False,
                            "result": None,
                            "error": None,
                        }

                        # Helper: execute the tool call and parse the result
                        # into (parsed, had_error, err_msg). Returns None for
                        # parsed if the call threw. Used twice: the initial
                        # attempt and the post-backup-swap retry.
                        async def _invoke_and_parse():
                            try:
                                if (
                                    server_name == "shodan"
                                    and self._is_shodan_reverse_dns_tool(tool_name)
                                ):
                                    _parsed = await self._call_shodan_reverse_dns_direct(tool_args)
                                    return _parsed, False, None, None

                                _mcp_result = await self.call_tool(tool_name, tool_args)
                                _parsed: Any = None
                                if _mcp_result.content and len(_mcp_result.content) > 0:
                                    _raw_text = _mcp_result.content[0].text
                                    try:
                                        _parsed = json.loads(_raw_text)
                                    except json.JSONDecodeError:
                                        _parsed = {"raw": _raw_text}
                                _had_error = bool(_mcp_result.isError)
                                _err_msg: Optional[str] = None
                                if isinstance(_parsed, dict) and _parsed.get("error"):
                                    _had_error = True
                                    _err_msg = _parsed.get("error")
                                return _parsed, _had_error, _err_msg, None
                            except Exception as _exc:
                                return None, True, f"Tool call failed: {_exc}", _exc

                        parsed, had_error, err_msg, raised = await _invoke_and_parse()

                        # WhoisXML backup-key retry: if this was a whoisxml
                        # tool that failed with what looks like an auth or
                        # rate-limit problem, swap to the backup key and
                        # retry this call exactly once. Swap happens at most
                        # once per client lifetime — see the flag inside
                        # _reconnect_whoisxml_with_backup.
                        if (
                            server_name == "whoisxml"
                            and not self._whoisxml_backup_attempted
                            and self._looks_like_whoisxml_key_failure(parsed, had_error, raised)
                        ):
                            swapped = await self._reconnect_whoisxml_with_backup()
                            if swapped:
                                parsed, had_error, err_msg, raised = await _invoke_and_parse()

                        call_record["result"] = parsed
                        call_record["success"] = not had_error
                        call_record["error"] = err_msg

                        # Feed the result back to Claude as a tool_result
                        tool_result_blocks.append({
                            "type": "tool_result",
                            "tool_use_id": tu.id,
                            "content": (
                                json.dumps(parsed)
                                if parsed is not None
                                else json.dumps({"error": err_msg or "Unknown error"})
                            ),
                            "is_error": had_error,
                        })

                        executed_calls.append(call_record)
                        result.tool_calls_made.append(call_record)

                        emit_progress(
                            "tool_complete",
                            f"{tool_name}: {'ok' if call_record['success'] else 'failed'}",
                            {
                                "turn": turn,
                                "tool": tool_name,
                                "server": server_name,
                                "success": call_record["success"],
                                "error": call_record["error"],
                            },
                            progress=min(92, base_progress + 8),
                        )

                    # Append all tool results as a single user turn
                    messages.append({"role": "user", "content": tool_result_blocks})

                    # Loop continues: Claude now sees the tool results and
                    # decides whether to call more tools or answer.

                else:
                    # while-else: only runs if we hit MAX_AGENT_TURNS without breaking
                    hit_cap = True
                    emit_progress(
                        "summarizing",
                        (
                            f"Reached {self.MAX_AGENT_TURNS} tool-calling turns; "
                            "summarizing findings gathered so far..."
                        ),
                        {"turns": turn, "tool_calls": len(executed_calls)},
                        progress=95,
                    )
                    messages.append({
                        "role": "user",
                        "content": (
                            f"The agent has reached the {self.MAX_AGENT_TURNS}-turn "
                            "tool-calling limit. Do not call any more tools. Provide "
                            "a concise final response that summarizes what was found, "
                            "the steps/tools used in order, any partial failures, and "
                            "what remains uncertain."
                        ),
                    })
                    try:
                        summary_response = await asyncio.to_thread(
                            self.anthropic.messages.create,
                            model="claude-sonnet-4-5-20250929",
                            max_tokens=2048,
                            system=(
                                "You are an OSINT research assistant. The tool-calling "
                                "limit has been reached, so you must answer from the "
                                "conversation and tool results already provided. Do not "
                                "request additional tools. Be explicit about partial "
                                "findings, steps taken, failed calls, and uncertainty."
                            ),
                            messages=messages,
                        )
                        final_text = "\n\n".join(
                            b.text for b in summary_response.content
                            if getattr(b, "type", None) == "text" and getattr(b, "text", "")
                        ).strip()
                    except Exception:
                        final_text = ""

                    if not final_text:
                        steps = [
                            c.get("tool", "unknown")
                            for c in executed_calls
                            if c.get("tool")
                        ]
                        successful = [c for c in executed_calls if c.get("success")]
                        failed = [c for c in executed_calls if not c.get("success")]
                        lines = [
                            (
                                f"The agent reached the {self.MAX_AGENT_TURNS}-turn "
                                "tool-calling limit before fully converging."
                            ),
                        ]
                        if steps:
                            lines.append("Steps taken: " + " -> ".join(steps) + ".")
                        lines.append(
                            f"Tool calls completed: {len(successful)} succeeded, "
                            f"{len(failed)} failed."
                        )
                        if successful:
                            lines.append("Findings gathered so far:")
                            for call in successful[:5]:
                                lines.append(
                                    f"- {call.get('tool', 'unknown')}: "
                                    f"{json.dumps(call.get('result'), default=str)[:700]}"
                                )
                        if failed:
                            lines.append("Partial failures:")
                            for call in failed[:5]:
                                lines.append(
                                    f"- {call.get('tool', 'unknown')}: "
                                    f"{call.get('error') or 'unknown error'}"
                                )
                        lines.append(
                            "Some parts of the investigation may remain incomplete "
                            "because the turn limit was reached."
                        )
                        final_text = "\n".join(lines)

                # Fill in summary fields on the QueryResult
                if executed_calls:
                    first = executed_calls[0]
                    result.action = first["tool"]
                    result.server_used = first["server"]
                    result.params = first["args"]
                else:
                    result.action = "no_tool"
                    result.params = None
                    result.answer_source = "agent_only"

                result.raw_results = {
                    "tool_calls": executed_calls,
                    "execution_steps": [
                        c["tool"] for c in executed_calls if c.get("tool")
                    ],
                    "total_found": sum(
                        (c["result"] or {}).get("total_found", 0)
                        if isinstance(c["result"], dict) else 0
                        for c in executed_calls
                    ),
                    "turns": turn,
                    "hit_cap": hit_cap,
                }

                # Determine overall success
                if hit_cap and final_text:
                    result.success = True
                    result.error = None
                    result.formatted_response = final_text
                    result.raw_results["partial_due_to_turn_limit"] = True
                    result.raw_results["turn_limit_message"] = (
                        f"Agent reached the {self.MAX_AGENT_TURNS}-turn tool-calling limit."
                    )
                elif hit_cap:
                    result.success = False
                    result.error = (
                        f"Agent did not converge within {self.MAX_AGENT_TURNS} turns."
                    )
                    result.formatted_response = None
                elif executed_calls and all(not c["success"] for c in executed_calls):
                    if final_text:
                        result.success = True
                        result.error = None
                        result.answer_source = "agent_only"
                        result.formatted_response = final_text
                    else:
                        result.success = False
                        errs = [c["error"] for c in executed_calls if c["error"]]
                        result.error = errs[0] if errs else "All tool calls failed."
                        result.formatted_response = None
                else:
                    result.success = True
                    result.formatted_response = final_text

                if result.raw_results is not None:
                    result.raw_results["answer_source"] = result.answer_source

                emit_progress(
                    "complete",
                    "Search complete!" if result.success else f"Completed with errors",
                    {
                        "turns": turn,
                        "tool_calls": len(executed_calls),
                        "success": result.success,
                    },
                    progress=100,
                )

                return result

            except Exception as e:
                emit_progress("error", f"Error: {str(e)}")
                result.success = False
                result.error = str(e)
                return result
        finally:
            pass
    
    async def get_server_capabilities(self) -> dict:
        """
        Get information about all connected server capabilities.
        """
        if not self._connected:
            return {"error": "Not connected"}
        
        capabilities = {
            "servers": {},
            "total_tools": len(self._all_tools)
        }
        
        for name, connection in self._connections.items():
            server_caps = {
                "tools": [
                    {"name": t["name"], "description": t["description"]}
                    for t in connection.tools
                ],
                "tool_count": len(connection.tools)
            }
            
            # Try to get resources and prompts
            try:
                resources_response = await connection.session.list_resources()
                server_caps["resources"] = [
                    {"uri": r.uri, "name": r.name}
                    for r in resources_response.resources
                ]
            except Exception:
                server_caps["resources"] = []
            
            try:
                prompts_response = await connection.session.list_prompts()
                server_caps["prompts"] = [
                    {"name": p.name, "description": p.description}
                    for p in prompts_response.prompts
                ]
            except Exception:
                server_caps["prompts"] = []
            
            capabilities["servers"][name] = server_caps
        
        return capabilities
    

def get_default_servers(custom_local_path: str = None, only: list[str] = None) -> list[ServerConfig]:
    """
    Get the default server configurations.
    
    Includes:
    - Local OSINT server (username_search)
    - WhoisXML API MCP server (17 domain/IP intelligence tools)
    - Shodan MCP server (host recon, CVE lookups)
    
    Args:
        custom_local_path: Override path to local MCP server script
        only: If provided, only return configs for these server names.
              Used by smart routing to avoid connecting to unnecessary servers.
    """
    import pathlib
    
    all_servers = []
    
    # Determine the path to local MCP server
    if custom_local_path is not None:
        server_path = custom_local_path
    else:
        # Auto-detect: mcp_server.py should be in the same directory as this file
        this_file = pathlib.Path(__file__).resolve()
        same_dir_path = this_file.parent / "mcp_server.py"
        
        if same_dir_path.exists():
            server_path = str(same_dir_path)
        else:
            # Fallback to relative path (Django project root)
            server_path = "researcher/services/mcp_server.py"
    
    # Local OSINT server
    all_servers.append(ServerConfig(
        name="local",
        server_type="stdio",
        script_path=server_path,
        description="Local OSINT tools (username search, person search)",
        enabled=True
    ))
    
    # WhoisXML API hosted MCP server
    whoisxml_api_key = os.getenv("WHOISXML_API_KEY")
    if whoisxml_api_key:
        all_servers.append(ServerConfig(
            name="whoisxml",
            server_type="http",
            url="https://mcp-hosted.whoisxmlapi.com/mcp",
            headers={"Authorization": f"Bearer {whoisxml_api_key}"},
            description="WhoisXML API (WHOIS, DNS, IP, threat intelligence)",
            enabled=True
        ))
    else:
        print("Warning: WHOISXML_API_KEY not set. WhoisXML MCP server disabled.")
    
    # Shodan MCP server
    shodan_api_key = os.getenv("SHODAN_API_KEY")
    if shodan_api_key:
        all_servers.append(ServerConfig(
            name="shodan",
            server_type="stdio",
            command="npx",
            args=["-y", "@burtthecoder/mcp-shodan"],
            env={"SHODAN_API_KEY": shodan_api_key},
            description="Shodan (host recon, CVE lookups, DNS)",
            enabled=True
        ))
    else:
        print("Warning: SHODAN_API_KEY not set. Shodan MCP server disabled.")
    
    # BuiltWith hosted MCP server
    builtwith_api_key = os.getenv("BUILTWITH_API_KEY")
    if builtwith_api_key:
        all_servers.append(ServerConfig(
            name="builtwith",
            server_type="http",
            url="https://api.builtwith.com/mcp",
            headers={"Authorization": f"Bearer {builtwith_api_key}"},
            description="BuiltWith (technology detection, trends)",
            enabled=True
        ))
    else:
        print("Warning: BUILTWITH_API_KEY not set. BuiltWith MCP server disabled.")
    
    # Filter if requested
    if only:
        all_servers = [s for s in all_servers if s.name in only]
    
    return all_servers


async def quick_search(
    query: str,
    servers: list[ServerConfig] = None,
    progress_callback: Callable[[ProgressUpdate], None] = None,
    # Legacy support
    server_script_path: str = None,
    sse_url: str = None,
) -> QueryResult:
    """
    Quick helper to process a query without managing connection lifecycle.
    
    Args:
        query: Natural language query
        servers: List of server configs (uses defaults if not provided)
        progress_callback: Optional progress callback
        
    Returns:
        QueryResult with the search results
    """
    if servers is None and server_script_path is None and sse_url is None:
        servers = get_default_servers()
    
    client = OSINTMCPClient(
        servers=servers,
        server_script_path=server_script_path,
        sse_url=sse_url,
        progress_callback=progress_callback
    )
    
    try:
        connected = await client.connect()
        if not connected:
            return QueryResult(success=False, error="Failed to connect to MCP servers")
        
        result = await client.process_query(query)
        return result
        
    finally:
        await client.disconnect()


async def main():
    """Demo the multi-server MCP client."""
    print("=" * 70)
    print("OSINT Multi-Server MCP Client Demo")
    print("=" * 70)
    
    def progress_handler(update: ProgressUpdate):
        prefix = {
            "connecting": "🔌",
            "connected": "✅",
            "parsing": "🔍",
            "tool_call": "🔧",
            "executing": "⚡",
            "formatting": "📝",
            "complete": "🎉",
            "error": "❌",
            "disconnected": "👋"
        }.get(update.stage, "•")
        
        progress = f" [{update.progress_percent}%]" if update.progress_percent else ""
        print(f"{prefix} {update.message}{progress}")
        
        if update.details:
            for key, value in update.details.items():
                if isinstance(value, list) and len(value) > 5:
                    print(f"   {key}: {value[:5]} ... ({len(value)} total)")
                else:
                    print(f"   {key}: {value}")
    
    # Use default servers (local + WhoisXML)
    servers = get_default_servers()
    
    print(f"\nConfigured servers:")
    for s in servers:
        status = "✅" if s.enabled else "❌"
        print(f"  {status} {s.name}: {s.description}")
    
    client = OSINTMCPClient(
        servers=servers,
        progress_callback=progress_handler
    )
    
    try:
        # Connect
        print("\n" + "-" * 70)
        connected = await client.connect()
        if not connected:
            print("Failed to connect!")
            return
        
        # Show capabilities
        print("\n📋 Server Capabilities:")
        caps = await client.get_server_capabilities()
        for server_name, server_caps in caps["servers"].items():
            print(f"\n  [{server_name}] - {server_caps['tool_count']} tools")
            for tool in server_caps["tools"][:5]:
                print(f"    • {tool['name']}: {tool['description'][:50]}...")
            if server_caps['tool_count'] > 5:
                print(f"    ... and {server_caps['tool_count'] - 5} more")
        
        # Test queries
        test_queries = [
            "Who owns google.com?",
            "Show historical WHOIS records for google.com",
            "Find all domains registered by Google LLC",
            "Discover domains containing 'shopify' in the name",
        ]
        
        for query in test_queries:
            print("\n" + "=" * 70)
            print(f"Query: {query}")
            print("=" * 70 + "\n")
            
            result = await client.process_query(query)
            
            if result.success:
                print(f"\n📊 Results:")
                print(f"   Action: {result.action}")
                print(f"   Server: {result.server_used}")
                print(f"   Params: {result.params}")
                if result.raw_results:
                    total = result.raw_results.get("total_found", "N/A")
                    print(f"   Total Found: {total}")
                print(f"\n📝 Summary:\n{result.formatted_response}")
            else:
                print(f"\n❌ Error: {result.error}")
            
            print("\n" + "-" * 70)
            
    finally:
        await client.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
