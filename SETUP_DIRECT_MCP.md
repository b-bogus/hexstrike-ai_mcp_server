# HexStrike AI Direct MCP Server Setup

This guide explains how to set up the new direct network MCP server that eliminates the need for local client files.

## Architecture

```
Machine .16 (Claude Code)  →  Machine .71 (MCP Server + Flask API)
        ↓ MCP over network              ↓ local HTTP calls
   Claude Code in VS Code        hexstrike_mcp_server.py:8889
                                        ↓
                                hexstrike_server.py:8888
                                        ↓
                                Security Tools
```

## Setup Instructions

### On Remote Machine (.71) - Server Side

1. **Install dependencies** (if not already done):
```bash
# On Debian/Ubuntu
sudo apt update
sudo apt install python3-pip python3-requests python3-fastmcp

# Or via pip
pip3 install requests fastmcp flask psutil
```

2. **Start the Flask API server** (existing):
```bash
cd /path/to/hexstrike-ai
python3 hexstrike_server.py
```

3. **Start the new MCP server** (in another terminal):
```bash
python3 hexstrike_mcp_server.py --host 0.0.0.0 --port 8889
```

**Expected output:**
```
✅ Connected to HexStrike API at http://localhost:8888
✅ 12 tools available
🚀 Starting HexStrike Direct MCP Server
📡 Listening on 0.0.0.0:8889
🔗 API Backend: http://localhost:8888
⚡ Configure Claude Code to connect to: http://0.0.0.0:8889
```

### On Local Machine (.16) - Client Side

**Configure VS Code User Settings:**

1. Open VS Code
2. `Ctrl+Shift+P` → "Preferences: Open User Settings (JSON)"
3. Add this configuration:

```json
{
    "git.enableSmartCommit": true,
    "mcp.servers": {
        "hexstrike-ai": {
            "command": "stdio",
            "args": [],
            "env": {
                "MCP_SERVER_URL": "http://192.168.0.71:8889"
            },
            "description": "HexStrike AI Direct Network MCP Server",
            "timeout": 300
        }
    }
}
```

**Alternative Configuration (if the above doesn't work):**
```json
{
    "git.enableSmartCommit": true,
    "mcp.servers": {
        "hexstrike-ai": {
            "command": "curl",
            "args": ["-X", "POST", "http://192.168.0.71:8889/mcp"],
            "description": "HexStrike AI Direct Network MCP Server",
            "timeout": 300
        }
    }
}
```

## Testing the Connection

### From Machine .16 (Local):
```bash
# Test basic connectivity
curl http://192.168.0.71:8889/health

# Test MCP endpoint (once server is running)
curl -X POST http://192.168.0.71:8889/mcp \
  -H "Content-Type: application/json" \
  -d '{"method": "tools/list"}'
```

### From Machine .71 (Remote):
```bash
# Test Flask API is running
curl http://localhost:8888/health

# Test MCP server is running
curl http://localhost:8889/health
```

## Available Tools

The MCP server exposes these tool categories:

**Network & Reconnaissance:**
- `nmap_scan()` - Advanced port scanning
- `rustscan_scan()` - Fast port scanning  
- `amass_enum()` - Subdomain enumeration
- `subfinder_scan()` - Passive subdomain discovery

**Web Application Security:**
- `gobuster_scan()` - Directory enumeration
- `nuclei_scan()` - Vulnerability scanning
- `sqlmap_scan()` - SQL injection testing
- `httpx_scan()` - HTTP probing

**Binary Analysis:**
- `ghidra_analyze()` - Reverse engineering
- `radare2_analyze()` - Binary analysis
- `gdb_debug()` - Debugging
- `volatility_analyze()` - Memory forensics

**Cloud Security:**
- `prowler_assess()` - Cloud security assessment
- `trivy_scan()` - Container scanning
- `kube_hunter_scan()` - Kubernetes testing

**AI Intelligence:**
- `ai_analyze_target()` - AI-powered target analysis
- `ai_select_tools()` - Intelligent tool selection
- `bugbounty_reconnaissance()` - Bug bounty workflows
- `ctf_solve_challenge()` - CTF automation

## Usage Example

Once configured, you can use Claude Code normally:

```
User: "I need to scan example.com for open ports"
Claude: I'll use the nmap_scan tool to scan example.com for open ports.
```

Claude Code will automatically call the MCP server on .71, which will execute the scan and return results.

## Troubleshooting

**Connection refused:**
- Check if ports 8888 and 8889 are open on .71
- Verify firewall settings
- Test with `telnet 192.168.0.71 8889`

**MCP server won't start:**
- Install missing dependencies: `pip3 install fastmcp requests`
- Check if Flask server (port 8888) is running first

**No tools available:**
- Check if security tools are installed on .71
- Review `/health` endpoint for tool availability

**Claude Code can't connect:**
- Verify VS Code MCP configuration
- Check Claude Code logs for connection errors
- Try alternative configuration format

## Benefits

✅ **No local files needed** on machine .16  
✅ **True network MCP server** - proper remote access  
✅ **Preserves existing architecture** - doesn't modify original files  
✅ **Easy maintenance** - all tools and updates on one machine  
✅ **Proper separation of concerns** - MCP server vs Flask API  