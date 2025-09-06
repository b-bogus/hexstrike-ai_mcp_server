# HexStrike AI MCP Server

A standalone network MCP (Model Context Protocol) server that provides direct access to HexStrike AI security tools without requiring local client files.

## Overview

This repository contains a network-accessible MCP server that connects to HexStrike AI's Flask API backend and exposes 150+ security tools through the MCP protocol. This allows AI agents like Claude Code to access powerful cybersecurity tools remotely.

## Architecture

```
AI Agent (Claude Code) ----MCP over network----> hexstrike_mcp_server.py:8889
                                                          |
                                                   HTTP requests
                                                          ↓
                                         HexStrike Flask API:8888
                                                          ↓
                                              Security Tools (nmap, etc.)
```

## Features

- **Network MCP Server**: Direct MCP access over TCP/IP - no local files required
- **150+ Security Tools**: Complete access to HexStrike AI's security arsenal
- **AI Intelligence**: AI-powered target analysis and tool selection
- **Specialized Workflows**: Bug bounty hunting, CTF challenges, penetration testing
- **Real-time Monitoring**: Process management and telemetry
- **Zero Client Setup**: No local HexStrike files needed on client machines

## Quick Start

### Prerequisites

- Python 3.8+
- HexStrike AI Flask server running on the same machine
- Required Python packages: `requests`, `fastmcp`

### Installation

1. **Download this MCP server:**
```bash
git clone https://github.com/b-bogus/hexstrike-ai_mcp_server.git
cd hexstrike-ai_mcp_server
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Start HexStrike Flask API** (on same machine):
```bash
# Download and run HexStrike AI from https://github.com/0x4m4/hexstrike-ai
python3 hexstrike_server.py
```

4. **Start the MCP server:**
```bash
python3 hexstrike_mcp_server.py --host 0.0.0.0 --port 8889
```

### Client Configuration

**For Claude Code in VS Code:**

Add to your VS Code user settings (`Ctrl+Shift+P` → "Preferences: Open User Settings (JSON)"):

```json
{
  "mcp.servers": {
    "hexstrike-ai": {
      "command": "stdio",
      "args": [],
      "env": {
        "MCP_SERVER_URL": "http://YOUR_SERVER_IP:8889"
      },
      "description": "HexStrike AI MCP Server",
      "timeout": 300
    }
  }
}
```

## Available Tools

### Network & Reconnaissance
- `nmap_scan()` - Advanced port scanning
- `rustscan_scan()` - Ultra-fast port scanning  
- `amass_enum()` - Subdomain enumeration
- `subfinder_scan()` - Passive subdomain discovery

### Web Application Security
- `gobuster_scan()` - Directory enumeration
- `nuclei_scan()` - Vulnerability scanning with 4000+ templates
- `sqlmap_scan()` - SQL injection testing
- `httpx_scan()` - HTTP probing and technology detection

### Binary Analysis
- `ghidra_analyze()` - Advanced reverse engineering
- `radare2_analyze()` - Binary analysis framework
- `gdb_debug()` - GNU debugger with exploit development
- `volatility_analyze()` - Memory forensics

### Cloud Security
- `prowler_assess()` - AWS/Azure/GCP security assessment
- `trivy_scan()` - Container vulnerability scanning
- `kube_hunter_scan()` - Kubernetes penetration testing

### AI Intelligence & Workflows
- `ai_analyze_target()` - AI-powered target analysis
- `ai_select_tools()` - Intelligent tool selection
- `bugbounty_reconnaissance()` - Bug bounty hunting workflows
- `ctf_solve_challenge()` - Automated CTF challenge solving

## Usage Example

Once configured, use with any MCP-compatible AI agent:

```
User: "Scan example.com for open ports and vulnerabilities"

AI Agent: I'll perform a comprehensive scan of example.com using HexStrike tools.

[Agent automatically calls nmap_scan(), then nuclei_scan(), analyzes results, and provides detailed security assessment]
```

## Command Line Options

```bash
python3 hexstrike_mcp_server.py [options]

Options:
  --host HOST          Host to bind to (default: 0.0.0.0)
  --port PORT          Port to listen on (default: 8889)
  --api-url URL        HexStrike Flask API URL (default: http://localhost:8888)
  --debug              Enable debug logging
  --help               Show help message
```

## Security Considerations

⚠️ **Important**: This tool provides AI agents with access to powerful security tools.

- **Authorized Use Only**: Only use on systems you own or have explicit permission to test
- **Network Security**: Run on isolated networks or with proper firewall rules
- **Authentication**: Consider implementing authentication for production deployments
- **Monitoring**: Monitor AI agent activities through the telemetry endpoints

## Troubleshooting

**Connection Issues:**
- Verify HexStrike Flask API is running on port 8888
- Check firewall settings for port 8889
- Test connectivity: `curl http://SERVER_IP:8889/health`

**No Tools Available:**
- Ensure security tools are installed on the server machine
- Check `/health` endpoint for tool availability status

**Client Connection Failed:**
- Verify MCP client configuration
- Check server logs for connection attempts
- Test with debug mode: `--debug`

## Related Projects

- **HexStrike AI**: https://github.com/0x4m4/hexstrike-ai - The main security tools framework
- **FastMCP**: MCP server framework used by this project

## License

MIT License - see LICENSE file for details.

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## Support

For support and questions:
- Create an issue on GitHub
- Review the troubleshooting section
- Check the setup documentation