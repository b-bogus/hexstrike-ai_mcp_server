#!/usr/bin/env python3
"""
HexStrike AI Direct MCP Server - Network-accessible MCP server

This server runs on the remote machine and provides direct MCP access
to HexStrike AI tools without requiring local client wrapper files.

Usage:
    python3 hexstrike_mcp_server.py --host 0.0.0.0 --port 8889
    
Then configure Claude Code to connect to: http://REMOTE_IP:8889

Architecture:
- Runs standalone MCP server using FastMCP
- Communicates with local HexStrike Flask API on localhost:8888  
- Exposes all 150+ security tools via MCP protocol over network
- No client-side files required
"""

import argparse
import asyncio
import logging
import sys
from typing import Dict, Any, Optional
import requests
import json

from mcp.server.fastmcp import FastMCP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

class HexStrikeColors:
    """Color constants for consistent output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

# Initialize FastMCP server
mcp = FastMCP("HexStrike AI Direct MCP Server")

class HexStrikeAPIClient:
    """Client for communicating with local HexStrike Flask API"""
    
    def __init__(self, api_base_url: str = "http://localhost:8888"):
        self.api_base_url = api_base_url.rstrip('/')
        
    def make_api_call(self, endpoint: str, method: str = "POST", data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Make API call to HexStrike Flask server"""
        url = f"{self.api_base_url}{endpoint}"
        
        try:
            if method == "GET":
                response = requests.get(url, timeout=300)
            elif method == "POST":
                response = requests.post(url, json=data or {}, timeout=300)
            else:
                return {"error": f"Unsupported HTTP method: {method}"}
                
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            logger.error(f"API call failed: {e}")
            return {
                "error": f"API call to {endpoint} failed: {str(e)}",
                "status": "failed",
                "endpoint": endpoint
            }
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error: {e}")
            return {
                "error": f"Invalid JSON response from {endpoint}: {str(e)}",
                "status": "failed",
                "raw_response": response.text if 'response' in locals() else "No response"
            }

# Initialize API client
api_client = HexStrikeAPIClient()

# Health check endpoint
@mcp.tool()
def hexstrike_health() -> Dict[str, Any]:
    """Check HexStrike server health and tool availability"""
    return api_client.make_api_call("/health", "GET")

# Core command execution
@mcp.tool()
def hexstrike_command(command: str, params: str = "") -> Dict[str, Any]:
    """Execute arbitrary command through HexStrike API with caching"""
    data = {
        "command": command,
        "params": params
    }
    return api_client.make_api_call("/api/command", "POST", data)

# ============================================================================
# NETWORK & RECONNAISSANCE TOOLS
# ============================================================================

@mcp.tool()
def nmap_scan(target: str, options: str = "", additional_args: str = "") -> Dict[str, Any]:
    """Advanced Nmap scanning with intelligent optimization"""
    data = {
        "target": target,
        "options": options,
        "additional_args": additional_args
    }
    return api_client.make_api_call("/api/tools/nmap", "POST", data)

@mcp.tool()
def rustscan_scan(target: str, ports: str = "", options: str = "") -> Dict[str, Any]:
    """Ultra-fast port scanning with Rustscan"""
    data = {
        "target": target,
        "ports": ports,
        "options": options
    }
    return api_client.make_api_call("/api/tools/rustscan", "POST", data)

@mcp.tool()
def masscan_scan(target: str, ports: str = "", rate: str = "1000", options: str = "") -> Dict[str, Any]:
    """High-speed Internet-scale port scanning"""
    data = {
        "target": target,
        "ports": ports,
        "rate": rate,
        "options": options
    }
    return api_client.make_api_call("/api/tools/masscan", "POST", data)

@mcp.tool()
def autorecon_scan(target: str, options: str = "", output_dir: str = "") -> Dict[str, Any]:
    """Comprehensive automated reconnaissance"""
    data = {
        "target": target,
        "options": options,
        "output_dir": output_dir
    }
    return api_client.make_api_call("/api/tools/autorecon", "POST", data)

@mcp.tool()
def amass_enum(target: str, options: str = "", config: str = "") -> Dict[str, Any]:
    """Advanced subdomain enumeration and OSINT gathering"""
    data = {
        "target": target,
        "options": options,
        "config": config
    }
    return api_client.make_api_call("/api/tools/amass", "POST", data)

@mcp.tool()
def subfinder_scan(target: str, options: str = "", sources: str = "") -> Dict[str, Any]:
    """Fast passive subdomain discovery"""
    data = {
        "target": target,
        "options": options,
        "sources": sources
    }
    return api_client.make_api_call("/api/tools/subfinder", "POST", data)

# ============================================================================
# WEB APPLICATION SECURITY TOOLS  
# ============================================================================

@mcp.tool()
def gobuster_scan(target: str, wordlist: str = "", extensions: str = "", options: str = "") -> Dict[str, Any]:
    """Directory and file enumeration with intelligent wordlists"""
    data = {
        "target": target,
        "wordlist": wordlist,
        "extensions": extensions,
        "options": options
    }
    return api_client.make_api_call("/api/tools/gobuster", "POST", data)

@mcp.tool()
def feroxbuster_scan(target: str, wordlist: str = "", extensions: str = "", options: str = "") -> Dict[str, Any]:
    """Recursive content discovery with intelligent filtering"""
    data = {
        "target": target,
        "wordlist": wordlist,
        "extensions": extensions,
        "options": options
    }
    return api_client.make_api_call("/api/tools/feroxbuster", "POST", data)

@mcp.tool()
def nuclei_scan(target: str, templates: str = "", options: str = "") -> Dict[str, Any]:
    """Fast vulnerability scanner with 4000+ templates"""
    data = {
        "target": target,
        "templates": templates,
        "options": options
    }
    return api_client.make_api_call("/api/tools/nuclei", "POST", data)

@mcp.tool()
def nikto_scan(target: str, options: str = "", port: str = "") -> Dict[str, Any]:
    """Web server vulnerability scanner"""
    data = {
        "target": target,
        "options": options,
        "port": port
    }
    return api_client.make_api_call("/api/tools/nikto", "POST", data)

@mcp.tool()
def sqlmap_scan(target: str, options: str = "", data: str = "") -> Dict[str, Any]:
    """Advanced automatic SQL injection testing"""
    data = {
        "target": target,
        "options": options,
        "data": data
    }
    return api_client.make_api_call("/api/tools/sqlmap", "POST", data)

@mcp.tool()
def httpx_scan(target: str, options: str = "", follow_redirects: bool = True) -> Dict[str, Any]:
    """Fast HTTP probing and technology detection"""
    data = {
        "target": target,
        "options": options,
        "follow_redirects": follow_redirects
    }
    return api_client.make_api_call("/api/tools/httpx", "POST", data)

# ============================================================================
# BINARY ANALYSIS & REVERSE ENGINEERING
# ============================================================================

@mcp.tool()
def ghidra_analyze(binary_path: str, options: str = "", script: str = "") -> Dict[str, Any]:
    """Advanced software reverse engineering with Ghidra"""
    data = {
        "binary_path": binary_path,
        "options": options,
        "script": script
    }
    return api_client.make_api_call("/api/tools/ghidra", "POST", data)

@mcp.tool()
def radare2_analyze(binary_path: str, options: str = "", commands: str = "") -> Dict[str, Any]:
    """Advanced reverse engineering framework"""
    data = {
        "binary_path": binary_path,
        "options": options,
        "commands": commands
    }
    return api_client.make_api_call("/api/tools/radare2", "POST", data)

@mcp.tool()
def gdb_debug(binary_path: str, commands: str = "", options: str = "") -> Dict[str, Any]:
    """GNU debugger with exploit development support"""
    data = {
        "binary_path": binary_path,
        "commands": commands,
        "options": options
    }
    return api_client.make_api_call("/api/tools/gdb", "POST", data)

@mcp.tool()
def volatility_analyze(memory_dump: str, profile: str = "", plugin: str = "") -> Dict[str, Any]:
    """Advanced memory forensics analysis"""
    data = {
        "memory_dump": memory_dump,
        "profile": profile,
        "plugin": plugin
    }
    return api_client.make_api_call("/api/tools/volatility", "POST", data)

# ============================================================================
# CLOUD SECURITY TOOLS
# ============================================================================

@mcp.tool()
def prowler_assess(cloud_provider: str = "aws", options: str = "", profile: str = "") -> Dict[str, Any]:
    """AWS/Azure/GCP security assessment"""
    data = {
        "cloud_provider": cloud_provider,
        "options": options,
        "profile": profile
    }
    return api_client.make_api_call("/api/tools/prowler", "POST", data)

@mcp.tool()
def trivy_scan(target: str, scan_type: str = "image", options: str = "") -> Dict[str, Any]:
    """Comprehensive vulnerability scanner for containers"""
    data = {
        "target": target,
        "scan_type": scan_type,
        "options": options
    }
    return api_client.make_api_call("/api/tools/trivy", "POST", data)

@mcp.tool()
def kube_hunter_scan(target: str = "", options: str = "", mode: str = "passive") -> Dict[str, Any]:
    """Kubernetes penetration testing"""
    data = {
        "target": target,
        "options": options,
        "mode": mode
    }
    return api_client.make_api_call("/api/tools/kube-hunter", "POST", data)

# ============================================================================
# AI INTELLIGENCE & WORKFLOWS
# ============================================================================

@mcp.tool()
def ai_analyze_target(target: str, analysis_type: str = "comprehensive") -> Dict[str, Any]:
    """AI-powered target analysis and profiling"""
    data = {
        "target": target,
        "analysis_type": analysis_type
    }
    return api_client.make_api_call("/api/intelligence/analyze-target", "POST", data)

@mcp.tool()
def ai_select_tools(target_info: Dict[str, Any], attack_type: str = "comprehensive") -> Dict[str, Any]:
    """Intelligent tool selection based on target analysis"""
    data = {
        "target_info": target_info,
        "attack_type": attack_type
    }
    return api_client.make_api_call("/api/intelligence/select-tools", "POST", data)

@mcp.tool()
def ai_create_attack_chain(target: str, objectives: list = None) -> Dict[str, Any]:
    """Generate multi-stage attack chains"""
    data = {
        "target": target,
        "objectives": objectives or ["reconnaissance", "vulnerability_discovery", "exploitation"]
    }
    return api_client.make_api_call("/api/intelligence/create-attack-chain", "POST", data)

@mcp.tool()
def bugbounty_reconnaissance(target: str, scope: list = None) -> Dict[str, Any]:
    """Comprehensive bug bounty reconnaissance workflow"""
    data = {
        "target": target,
        "scope": scope or []
    }
    return api_client.make_api_call("/api/bugbounty/reconnaissance-workflow", "POST", data)

@mcp.tool()
def ctf_solve_challenge(challenge_url: str, category: str = "", hints: str = "") -> Dict[str, Any]:
    """Automated CTF challenge solving"""
    data = {
        "challenge_url": challenge_url,
        "category": category,
        "hints": hints
    }
    return api_client.make_api_call("/api/ctf/auto-solve-challenge", "POST", data)

# ============================================================================
# PROCESS & SYSTEM MANAGEMENT
# ============================================================================

@mcp.tool()
def list_processes() -> Dict[str, Any]:
    """List all active HexStrike processes"""
    return api_client.make_api_call("/api/processes/list", "GET")

@mcp.tool()
def get_telemetry() -> Dict[str, Any]:
    """Get system performance metrics and statistics"""
    return api_client.make_api_call("/api/telemetry", "GET")

@mcp.tool()
def get_cache_stats() -> Dict[str, Any]:
    """Get cache performance statistics"""
    return api_client.make_api_call("/api/cache/stats", "GET")

def main():
    """Main function to start the direct MCP server"""
    parser = argparse.ArgumentParser(description="HexStrike AI Direct MCP Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8889, help="Port to bind to (default: 8889)")
    parser.add_argument("--api-url", default="http://localhost:8888", 
                       help="HexStrike Flask API URL (default: http://localhost:8888)")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Update API client with custom URL
    global api_client
    api_client = HexStrikeAPIClient(args.api_url)
    
    # Test connection to Flask API
    try:
        health = api_client.make_api_call("/health", "GET")
        if "error" in health:
            logger.error(f"Cannot connect to HexStrike API at {args.api_url}")
            logger.error(f"Error: {health['error']}")
            logger.info("Make sure hexstrike_server.py is running first")
            sys.exit(1)
        else:
            logger.info(f"✅ Connected to HexStrike API at {args.api_url}")
            logger.info(f"✅ {health.get('total_tools_available', 0)} tools available")
    except Exception as e:
        logger.error(f"Failed to connect to HexStrike API: {e}")
        sys.exit(1)
    
    logger.info(f"{HexStrikeColors.GREEN}🚀 Starting HexStrike Direct MCP Server{HexStrikeColors.RESET}")
    logger.info(f"{HexStrikeColors.CYAN}📡 Listening on {args.host}:{args.port}{HexStrikeColors.RESET}")
    logger.info(f"{HexStrikeColors.YELLOW}🔗 API Backend: {args.api_url}{HexStrikeColors.RESET}")
    logger.info(f"{HexStrikeColors.MAGENTA}⚡ Configure Claude Code to connect to: http://{args.host}:{args.port}{HexStrikeColors.RESET}")
    
    # Run the MCP server
    mcp.run(host=args.host, port=args.port)

if __name__ == "__main__":
    main()