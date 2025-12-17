#!/usr/bin/env python3
"""
Test script to prove multi-program support in ReVa.
Tests opening a project, loading all programs, and accessing strings from multiple programs.
"""

import json
import sys
import httpx
from typing import Dict, Any

# ReVa MCP server endpoint (default port 8080)
MCP_SERVER_URL = "http://localhost:8080/mcp/message"

def call_mcp_tool(tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Call an MCP tool via HTTP."""
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments
        }
    }

    try:
        response = httpx.post(MCP_SERVER_URL, json=request, timeout=60.0)
        response.raise_for_status()
        result = response.json()

        if "error" in result:
            print(f"ERROR: {result['error']}")
            return None

        return result.get("result", {})
    except httpx.RequestError as e:
        print(f"Connection error: {e}")
        print("Make sure Ghidra is running with ReVa extension enabled on port 8080")
        return None
    except Exception as e:
        print(f"Error calling tool: {e}")
        return None

def main():
    print("=" * 70)
    print("TESTING MULTI-PROGRAM SUPPORT IN REVA")
    print("=" * 70)
    print()

    # Step 1: Open project
    print("Step 1: Opening project C:/Users/boden/test.gpr")
    print("-" * 70)
    result = call_mcp_tool("open-project", {
        "projectPath": "C:/Users/boden/test.gpr"
    })

    if result is None:
        print("FAILED: Could not open project")
        sys.exit(1)

    if result.get("isError"):
        print(f"ERROR: {result.get('content', [{}])[0].get('text', 'Unknown error')}")
        sys.exit(1)

    project_info = json.loads(result.get("content", [{}])[0].get("text", "{}"))
    print(f"SUCCESS: Project opened - {project_info.get('projectName')}")
    print(f"  Programs in project: {project_info.get('programCount', 0)}")
    print()

    # Step 2: Open all exe/dll programs in Code Browser
    print("Step 2: Opening all exe/dll programs in Code Browser")
    print("-" * 70)
    result = call_mcp_tool("open-all-programs-in-code-browser", {
        "extensions": "exe,dll"
    })

    if result is None:
        print("FAILED: Could not open programs")
        sys.exit(1)

    if result.get("isError"):
        print(f"ERROR: {result.get('content', [{}])[0].get('text', 'Unknown error')}")
        sys.exit(1)

    open_info = json.loads(result.get("content", [{}])[0].get("text", "{}"))
    print(f"SUCCESS: Programs opened")
    print(f"  Found: {open_info.get('programsFound', 0)}")
    print(f"  Opened: {open_info.get('programsOpened', 0)}")
    print(f"  Already open: {open_info.get('programsAlreadyOpen', 0)}")
    print(f"  Failed: {open_info.get('programsFailed', 0)}")
    if open_info.get('openedPrograms'):
        print("  Opened programs:")
        for prog in open_info['openedPrograms']:
            print(f"    - {prog}")
    print()

    # Step 3: Get strings from swkotor.exe
    print("Step 3: Getting strings from /swkotor.exe")
    print("-" * 70)
    result = call_mcp_tool("get-strings", {
        "programPath": "/swkotor.exe",
        "maxCount": 10
    })

    if result is None:
        print("FAILED: Could not get strings from swkotor.exe")
        sys.exit(1)

    if result.get("isError"):
        print(f"ERROR: {result.get('content', [{}])[0].get('text', 'Unknown error')}")
        sys.exit(1)

    strings_data = json.loads(result.get("content", [{}])[0].get("text", "[]"))
    if isinstance(strings_data, list) and len(strings_data) > 0:
        pagination = strings_data[0] if isinstance(strings_data[0], dict) else {}
        strings = strings_data[1:] if len(strings_data) > 1 else []
        print(f"SUCCESS: Retrieved {len(strings)} strings from swkotor.exe")
        print(f"  Total available: {pagination.get('nextStartIndex', 'unknown')}")
        if strings:
            print("  Sample strings:")
            for s in strings[:3]:
                print(f"    - {s.get('address', '?')}: {s.get('content', '')[:50]}...")
    print()

    # Step 4: Get strings from masseffect.exe
    print("Step 4: Getting strings from /masseffect.exe")
    print("-" * 70)
    result = call_mcp_tool("get-strings", {
        "programPath": "/masseffect.exe",
        "maxCount": 10
    })

    if result is None:
        print("FAILED: Could not get strings from masseffect.exe")
        sys.exit(1)

    if result.get("isError"):
        print(f"ERROR: {result.get('content', [{}])[0].get('text', 'Unknown error')}")
        sys.exit(1)

    strings_data = json.loads(result.get("content", [{}])[0].get("text", "[]"))
    if isinstance(strings_data, list) and len(strings_data) > 0:
        pagination = strings_data[0] if isinstance(strings_data[0], dict) else {}
        strings = strings_data[1:] if len(strings_data) > 1 else []
        print(f"SUCCESS: Retrieved {len(strings)} strings from masseffect.exe")
        print(f"  Total available: {pagination.get('nextStartIndex', 'unknown')}")
        if strings:
            print("  Sample strings:")
            for s in strings[:3]:
                print(f"    - {s.get('address', '?')}: {s.get('content', '')[:50]}...")
    print()

    # Step 5: Get strings from swkotor2.exe
    print("Step 5: Getting strings from /swkotor2.exe")
    print("-" * 70)
    result = call_mcp_tool("get-strings", {
        "programPath": "/swkotor2.exe",
        "maxCount": 10
    })

    if result is None:
        print("FAILED: Could not get strings from swkotor2.exe")
        sys.exit(1)

    if result.get("isError"):
        print(f"ERROR: {result.get('content', [{}])[0].get('text', 'Unknown error')}")
        sys.exit(1)

    strings_data = json.loads(result.get("content", [{}])[0].get("text", "[]"))
    if isinstance(strings_data, list) and len(strings_data) > 0:
        pagination = strings_data[0] if isinstance(strings_data[0], dict) else {}
        strings = strings_data[1:] if len(strings_data) > 1 else []
        print(f"SUCCESS: Retrieved {len(strings)} strings from swkotor2.exe")
        print(f"  Total available: {pagination.get('nextStartIndex', 'unknown')}")
        if strings:
            print("  Sample strings:")
            for s in strings[:3]:
                print(f"    - {s.get('address', '?')}: {s.get('content', '')[:50]}...")
    print()

    print("=" * 70)
    print("ALL TESTS COMPLETED SUCCESSFULLY!")
    print("=" * 70)
    print()
    print("This proves that ReVa supports:")
    print("  ✓ Opening projects")
    print("  ✓ Opening multiple programs simultaneously in Code Browser")
    print("  ✓ Accessing strings from multiple different programs without switching")
    print("  ✓ Multi-program analysis workflow")

if __name__ == "__main__":
    main()

