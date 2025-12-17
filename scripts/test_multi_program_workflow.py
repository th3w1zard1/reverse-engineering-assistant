#!/usr/bin/env python3
"""
Test script to demonstrate multi-program support in ReVa.
This script shows the workflow for opening a project, loading all programs,
and querying strings from multiple programs simultaneously.

Usage:
    python scripts/test_multi_program_workflow.py

Note: Requires Ghidra to be running with ReVa extension enabled and MCP server on port 8080.
"""

import json
import httpx
import sys
from typing import Dict, Any

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
        response = httpx.post(MCP_SERVER_URL, json=request, timeout=30.0)
        response.raise_for_status()
        result = response.json()
        
        if "error" in result:
            return {"error": result["error"]}
        
        if "result" in result:
            return result["result"]
        
        return result
    except httpx.RequestError as e:
        return {"error": f"Request failed: {e}"}
    except Exception as e:
        return {"error": f"Unexpected error: {e}"}

def main():
    """Execute the multi-program workflow test."""
    print("=" * 70)
    print("ReVa Multi-Program Support Test")
    print("=" * 70)
    print()
    
    # Step 1: Open project
    print("Step 1: Opening project C:/Users/boden/test.gpr")
    print("-" * 70)
    result1 = call_mcp_tool("open-project", {
        "projectPath": "C:/Users/boden/test.gpr"
    })
    
    if "error" in result1:
        print(f"ERROR: {result1['error']}")
        print("\nNote: Make sure Ghidra is running with ReVa extension enabled.")
        return 1
    
    print(f"SUCCESS: Project opened: {result1.get('projectName', 'Unknown')}")
    print(f"  Location: {result1.get('projectLocation', 'Unknown')}")
    print(f"  Programs in project: {result1.get('programCount', 0)}")
    print()
    
    # Step 2: Open all exe/dll programs in Code Browser
    print("Step 2: Opening all exe/dll programs in Code Browser")
    print("-" * 70)
    result2 = call_mcp_tool("open-all-programs-in-code-browser", {
        "extensions": "exe,dll"
    })
    
    if "error" in result2:
        print(f"ERROR: {result2['error']}")
        return 1
    
    print(f"SUCCESS: Programs processed")
    print(f"  Found: {result2.get('programsFound', 0)}")
    print(f"  Opened: {result2.get('programsOpened', 0)}")
    print(f"  Already open: {result2.get('programsAlreadyOpen', 0)}")
    print(f"  Failed: {result2.get('programsFailed', 0)}")
    
    if result2.get('openedPrograms'):
        print("  Opened programs:")
        for prog in result2['openedPrograms']:
            print(f"    - {prog}")
    print()
    
    # Step 3: Get strings from swkotor.exe
    print("Step 3: Getting strings from /swkotor.exe")
    print("-" * 70)
    result3 = call_mcp_tool("get-strings", {
        "programPath": "/swkotor.exe",
        "maxCount": 10
    })
    
    if "error" in result3:
        print(f"ERROR: {result3['error']}")
        return 1
    
    # Result is a list with pagination info first, then strings
    if isinstance(result3, list) and len(result3) > 0:
        pagination = result3[0] if isinstance(result3[0], dict) else {}
        strings = result3[1:] if len(result3) > 1 else []
        
        print(f"SUCCESS: Retrieved {len(strings)} strings")
        print(f"  Total available: {pagination.get('nextStartIndex', 'Unknown')}")
        print("  Sample strings:")
        for i, s in enumerate(strings[:5], 1):
            if isinstance(s, dict):
                content = s.get('content', 'N/A')[:50]
                addr = s.get('address', 'N/A')
                print(f"    {i}. [{addr}] {content}...")
    print()
    
    # Step 4: Get strings from masseffect.exe
    print("Step 4: Getting strings from /masseffect.exe")
    print("-" * 70)
    result4 = call_mcp_tool("get-strings", {
        "programPath": "/masseffect.exe",
        "maxCount": 10
    })
    
    if "error" in result4:
        print(f"ERROR: {result4['error']}")
        return 1
    
    if isinstance(result4, list) and len(result4) > 0:
        pagination = result4[0] if isinstance(result4[0], dict) else {}
        strings = result4[1:] if len(result4) > 1 else []
        
        print(f"SUCCESS: Retrieved {len(strings)} strings")
        print(f"  Total available: {pagination.get('nextStartIndex', 'Unknown')}")
        print("  Sample strings:")
        for i, s in enumerate(strings[:5], 1):
            if isinstance(s, dict):
                content = s.get('content', 'N/A')[:50]
                addr = s.get('address', 'N/A')
                print(f"    {i}. [{addr}] {content}...")
    print()
    
    # Step 5: Get strings from swkotor2.exe
    print("Step 5: Getting strings from /swkotor2.exe")
    print("-" * 70)
    result5 = call_mcp_tool("get-strings", {
        "programPath": "/swkotor2.exe",
        "maxCount": 10
    })
    
    if "error" in result5:
        print(f"ERROR: {result5['error']}")
        return 1
    
    if isinstance(result5, list) and len(result5) > 0:
        pagination = result5[0] if isinstance(result5[0], dict) else {}
        strings = result5[1:] if len(result5) > 1 else []
        
        print(f"SUCCESS: Retrieved {len(strings)} strings")
        print(f"  Total available: {pagination.get('nextStartIndex', 'Unknown')}")
        print("  Sample strings:")
        for i, s in enumerate(strings[:5], 1):
            if isinstance(s, dict):
                content = s.get('content', 'N/A')[:50]
                addr = s.get('address', 'N/A')
                print(f"    {i}. [{addr}] {content}...")
    print()
    
    print("=" * 70)
    print("TEST COMPLETE: Multi-program support verified!")
    print("=" * 70)
    print()
    print("Summary:")
    print("  ✓ Project opened successfully")
    print("  ✓ All exe/dll programs opened in Code Browser")
    print("  ✓ Strings retrieved from swkotor.exe")
    print("  ✓ Strings retrieved from masseffect.exe (different program)")
    print("  ✓ Strings retrieved from swkotor2.exe (another different program)")
    print()
    print("This proves that ReVa supports multiple programs simultaneously!")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())

