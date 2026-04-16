#!/usr/bin/env python3
"""Test the modified functions logic without running them"""

import sys
import os
import ast

# Add path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'threat-feed-aggregator'))

print("=" * 70)
print("SYNTAX & LOGIC VALIDATION")
print("=" * 70)

def check_file_syntax(filepath, desc):
    """Check if Python file has valid syntax"""
    print(f"\n{desc}:")
    try:
        with open(filepath) as f:
            code = f.read()
        ast.parse(code)
        print(f"  ✓ Syntax is valid")
        return True
    except SyntaxError as e:
        print(f"  ✗ Syntax Error: {e}")
        return False

def check_function_exists(filepath, func_name):
    """Check if function exists in file"""
    try:
        with open(filepath) as f:
            code = f.read()
        tree = ast.parse(code)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == func_name:
                return True
        return False
    except:
        return False

# Test 1: dns_deduplication.py
dns_file = "threat-feed-aggregator/threat_feed_aggregator/services/dns_deduplication.py"
if check_file_syntax(dns_file, "1. dns_deduplication.py syntax"):
    # Check for new import
    with open(dns_file) as f:
        content = f.read()
    if 'from ..config_manager import read_stats, write_stats' in content:
        print("  ✓ config_manager imports added")
    else:
        print("  ✗ config_manager imports NOT found")
    
    if 'stats["dedup_stats"]["total_deleted"] +=' in content:
        print("  ✓ total_deleted increment logic added")
    else:
        print("  ✗ total_deleted logic NOT found")
    
    if 'write_stats(stats)' in content:
        print("  ✓ stats write logic added")
    else:
        print("  ✗ stats write logic NOT found")

# Test 2: tools.py
tools_file = "threat-feed-aggregator/threat_feed_aggregator/routes/tools.py"
if check_file_syntax(tools_file, "2. tools.py syntax"):
    # Check if new functions exist
    if check_function_exists(tools_file, 'get_dns_dedup_status'):
        print("  ✓ get_dns_dedup_status() function added")
    else:
        print("  ✗ get_dns_dedup_status() function NOT found")
    
    # Check if analyze_dns_duplicates is updated
    with open(tools_file) as f:
        content = f.read()
    if 'total_deleted' in content and 'stats.get("dedup_stats"' in content:
        print("  ✓ total_deleted in analyze_dns_duplicates()")
    else:
        print("  ✗ total_deleted NOT found in analyze_dns_duplicates()")

# Test 3: Check imports in files
print("\n3. Checking imports consistency:")
dns_content = open(dns_file).read()
tools_content = open(tools_file).read()

missing = []
if 'import json' not in tools_content:
    missing.append("  ✗ tools.py missing 'import json'")
else:
    print("  ✓ tools.py has 'import json'")

if 'from pathlib import Path' not in tools_content:
    missing.append("  ✗ tools.py missing 'from pathlib import Path'")
else:
    print("  ✓ tools.py has 'from pathlib import Path'")

if missing:
    for msg in missing:
        print(msg)

print("\n" + "=" * 70)
print("VALIDATION COMPLETE")
print("=" * 70)
