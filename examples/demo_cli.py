#!/usr/bin/env python3
"""
Comprehensive AIWAF CLI Demo

Demonstrates all CLI functionality with real examples.
"""

import os
import sys
import subprocess
from pathlib import Path

def run_command(cmd):
    """Run a CLI command and return output."""
    print(f"$ {cmd}")
    result = subprocess.run(cmd.split(), capture_output=True, text=True, cwd=Path(__file__).parent)
    if result.stdout:
        print(result.stdout.strip())
    if result.stderr:
        print(f"ERROR: {result.stderr.strip()}")
    print()
    return result.returncode == 0

def main():
    """Run comprehensive CLI demo."""
    print("🚀 AIWAF Flask CLI Comprehensive Demo")
    print("=" * 60)
    
    commands = [
        # Initial status
        "python aiwaf_console.py stats",
        
        # Add multiple IPs to whitelist
        "python aiwaf_console.py add whitelist 192.168.1.100",
        "python aiwaf_console.py add whitelist 192.168.1.200",
        "python aiwaf_console.py add whitelist 10.0.0.50",
        
        # Add IPs to blacklist with reasons
        "python aiwaf_console.py add blacklist 203.0.113.10 --reason 'SQL injection attempts'",
        "python aiwaf_console.py add blacklist 198.51.100.5 --reason 'Brute force login'",
        "python aiwaf_console.py add blacklist 10.0.0.1 --reason 'Suspicious scanning'",
        
        # Add security keywords
        "python aiwaf_console.py add keyword 'union select'",
        "python aiwaf_console.py add keyword 'drop table'",
        "python aiwaf_console.py add keyword '<script>'",
        "python aiwaf_console.py add keyword 'eval('",
        
        # Show all data
        "python aiwaf_console.py list all",
        
        # Show statistics
        "python aiwaf_console.py stats",
        
        # Export configuration
        "python aiwaf_console.py export demo_backup.json",
        
        # Test removal
        "python aiwaf_console.py remove whitelist 10.0.0.50",
        "python aiwaf_console.py remove blacklist 10.0.0.1",
        
        # Final status
        "python aiwaf_console.py list all",
        "python aiwaf_console.py stats"
    ]
    
    success_count = 0
    for cmd in commands:
        if run_command(cmd):
            success_count += 1
    
    print(f"🎉 Demo completed! {success_count}/{len(commands)} commands successful")
    
    # Show the exported file
    if os.path.exists("demo_backup.json"):
        print("\n📄 Exported configuration preview:")
        with open("demo_backup.json", 'r') as f:
            content = f.read()
            print(content[:500] + "..." if len(content) > 500 else content)

if __name__ == '__main__':
    main()