#!/usr/bin/env python3
"""
AIWAF Flask Setup and CLI Tool

This script can:
1. Install Flask if needed for web protection
2. Work as standalone CLI tool for managing data
3. Test the installation
"""

import sys
import subprocess
import os
from pathlib import Path

def check_flask_available():
    """Check if Flask is available."""
    try:
        import flask
        return True, flask.__version__
    except ImportError:
        return False, None

def install_flask():
    """Install Flask using pip."""
    try:
        print("📦 Installing Flask...")
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'flask'])
        return True
    except subprocess.CalledProcessError:
        return False

def show_usage():
    """Show usage information."""
    print("\n🚀 AIWAF Flask Setup and CLI Tool")
    print("=" * 50)
    
    flask_available, flask_version = check_flask_available()
    
    if flask_available:
        print(f"✅ Flask {flask_version} is available")
        print("🛡️  Web protection features: ENABLED")
    else:
        print("⚠️  Flask not available")
        print("🛡️  Web protection features: DISABLED")
        print("📊 CLI management features: ENABLED")
    
    print("\n📋 Available Commands:")
    print("  python aiwaf_setup.py install-flask    # Install Flask")
    print("  python aiwaf_setup.py cli-help         # Show CLI help")
    print("  python aiwaf_setup.py test-cli         # Test CLI functions")
    print("  python aiwaf_setup.py demo             # Run demo")
    
    print("\n🔧 CLI Management Commands:")
    print("  python aiwaf_console.py stats          # Show statistics")
    print("  python aiwaf_console.py list all       # List all data")
    print("  python aiwaf_console.py add whitelist <ip>")
    print("  python aiwaf_console.py add blacklist <ip> --reason '<reason>'")
    print("  python aiwaf_console.py add keyword '<keyword>'")
    print("  python aiwaf_console.py remove whitelist <ip>")
    print("  python aiwaf_console.py export <file.json>")

def test_cli():
    """Test CLI functionality."""
    print("🧪 Testing CLI functionality...")
    
    # Test basic commands
    commands = [
        "python aiwaf_console.py stats",
        "python aiwaf_console.py add whitelist 192.168.1.99",
        "python aiwaf_console.py add blacklist 10.0.0.99 --reason 'Test IP'",
        "python aiwaf_console.py add keyword 'test-keyword'",
        "python aiwaf_console.py list all",
        "python aiwaf_console.py remove whitelist 192.168.1.99",
        "python aiwaf_console.py remove blacklist 10.0.0.99"
    ]
    
    for cmd in commands:
        print(f"\n$ {cmd}")
        try:
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                print("✅ Success")
                if result.stdout:
                    # Show only key lines
                    lines = result.stdout.strip().split('\n')
                    for line in lines[-3:]:  # Show last 3 lines
                        if line.strip():
                            print(f"  {line}")
            else:
                print("❌ Failed")
                if result.stderr:
                    print(f"  Error: {result.stderr.strip()}")
        except Exception as e:
            print(f"❌ Error: {e}")

def run_demo():
    """Run a quick demo."""
    print("🎬 AIWAF CLI Demo")
    print("=" * 30)
    
    test_commands = [
        ("Show current status", "python aiwaf_console.py stats"),
        ("Add trusted IP", "python aiwaf_console.py add whitelist 192.168.1.200"),
        ("Block suspicious IP", "python aiwaf_console.py add blacklist 203.0.113.1 --reason 'Port scanning'"),
        ("Add dangerous keyword", "python aiwaf_console.py add keyword '<script>alert'"),
        ("Show all data", "python aiwaf_console.py list all"),
        ("Export config", "python aiwaf_console.py export demo_config.json")
    ]
    
    for description, cmd in test_commands:
        print(f"\n🔹 {description}")
        print(f"$ {cmd}")
        try:
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=10)
            if result.stdout:
                # Show relevant output
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if any(marker in line for marker in ['✅', '📊', '🟢', '🔴', '🚫', '📁']):
                        print(f"  {line}")
        except Exception as e:
            print(f"  ❌ Error: {e}")
    
    print(f"\n🎉 Demo completed! Check 'demo_config.json' for exported configuration.")

def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        show_usage()
        return
    
    command = sys.argv[1].lower()
    
    if command == 'install-flask':
        flask_available, _ = check_flask_available()
        if flask_available:
            print("✅ Flask is already installed")
        else:
            if install_flask():
                print("✅ Flask installed successfully")
                print("🛡️  Web protection features are now available")
            else:
                print("❌ Failed to install Flask")
                print("💡 Try: pip install flask")
    
    elif command == 'cli-help':
        subprocess.run([sys.executable, 'aiwaf_console.py', '--help'])
    
    elif command == 'test-cli':
        test_cli()
    
    elif command == 'demo':
        run_demo()
    
    else:
        print(f"❌ Unknown command: {command}")
        show_usage()

if __name__ == '__main__':
    main()