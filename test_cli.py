#!/usr/bin/env python3
"""
Test AIWAF CLI functionality
"""

import tempfile
import os
import sys
from pathlib import Path

# Add package to path
sys.path.insert(0, str(Path(__file__).parent))

def test_cli_functionality():
    """Test basic CLI operations."""
    print("🧪 Testing AIWAF CLI functionality...")
    
    try:
        from aiwaf_flask.cli import AIWAFManager
        
        # Create temporary directory for testing
        with tempfile.TemporaryDirectory() as temp_dir:
            print(f"📁 Using temporary directory: {temp_dir}")
            
            # Initialize manager with temp directory
            manager = AIWAFManager(temp_dir)
            
            # Test adding to whitelist
            print("\n1️⃣ Testing whitelist operations...")
            result = manager.add_to_whitelist("192.168.1.100")
            assert result, "Failed to add IP to whitelist"
            
            whitelist = manager.list_whitelist()
            assert "192.168.1.100" in whitelist, "IP not found in whitelist"
            print(f"✅ Whitelist: {whitelist}")
            
            # Test adding to blacklist
            print("\n2️⃣ Testing blacklist operations...")
            result = manager.add_to_blacklist("10.0.0.5", "Test IP")
            assert result, "Failed to add IP to blacklist"
            
            blacklist = manager.list_blacklist()
            assert "10.0.0.5" in blacklist, "IP not found in blacklist"
            print(f"✅ Blacklist: {list(blacklist.keys())}")
            
            # Test adding keywords
            print("\n3️⃣ Testing keyword operations...")
            result = manager.add_keyword("test-attack")
            assert result, "Failed to add keyword"
            
            keywords = manager.list_keywords()
            assert "test-attack" in keywords, "Keyword not found in list"
            print(f"✅ Keywords: {keywords}")
            
            # Test statistics
            print("\n4️⃣ Testing statistics...")
            manager.show_stats()
            
            # Test export/import
            print("\n5️⃣ Testing export/import...")
            export_file = os.path.join(temp_dir, "test_export.json")
            result = manager.export_config(export_file)
            assert result, "Failed to export configuration"
            assert os.path.exists(export_file), "Export file not created"
            
            # Test removal
            print("\n6️⃣ Testing removal operations...")
            result = manager.remove_from_whitelist("192.168.1.100")
            assert result, "Failed to remove IP from whitelist"
            
            whitelist_after = manager.list_whitelist()
            assert "192.168.1.100" not in whitelist_after, "IP still in whitelist after removal"
            print(f"✅ Whitelist after removal: {whitelist_after}")
            
            print("\n🎉 All CLI tests passed!")
            return True
            
    except Exception as e:
        print(f"❌ CLI test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_console_script():
    """Test the console script entry point."""
    print("\n🧪 Testing console script...")
    
    try:
        # Test importing the console script
        import aiwaf_console
        print("✅ Console script imports successfully")
        
        # Test CLI argument parsing (without execution)
        from aiwaf_flask.cli import main
        print("✅ CLI main function accessible")
        
        return True
    except Exception as e:
        print(f"❌ Console script test failed: {e}")
        return False

if __name__ == '__main__':
    print("🚀 AIWAF CLI Test Suite")
    print("=" * 50)
    
    success = True
    
    # Test CLI functionality
    if not test_cli_functionality():
        success = False
    
    # Test console script
    if not test_console_script():
        success = False
    
    if success:
        print("\n🎉 All tests passed! CLI is ready to use.")
        print("\nUsage examples:")
        print("  python aiwaf_console.py list all")
        print("  python aiwaf_console.py add whitelist 192.168.1.10")
        print("  python aiwaf_console.py add blacklist 10.0.0.1 --reason 'Suspicious activity'")
        print("  python aiwaf_console.py stats")
    else:
        print("\n❌ Some tests failed. Please check the errors above.")
        sys.exit(1)