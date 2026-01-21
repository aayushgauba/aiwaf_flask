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

            # Test geo blocked countries
            print("\n4️⃣ Testing geo blocked countries...")
            result = manager.add_geo_blocked_country("us")
            assert result, "Failed to add geo blocked country"
            
            countries = manager.list_geo_blocked_countries()
            assert "US" in countries, "Country not found in geo blocked list"
            print(f"✅ Geo blocked countries: {countries}")
            
            result = manager.remove_geo_blocked_country("US")
            assert result, "Failed to remove geo blocked country"
            
            countries_after = manager.list_geo_blocked_countries()
            assert "US" not in countries_after, "Country still in geo blocked list after removal"
            
            # Test statistics
            print("\n5️⃣ Testing statistics...")
            manager.show_stats()
            
            # Test export/import
            print("\n6️⃣ Testing export/import...")
            export_file = os.path.join(temp_dir, "test_export.json")
            result = manager.export_config(export_file)
            assert result, "Failed to export configuration"
            assert os.path.exists(export_file), "Export file not created"
            
            # Test removal
            print("\n7️⃣ Testing removal operations...")
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


def test_cli_geo_command(monkeypatch, tmp_path):
    """Test CLI geo blocked countries command."""
    from aiwaf_flask.cli import main

    monkeypatch.setenv("AIWAF_DATA_DIR", str(tmp_path))

    monkeypatch.setattr(sys, "argv", ["aiwaf_console.py", "geo", "list"])
    main()

    monkeypatch.setattr(sys, "argv", ["aiwaf_console.py", "geo", "add", "US"])
    main()

    monkeypatch.setattr(sys, "argv", ["aiwaf_console.py", "geo", "list"])
    main()

    monkeypatch.setattr(sys, "argv", ["aiwaf_console.py", "geo", "remove", "US"])
    main()


def test_cli_geoip_summary(monkeypatch, tmp_path, capsys):
    from aiwaf_flask.cli import AIWAFManager
    from aiwaf_flask import trainer as trainer_mod
    import aiwaf_flask.geoip as geoip_mod

    manager = AIWAFManager(str(tmp_path))

    monkeypatch.setattr(trainer_mod._trainer, "_read_all_logs", lambda: ["line1", "line2"])
    monkeypatch.setattr(
        trainer_mod._trainer,
        "_parse",
        lambda line: {"ip": "1.1.1.1"} if line == "line1" else {"ip": "2.2.2.2"},
    )
    monkeypatch.setattr(
        geoip_mod,
        "lookup_country_name",
        lambda ip, **kwargs: "United States" if ip == "1.1.1.1" else None,
    )

    manager.geoip_traffic_summary(log_dir=str(tmp_path), top=10, limit=0)

    out = capsys.readouterr().out
    assert "GeoIP traffic summary" in out
    assert "United States: 1" in out
    assert "UNKNOWN: 1" in out


def test_cli_exempt_path_command(monkeypatch, tmp_path):
    from aiwaf_flask.cli import main

    monkeypatch.setenv("AIWAF_DATA_DIR", str(tmp_path))

    monkeypatch.setattr(sys, "argv", ["aiwaf_console.py", "exempt-path", "list"])
    main()

    monkeypatch.setattr(sys, "argv", ["aiwaf_console.py", "exempt-path", "add", "/health", "--reason", "Health check"])
    main()

    monkeypatch.setattr(sys, "argv", ["aiwaf_console.py", "exempt-path", "list"])
    main()

    monkeypatch.setattr(sys, "argv", ["aiwaf_console.py", "exempt-path", "remove", "/health"])
    main()

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
