#!/usr/bin/env python3
"""
Diagnostic script to debug AIWAF CLI issues in deployed environments
"""

import os
import sys
from pathlib import Path
import csv

def diagnose_aiwaf_cli():
    """Diagnose AIWAF CLI data directory and file issues."""
    print("🔍 AIWAF CLI Diagnostic Report")
    print("=" * 50)
    
    # Check current working directory
    print(f"📍 Current working directory: {os.getcwd()}")
    
    # Check environment variables
    data_dir_env = os.environ.get('AIWAF_DATA_DIR')
    print(f"🌍 AIWAF_DATA_DIR environment variable: {data_dir_env or 'Not set'}")
    
    # Check default data directory
    default_data_dir = 'aiwaf_data'
    actual_data_dir = data_dir_env or default_data_dir
    print(f"📁 Expected data directory: {actual_data_dir}")
    
    # Check if data directory exists
    data_path = Path(actual_data_dir)
    print(f"📂 Data directory exists: {data_path.exists()}")
    print(f"📂 Data directory absolute path: {data_path.absolute()}")
    
    if data_path.exists():
        print(f"📂 Data directory contents:")
        try:
            for item in data_path.iterdir():
                print(f"   • {item.name}")
                if item.is_file() and item.suffix == '.csv':
                    print(f"     - Size: {item.stat().st_size} bytes")
                    print(f"     - Readable: {os.access(item, os.R_OK)}")
        except PermissionError:
            print("   ❌ Permission denied accessing data directory")
    
    # Check specific CSV files
    csv_files = ['whitelist.csv', 'blacklist.csv', 'keywords.csv']
    for csv_file in csv_files:
        csv_path = data_path / csv_file
        print(f"\n📄 {csv_file}:")
        print(f"   • Exists: {csv_path.exists()}")
        
        if csv_path.exists():
            try:
                print(f"   • Size: {csv_path.stat().st_size} bytes")
                print(f"   • Readable: {os.access(csv_path, os.R_OK)}")
                
                # Try to read first few lines
                with open(csv_path, 'r', newline='') as f:
                    lines = f.readlines()
                    print(f"   • Total lines: {len(lines)}")
                    if lines:
                        print(f"   • Header: {lines[0].strip()}")
                        if len(lines) > 1:
                            print(f"   • First data row: {lines[1].strip()}")
                            
                        # Try CSV parsing
                        f.seek(0)
                        reader = csv.reader(f)
                        try:
                            header = next(reader, None)
                            data_rows = list(reader)
                            print(f"   • CSV header: {header}")
                            print(f"   • Data rows count: {len(data_rows)}")
                            if data_rows:
                                print(f"   • First data row parsed: {data_rows[0]}")
                        except Exception as e:
                            print(f"   ❌ CSV parsing error: {e}")
                            
            except Exception as e:
                print(f"   ❌ Error reading file: {e}")
    
    # Test the CLI storage functions directly
    print(f"\n🧪 Testing CLI storage functions:")
    try:
        sys.path.insert(0, os.path.dirname(__file__))
        from aiwaf_flask.cli import AIWAFManager
        
        manager = AIWAFManager(data_dir_env)
        
        # Test each function
        try:
            whitelist = manager.list_whitelist()
            print(f"   • Whitelist function result: {len(whitelist)} items - {list(whitelist)[:3]}...")
        except Exception as e:
            print(f"   ❌ Whitelist function error: {e}")
            
        try:
            blacklist = manager.list_blacklist()
            print(f"   • Blacklist function result: {len(blacklist)} items - {list(blacklist.keys())[:3]}...")
        except Exception as e:
            print(f"   ❌ Blacklist function error: {e}")
            
        try:
            keywords = manager.list_keywords()
            print(f"   • Keywords function result: {len(keywords)} items - {list(keywords)[:3]}...")
        except Exception as e:
            print(f"   ❌ Keywords function error: {e}")
            
    except Exception as e:
        print(f"   ❌ Error importing/testing CLI manager: {e}")
    
    print(f"\n✅ Diagnostic complete!")
    print(f"💡 To fix path issues, try:")
    print(f"   • Set AIWAF_DATA_DIR environment variable to absolute path")
    print(f"   • Run CLI from the same directory as your app")
    print(f"   • Use --data-dir parameter to specify absolute path")

if __name__ == '__main__':
    diagnose_aiwaf_cli()