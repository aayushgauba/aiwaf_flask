#!/usr/bin/env python3
"""
AIWAF Flask CLI Management Tool

Provides command-line functions for managing AIWAF data:
- Add/remove IPs from whitelist/blacklist
- View current lists
- Clear data
- Import/export configurations
"""

import argparse
import sys
import json
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any

def get_storage_instance():
    """Get storage instance based on available configuration."""
    try:
        # Import storage functions directly without importing Flask dependencies
        import csv
        import os
        from pathlib import Path
        
        def _get_data_dir():
            """Get data directory path."""
            return os.environ.get('AIWAF_DATA_DIR', 'aiwaf_data')
        
        def _read_csv_whitelist():
            """Read whitelist from CSV."""
            data_dir = Path(_get_data_dir())
            data_dir.mkdir(exist_ok=True)
            whitelist_file = data_dir / 'whitelist.csv'
            
            whitelist = set()
            if whitelist_file.exists():
                with open(whitelist_file, 'r', newline='') as f:
                    reader = csv.reader(f)
                    next(reader, None)  # Skip header
                    for row in reader:
                        if row and len(row) > 0:
                            whitelist.add(row[0])
            return whitelist
        
        def _read_csv_blacklist():
            """Read blacklist from CSV."""
            data_dir = Path(_get_data_dir())
            data_dir.mkdir(exist_ok=True)
            blacklist_file = data_dir / 'blacklist.csv'
            
            blacklist = {}
            if blacklist_file.exists():
                with open(blacklist_file, 'r', newline='') as f:
                    reader = csv.reader(f)
                    next(reader, None)  # Skip header
                    for row in reader:
                        if row and len(row) >= 2:
                            ip = row[0]
                            timestamp = row[1] if len(row) > 1 else ''
                            reason = row[2] if len(row) > 2 else ''
                            blacklist[ip] = {'timestamp': timestamp, 'reason': reason}
            return blacklist
        
        def _read_csv_keywords():
            """Read keywords from CSV."""
            data_dir = Path(_get_data_dir())
            data_dir.mkdir(exist_ok=True)
            keywords_file = data_dir / 'keywords.csv'
            
            keywords = set()
            if keywords_file.exists():
                with open(keywords_file, 'r', newline='') as f:
                    reader = csv.reader(f)
                    next(reader, None)  # Skip header
                    for row in reader:
                        if row and len(row) > 0:
                            keywords.add(row[0])
            return keywords
        
        def _append_csv_whitelist(ip):
            """Add IP to whitelist CSV."""
            data_dir = Path(_get_data_dir())
            data_dir.mkdir(exist_ok=True)
            whitelist_file = data_dir / 'whitelist.csv'
            
            # Check if file exists and has header
            file_exists = whitelist_file.exists()
            with open(whitelist_file, 'a', newline='') as f:
                writer = csv.writer(f)
                if not file_exists:
                    writer.writerow(['ip', 'timestamp'])
                writer.writerow([ip, datetime.now().isoformat()])
        
        def _append_csv_blacklist(ip, reason="Manual addition"):
            """Add IP to blacklist CSV."""
            data_dir = Path(_get_data_dir())
            data_dir.mkdir(exist_ok=True)
            blacklist_file = data_dir / 'blacklist.csv'
            
            # Check if file exists and has header
            file_exists = blacklist_file.exists()
            with open(blacklist_file, 'a', newline='') as f:
                writer = csv.writer(f)
                if not file_exists:
                    writer.writerow(['ip', 'timestamp', 'reason'])
                writer.writerow([ip, datetime.now().isoformat(), reason])
        
        def _append_csv_keyword(keyword):
            """Add keyword to keywords CSV."""
            data_dir = Path(_get_data_dir())
            data_dir.mkdir(exist_ok=True)
            keywords_file = data_dir / 'keywords.csv'
            
            # Check if file exists and has header
            file_exists = keywords_file.exists()
            with open(keywords_file, 'a', newline='') as f:
                writer = csv.writer(f)
                if not file_exists:
                    writer.writerow(['keyword', 'timestamp'])
                writer.writerow([keyword, datetime.now().isoformat()])
        
        return {
            'read_whitelist': _read_csv_whitelist,
            'read_blacklist': _read_csv_blacklist,
            'read_keywords': _read_csv_keywords,
            'add_whitelist': _append_csv_whitelist,
            'add_blacklist': _append_csv_blacklist,
            'add_keyword': _append_csv_keyword,
            'data_dir': _get_data_dir,
            'mode': 'CSV'
        }
    except Exception as e:
        print(f"⚠️  Storage not available: {e}")
        return None

class AIWAFManager:
    """AIWAF management class for CLI operations."""
    
    def __init__(self, data_dir: Optional[str] = None):
        self.storage = get_storage_instance()
        if not self.storage:
            print("❌ No storage backend available")
            sys.exit(1)
        
        if data_dir:
            # Override data directory if specified
            import os
            os.environ['AIWAF_DATA_DIR'] = data_dir
        
        print(f"📁 Using {self.storage['mode']} storage: {self.storage['data_dir']()}")
    
    def list_whitelist(self) -> List[str]:
        """Get all whitelisted IPs."""
        try:
            whitelist = self.storage['read_whitelist']()
            return sorted(list(whitelist))
        except Exception as e:
            print(f"❌ Error reading whitelist: {e}")
            return []
    
    def list_blacklist(self) -> Dict[str, Any]:
        """Get all blacklisted IPs with timestamps."""
        try:
            blacklist = self.storage['read_blacklist']()
            return dict(sorted(blacklist.items()))
        except Exception as e:
            print(f"❌ Error reading blacklist: {e}")
            return {}
    
    def list_keywords(self) -> List[str]:
        """Get all blocked keywords."""
        try:
            keywords = self.storage['read_keywords']()
            return sorted(list(keywords))
        except Exception as e:
            print(f"❌ Error reading keywords: {e}")
            return []
    
    def add_to_whitelist(self, ip: str) -> bool:
        """Add IP to whitelist."""
        try:
            self.storage['add_whitelist'](ip)
            print(f"✅ Added {ip} to whitelist")
            return True
        except Exception as e:
            print(f"❌ Error adding {ip} to whitelist: {e}")
            return False
    
    def add_to_blacklist(self, ip: str, reason: str = "Manual CLI addition") -> bool:
        """Add IP to blacklist."""
        try:
            self.storage['add_blacklist'](ip, reason)
            print(f"✅ Added {ip} to blacklist")
            return True
        except Exception as e:
            print(f"❌ Error adding {ip} to blacklist: {e}")
            return False
    
    def add_keyword(self, keyword: str) -> bool:
        """Add keyword to blocked list."""
        try:
            self.storage['add_keyword'](keyword)
            print(f"✅ Added '{keyword}' to blocked keywords")
            return True
        except Exception as e:
            print(f"❌ Error adding keyword '{keyword}': {e}")
            return False
    
    def remove_from_whitelist(self, ip: str) -> bool:
        """Remove IP from whitelist."""
        try:
            data_dir = Path(self.storage['data_dir']())
            whitelist_file = data_dir / 'whitelist.csv'
            
            if not whitelist_file.exists():
                print(f"❌ Whitelist file not found")
                return False
            
            # Read current data
            current = self.list_whitelist()
            if ip not in current:
                print(f"⚠️  {ip} not found in whitelist")
                return False
            
            # Rewrite file without the IP
            import csv
            with open(whitelist_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['ip', 'timestamp'])
                for existing_ip in current:
                    if existing_ip != ip:
                        writer.writerow([existing_ip, datetime.now().isoformat()])
            
            print(f"✅ Removed {ip} from whitelist")
            return True
        except Exception as e:
            print(f"❌ Error removing {ip} from whitelist: {e}")
            return False
    
    def remove_from_blacklist(self, ip: str) -> bool:
        """Remove IP from blacklist."""
        try:
            data_dir = Path(self.storage['data_dir']())
            blacklist_file = data_dir / 'blacklist.csv'
            
            if not blacklist_file.exists():
                print(f"❌ Blacklist file not found")
                return False
            
            # Read current data
            current = self.list_blacklist()
            if ip not in current:
                print(f"⚠️  {ip} not found in blacklist")
                return False
            
            # Rewrite file without the IP
            import csv
            with open(blacklist_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['ip', 'timestamp', 'reason'])
                for existing_ip, data in current.items():
                    if existing_ip != ip:
                        if isinstance(data, dict):
                            timestamp = data.get('timestamp', '')
                            reason = data.get('reason', '')
                        else:
                            # Handle string format (reason only)
                            timestamp = datetime.now().isoformat()
                            reason = str(data) if data else ''
                        writer.writerow([existing_ip, timestamp, reason])
            
            print(f"✅ Removed {ip} from blacklist")
            return True
        except Exception as e:
            print(f"❌ Error removing {ip} from blacklist: {e}")
            return False
    
    def show_stats(self):
        """Display statistics about current AIWAF data."""
        whitelist = self.list_whitelist()
        blacklist = self.list_blacklist()
        keywords = self.list_keywords()
        
        print("\n📊 AIWAF Statistics")
        print("=" * 50)
        print(f"Whitelisted IPs: {len(whitelist)}")
        print(f"Blacklisted IPs: {len(blacklist)}")
        print(f"Blocked Keywords: {len(keywords)}")
        print(f"Storage Mode: {self.storage['mode']}")
        print(f"Data Directory: {self.storage['data_dir']()}")
    
    def export_config(self, filename: str):
        """Export current configuration to JSON file."""
        try:
            config = {
                'whitelist': self.list_whitelist(),
                'blacklist': self.list_blacklist(),
                'keywords': self.list_keywords(),
                'exported_at': datetime.now().isoformat(),
                'storage_mode': self.storage['mode']
            }
            
            with open(filename, 'w') as f:
                json.dump(config, f, indent=2)
            
            print(f"✅ Configuration exported to {filename}")
            return True
        except Exception as e:
            print(f"❌ Error exporting configuration: {e}")
            return False
    
    def import_config(self, filename: str):
        """Import configuration from JSON file."""
        try:
            with open(filename, 'r') as f:
                config = json.load(f)
            
            success_count = 0
            
            # Import whitelist
            for ip in config.get('whitelist', []):
                if self.add_to_whitelist(ip):
                    success_count += 1
            
            # Import blacklist
            for ip, data in config.get('blacklist', {}).items():
                reason = data.get('reason', 'Imported from config') if isinstance(data, dict) else 'Imported from config'
                if self.add_to_blacklist(ip, reason):
                    success_count += 1
            
            # Import keywords
            for keyword in config.get('keywords', []):
                if self.add_keyword(keyword):
                    success_count += 1
            
            print(f"✅ Imported {success_count} items from {filename}")
            return True
        except Exception as e:
            print(f"❌ Error importing configuration: {e}")
            return False

def main():
    """Main CLI interface."""
    parser = argparse.ArgumentParser(description='AIWAF Flask Management Tool')
    parser.add_argument('--data-dir', help='Custom data directory path')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # List commands
    list_parser = subparsers.add_parser('list', help='List current data')
    list_parser.add_argument('type', choices=['whitelist', 'blacklist', 'keywords', 'all'], 
                           help='Type of data to list')
    
    # Add commands
    add_parser = subparsers.add_parser('add', help='Add item to list')
    add_parser.add_argument('type', choices=['whitelist', 'blacklist', 'keyword'], 
                          help='Type of list to add to')
    add_parser.add_argument('value', help='IP address or keyword to add')
    add_parser.add_argument('--reason', help='Reason for blacklisting (blacklist only)')
    
    # Remove commands
    remove_parser = subparsers.add_parser('remove', help='Remove item from list')
    remove_parser.add_argument('type', choices=['whitelist', 'blacklist'], 
                             help='Type of list to remove from')
    remove_parser.add_argument('value', help='IP address to remove')
    
    # Stats command
    subparsers.add_parser('stats', help='Show statistics')
    
    # Export/Import commands
    export_parser = subparsers.add_parser('export', help='Export configuration')
    export_parser.add_argument('filename', help='Output JSON file')
    
    import_parser = subparsers.add_parser('import', help='Import configuration')
    import_parser.add_argument('filename', help='Input JSON file')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize manager
    manager = AIWAFManager(args.data_dir)
    
    # Execute commands
    if args.command == 'list':
        if args.type == 'whitelist' or args.type == 'all':
            whitelist = manager.list_whitelist()
            print(f"\n🟢 Whitelisted IPs ({len(whitelist)}):")
            for ip in whitelist:
                print(f"  • {ip}")
        
        if args.type == 'blacklist' or args.type == 'all':
            blacklist = manager.list_blacklist()
            print(f"\n🔴 Blacklisted IPs ({len(blacklist)}):")
            for ip, data in blacklist.items():
                if isinstance(data, dict):
                    reason = data.get('reason', 'Unknown')
                    timestamp = data.get('timestamp', 'Unknown')
                    print(f"  • {ip} - {reason} ({timestamp})")
                else:
                    print(f"  • {ip}")
        
        if args.type == 'keywords' or args.type == 'all':
            keywords = manager.list_keywords()
            print(f"\n🚫 Blocked Keywords ({len(keywords)}):")
            for keyword in keywords:
                print(f"  • {keyword}")
    
    elif args.command == 'add':
        if args.type == 'whitelist':
            manager.add_to_whitelist(args.value)
        elif args.type == 'blacklist':
            reason = args.reason or "Manual CLI addition"
            manager.add_to_blacklist(args.value, reason)
        elif args.type == 'keyword':
            manager.add_keyword(args.value)
    
    elif args.command == 'remove':
        if args.type == 'whitelist':
            manager.remove_from_whitelist(args.value)
        elif args.type == 'blacklist':
            manager.remove_from_blacklist(args.value)
    
    elif args.command == 'stats':
        manager.show_stats()
    
    elif args.command == 'export':
        manager.export_config(args.filename)
    
    elif args.command == 'import':
        manager.import_config(args.filename)

if __name__ == '__main__':
    main()