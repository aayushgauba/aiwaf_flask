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
    
    def analyze_logs(self, log_dir: Optional[str] = None, log_format: str = 'combined'):
        """Analyze AIWAF logs and show statistics."""
        try:
            from .logging_middleware import analyze_access_logs
            
            if log_dir:
                stats = analyze_access_logs(log_dir, log_format)
            else:
                # Use default log directory
                stats = analyze_access_logs('aiwaf_logs', log_format)
            
            if 'error' in stats:
                print(f"❌ {stats['error']}")
                return False
            
            print("\n📊 AIWAF Access Log Analysis")
            print("=" * 50)
            print(f"Total Requests: {stats['total_requests']}")
            print(f"Blocked Requests: {stats['blocked_requests']}")
            print(f"Unique IPs: {len(stats.get('ips', {}))}")
            print(f"Block Rate: {(stats['blocked_requests']/stats['total_requests']*100):.1f}%" if stats['total_requests'] > 0 else "Block Rate: 0.0%")
            
            # Performance metrics
            if 'avg_response_time' in stats:
                print(f"Average Response Time: {stats['avg_response_time']:.0f}ms")
                print(f"95th Percentile Response Time: {stats.get('p95_response_time', 0):.0f}ms")
            
            # Status code distribution
            if stats.get('status_codes'):
                print(f"\n📈 Status Code Distribution:")
                for code, count in sorted(stats['status_codes'].items()):
                    percentage = (count / stats['total_requests'] * 100) if stats['total_requests'] > 0 else 0
                    print(f"  • {code}: {count} ({percentage:.1f}%)")
            
            # Top IPs
            if stats.get('top_ips'):
                print(f"\n🌐 Top Client IPs:")
                for ip, count in stats['top_ips'][:5]:
                    percentage = (count / stats['total_requests'] * 100) if stats['total_requests'] > 0 else 0
                    print(f"  • {ip}: {count} requests ({percentage:.1f}%)")
            
            # Top paths
            if stats.get('top_paths'):
                print(f"\n� Most Requested Paths:")
                for path, count in stats['top_paths'][:5]:
                    print(f"  • {path}: {count} requests")
            
            # Blocked request reasons
            if stats.get('blocked_reasons'):
                print(f"\n🚫 Block Reasons:")
                for reason, count in sorted(stats['blocked_reasons'].items(), key=lambda x: x[1], reverse=True):
                    print(f"  • {reason}: {count} times")
            
            # Hourly distribution
            if stats.get('hourly_distribution'):
                print(f"\n🕐 Hourly Request Distribution:")
                max_requests = max(stats['hourly_distribution'].values()) if stats['hourly_distribution'] else 1
                for hour in sorted(stats['hourly_distribution'].keys()):
                    count = stats['hourly_distribution'][hour]
                    bar_length = int((count / max_requests) * 30)  # Scale to 30 chars max
                    bar = "█" * bar_length
                    print(f"  {hour}:00 {bar:<30} {count}")
            
            return True
            
        except Exception as e:
            print(f"❌ Error analyzing logs: {e}")
            return False
    
    def train_model(self, log_dir: Optional[str] = None, disable_ai: bool = False, 
                   min_ai_logs: int = 10000, force_ai: bool = False, verbose: bool = False):
        """Train AIWAF AI model from access logs."""
        try:
            from flask import Flask
            from .trainer import train_from_logs
            
            if verbose:
                print("🚀 AIWAF Flask Training Tool")
                print("=" * 40)
                print(f"Log directory: {log_dir or 'aiwaf_logs'}")
                print(f"AI training: {'disabled' if disable_ai else 'enabled'}")
                print(f"Min AI logs threshold: {min_ai_logs}")
                print(f"Force AI: {force_ai}")
                print("=" * 40)
            
            # Create minimal Flask app for training
            app = Flask(__name__)
            
            # Configure AIWAF settings
            app.config['AIWAF_LOG_DIR'] = log_dir or 'aiwaf_logs'
            app.config['AIWAF_DYNAMIC_TOP_N'] = 15
            app.config['AIWAF_AI_CONTAMINATION'] = 0.05
            app.config['AIWAF_MIN_AI_LOGS'] = min_ai_logs
            app.config['AIWAF_FORCE_AI'] = force_ai
            
            # Optional settings (can be customized)
            app.config['AIWAF_EXEMPT_PATHS'] = {'/health', '/status', '/favicon.ico'}
            app.config['AIWAF_EXEMPT_KEYWORDS'] = ['health', 'status', 'ping', 'check']
            
            # Set data directory for training
            if hasattr(self, 'storage') and 'data_dir' in self.storage:
                app.config['AIWAF_DATA_DIR'] = self.storage['data_dir']()
            
            # Run training with app context
            with app.app_context():
                train_from_logs(app, disable_ai=disable_ai)
            
            if verbose:
                print("\n✅ Training completed successfully!")
                if not disable_ai:
                    print("🤖 AI model saved and ready for anomaly detection")
                else:
                    print("📚 Keyword learning completed")
                print("🛡️  Enhanced protection is now active!")
            else:
                print("✅ Training completed successfully!")
            
            return True
            
        except ImportError as e:
            if 'flask' in str(e).lower():
                print("❌ Flask is required for training. Install with: pip install flask")
            else:
                print(f"❌ Missing training dependencies: {e}")
                if not disable_ai:
                    print("💡 Try with --disable-ai for keyword-only training")
            return False
        except Exception as e:
            print(f"❌ Training failed: {e}")
            if not disable_ai:
                print("💡 Try with --disable-ai if AI dependencies are missing")
            return False
    
    def model_diagnostics(self, check: bool = False, retrain: bool = False, info: bool = False):
        """Run model diagnostics and management."""
        try:
            from pathlib import Path
            import pickle
            import warnings
            
            # Use the same model path function as trainer
            from .trainer import get_default_model_path
            model_path = Path(get_default_model_path())
            
            if info or check:
                print("🔧 AIWAF Model Diagnostics")
                print("=" * 50)
                print(f"📁 Model path: {model_path}")
                print(f"📄 Model exists: {model_path.exists()}")
                
                if not model_path.exists():
                    print("❌ No model found")
                    if retrain:
                        print("🔄 Proceeding with training...")
                        return self.train_model(verbose=True)
                    else:
                        print("💡 Run 'aiwaf train' to create a model")
                        return False
            
            if check or info:
                # Try to load and check the model
                with warnings.catch_warnings(record=True) as w:
                    warnings.simplefilter("always")
                    
                    try:
                        # Use joblib instead of pickle (matches trainer save format)
                        import joblib
                        model_data = joblib.load(model_path)
                        
                        # Check for warnings
                        sklearn_warnings = [warning for warning in w 
                                          if 'sklearn' in str(warning.message).lower()]
                        
                        if sklearn_warnings:
                            print("⚠️  Sklearn version compatibility warnings:")
                            for warning in sklearn_warnings:
                                print(f"   {warning.message}")
                            
                            if check:
                                print("\n💡 Model loads but may have compatibility issues")
                                print("   Consider retraining: aiwaf model --retrain")
                        else:
                            print("✅ Model loads successfully without warnings")
                        
                        if info:
                            # Show model information
                            if isinstance(model_data, dict):
                                print("\n📊 Model Information:")
                                print(f"   Format: Enhanced (with metadata)")
                                for key, value in model_data.items():
                                    if key == 'model':
                                        print(f"   Model Type: {type(value).__name__}")
                                    else:
                                        print(f"   {key}: {value}")
                            else:
                                print("\n📊 Model Information:")
                                print(f"   Format: Legacy (direct model)")
                                print(f"   Model Type: {type(model_data).__name__}")
                        
                        # Get file stats
                        import os
                        file_stats = os.stat(model_path)
                        file_size = file_stats.st_size
                        modified_time = datetime.fromtimestamp(file_stats.st_mtime)
                        
                        if info:
                            print(f"\n📄 File Information:")
                            print(f"   Size: {file_size:,} bytes")
                            print(f"   Modified: {modified_time}")
                            
                            # Try to get sklearn version info
                            try:
                                import sklearn
                                print(f"   Current sklearn: {sklearn.__version__}")
                            except ImportError:
                                print(f"   Current sklearn: Not installed")
                        
                        return True
                        
                    except Exception as e:
                        print(f"❌ Error loading model: {e}")
                        if retrain:
                            print("🔄 Model appears corrupted, proceeding with retraining...")
                            return self.train_model(verbose=True)
                        else:
                            print("💡 Model may be corrupted. Try: aiwaf model --retrain")
                            return False
            
            if retrain:
                print("🔄 Retraining model with current dependencies...")
                return self.train_model(verbose=True)
            
            return True
            
        except Exception as e:
            print(f"❌ Model diagnostics failed: {e}")
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
    
    # Log analysis command
    logs_parser = subparsers.add_parser('logs', help='Analyze request logs')
    logs_parser.add_argument('--log-dir', help='Custom log directory path')
    logs_parser.add_argument('--format', choices=['combined', 'common', 'csv', 'json'], 
                           default='combined', help='Log format to analyze')
    
    # Train command
    train_parser = subparsers.add_parser('train', help='Train AI model from logs')
    train_parser.add_argument('--log-dir', help='Custom log directory path (default: aiwaf_logs)')
    train_parser.add_argument('--disable-ai', action='store_true', 
                            help='Disable AI model training (keyword learning only)')
    train_parser.add_argument('--min-ai-logs', type=int, default=10000,
                            help='Minimum log lines required for AI training (default: 10000)')
    train_parser.add_argument('--force-ai', action='store_true',
                            help='Force AI training even with insufficient log data')
    train_parser.add_argument('--verbose', '-v', action='store_true',
                            help='Enable verbose output')
    
    # Model diagnostics command
    model_parser = subparsers.add_parser('model', help='Model diagnostics and management')
    model_parser.add_argument('--check', action='store_true',
                            help='Check model compatibility')
    model_parser.add_argument('--retrain', action='store_true',
                            help='Force retrain model with current dependencies')
    model_parser.add_argument('--info', action='store_true',
                            help='Show model information')
    
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
    
    elif args.command == 'logs':
        log_format = getattr(args, 'format', 'combined')
        manager.analyze_logs(args.log_dir, log_format)
    
    elif args.command == 'train':
        manager.train_model(args.log_dir, args.disable_ai, args.min_ai_logs, args.force_ai, args.verbose)
    
    elif args.command == 'model':
        # Handle model diagnostics
        if not any([args.check, args.retrain, args.info]):
            # Default to showing info if no specific action
            args.info = True
        manager.model_diagnostics(args.check, args.retrain, args.info)
    
    elif args.command == 'export':
        manager.export_config(args.filename)
    
    elif args.command == 'import':
        manager.import_config(args.filename)

if __name__ == '__main__':
    main()