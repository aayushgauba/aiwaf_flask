#!/usr/bin/env python3
"""
Debug logging middleware with verbose output to help diagnose issues.
"""

import os
import sys
from pathlib import Path
from flask import Flask
from aiwaf_flask import register_aiwaf_middlewares

def create_debug_app():
    """Create a debug-enabled Flask app to test user's issue."""
    
    # Create Flask app
    app = Flask(__name__)
    
    # Add debug configuration similar to what a user might have
    app.config.update({
        'AIWAF_LOG_DIR': 'user_test_logs',
        'AIWAF_LOG_FORMAT': 'combined',
        'AIWAF_ENABLE_LOGGING': True,
        'AIWAF_USE_CSV': True,
        'AIWAF_DATA_DIR': 'user_test_data',
        'DEBUG': True  # Enable debug mode like user might have
    })
    
    @app.route('/')
    def index():
        return '<h1>Debug Test App</h1><p>This is a test app to debug logging issues.</p>'
    
    @app.route('/api/test')
    def api_test():
        return {'status': 'ok', 'message': 'API test successful'}
    
    @app.route('/admin')
    def admin():
        return 'Admin page'
    
    print("=== AIWAF Debug App ===")
    print(f"Python version: {sys.version}")
    print(f"Working directory: {os.getcwd()}")
    print(f"App config: {dict(app.config)}")
    
    # Clean up existing logs
    log_dir = Path('user_test_logs')
    if log_dir.exists():
        import shutil
        shutil.rmtree(log_dir)
        print(f"Cleaned up: {log_dir}")
    
    # Register AIWAF
    print("\\nRegistering AIWAF middlewares...")
    try:
        register_aiwaf_middlewares(app)
        print("✓ AIWAF middlewares registered successfully")
    except Exception as e:
        print(f"✗ Failed to register AIWAF: {e}")
        import traceback
        traceback.print_exc()
        return None, str(e)
    
    # Verify logger attachment
    if hasattr(app, 'aiwaf_logger'):
        logger = app.aiwaf_logger
        print(f"✓ Logger attached: {type(logger)}")
        print(f"  Log directory: {logger.log_dir}")
        print(f"  Access log: {logger.access_log_file}")
        print(f"  Error log: {logger.error_log_file}")
        print(f"  AIWAF log: {logger.aiwaf_log_file}")
        print(f"  Log format: {logger.log_format}")
        
        # Check if directory exists
        log_path = Path(logger.log_dir)
        if log_path.exists():
            print(f"✓ Log directory exists: {log_path.absolute()}")
        else:
            print(f"! Log directory will be created: {log_path.absolute()}")
    else:
        print("✗ No AIWAF logger attached to app")
        return None, "Logger not attached"
    
    return app, None

def test_with_real_server():
    """Test with real server like user would do."""
    
    app, error = create_debug_app()
    if error:
        print(f"Failed to create app: {error}")
        return False
    
    print("\\n=== Testing with Test Client ===")
    
    # Test with test client
    with app.test_client() as client:
        responses = []
        
        print("Making test requests...")
        for url in ['/', '/api/test', '/admin', '/nonexistent']:
            try:
                response = client.get(url)
                responses.append((url, response.status_code))
                print(f"  GET {url} -> {response.status_code}")
            except Exception as e:
                print(f"  GET {url} -> ERROR: {e}")
                responses.append((url, f"ERROR: {e}"))
    
    # Check logs
    print("\\n=== Checking Log Files ===")
    log_dir = Path('user_test_logs')
    
    if log_dir.exists():
        print(f"✓ Log directory exists: {log_dir.absolute()}")
        for log_file in log_dir.glob('*.log'):
            size = log_file.stat().st_size
            print(f"  {log_file.name}: {size} bytes")
            if size > 0:
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    lines = content.splitlines()
                    print(f"    Lines: {len(lines)}")
                    if lines:
                        print(f"    Sample: {lines[0][:100]}...")
    else:
        print(f"✗ Log directory does not exist: {log_dir.absolute()}")
        return False
    
    return True

def test_with_wsgi():
    """Test with WSGI server simulation."""
    
    app, error = create_debug_app()
    if error:
        return False
    
    print("\\n=== Testing WSGI Simulation ===")
    
    # Simulate WSGI environment
    from werkzeug.test import Client
    from werkzeug.wrappers import Response
    
    client = Client(app, Response)
    
    # Make requests
    try:
        response = client.get('/')
        print(f"WSGI GET / -> {response.status_code}")
        
        response = client.get('/api/test')
        print(f"WSGI GET /api/test -> {response.status_code}")
        
    except Exception as e:
        print(f"WSGI test failed: {e}")
        import traceback
        traceback.print_exc()
    
    return True

if __name__ == '__main__':
    print("🔍 AIWAF Logging Debug Tool")
    print("=" * 50)
    
    try:
        success1 = test_with_real_server()
        success2 = test_with_wsgi()
        
        if success1 and success2:
            print("\\n✅ All tests passed! If you're still having issues:")
            print("1. Check that your app calls register_aiwaf_middlewares(app)")
            print("2. Verify your AIWAF_LOG_DIR configuration")
            print("3. Make sure the directory is writable")
            print("4. Check for permission errors in your application")
            print("\\nIf logs still don't appear, the issue might be:")
            print("- File permissions")
            print("- Antivirus software blocking file creation")
            print("- Running from a read-only directory")
            print("- Middleware not being registered properly")
        else:
            print("\\n❌ Tests failed - check the output above")
    
    except Exception as e:
        print(f"\\n💥 Debug test crashed: {e}")
        import traceback
        traceback.print_exc()