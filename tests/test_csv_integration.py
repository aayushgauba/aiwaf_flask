import pytest
import tempfile
import shutil
from pathlib import Path

def test_csv_middleware_integration(app):
    """Test AIWAF middleware with CSV storage."""
    from aiwaf_flask.middleware import register_aiwaf_middlewares
    from aiwaf_flask.storage import add_ip_blacklist, add_keyword
    
    # Configure for CSV storage
    temp_dir = tempfile.mkdtemp()
    app.config['AIWAF_USE_CSV'] = True
    app.config['AIWAF_DATA_DIR'] = temp_dir
    app.config['AIWAF_RATE_WINDOW'] = 60
    app.config['AIWAF_RATE_MAX'] = 10
    
    # Register middleware
    register_aiwaf_middlewares(app)
    
    @app.route('/test')
    def test_route():
        return 'OK'
    
    client = app.test_client()
    
    with app.app_context():
        # Add IP to blacklist via CSV
        add_ip_blacklist('127.0.0.1', 'Test block')
        
        # Test that blacklisted IP is blocked
        response = client.get('/test', headers={'User-Agent': 'Test Browser 1.0'})
        assert response.status_code == 403
        
        # Add malicious keyword
        add_keyword('malicious')
        
        # Test keyword blocking - should be blocked by middleware
        response = client.get('/test/malicious', headers={'User-Agent': 'Test Browser 1.0'})
        assert response.status_code == 403  # Blocked by keyword filter
    
    # Cleanup
    shutil.rmtree(temp_dir, ignore_errors=True)

def test_csv_files_structure():
    """Test CSV file structure and content."""
    from aiwaf_flask.storage import _ensure_csv_files, _get_data_dir
    import csv
    
    # Create temporary directory
    temp_dir = tempfile.mkdtemp()
    
    # Mock the data directory
    import aiwaf_flask.storage as storage_module
    original_get_data_dir = storage_module._get_data_dir
    storage_module._get_data_dir = lambda: temp_dir
    
    try:
        # Ensure CSV files are created
        _ensure_csv_files()
        
        # Check whitelist structure
        whitelist_file = Path(temp_dir) / 'whitelist.csv'
        assert whitelist_file.exists()
        
        with open(whitelist_file, 'r') as f:
            reader = csv.reader(f)
            headers = next(reader)
            assert headers == ['ip', 'added_date']
        
        # Check blacklist structure
        blacklist_file = Path(temp_dir) / 'blacklist.csv'
        assert blacklist_file.exists()
        
        with open(blacklist_file, 'r') as f:
            reader = csv.reader(f)
            headers = next(reader)
            assert headers == ['ip', 'reason', 'added_date']
        
        # Check keywords structure
        keywords_file = Path(temp_dir) / 'keywords.csv'
        assert keywords_file.exists()
        
        with open(keywords_file, 'r') as f:
            reader = csv.reader(f)
            headers = next(reader)
            assert headers == ['keyword', 'added_date']
    
    finally:
        # Restore original function
        storage_module._get_data_dir = original_get_data_dir
        # Cleanup
        shutil.rmtree(temp_dir, ignore_errors=True)

def test_csv_storage_mode_selection():
    """Test storage mode selection logic."""
    from flask import Flask
    from aiwaf_flask.storage import _get_storage_mode
    
    # Test CSV mode
    app = Flask(__name__)
    app.config['AIWAF_USE_CSV'] = True
    
    with app.app_context():
        assert _get_storage_mode() == 'csv'
    
    # Test memory mode (CSV disabled)
    app.config['AIWAF_USE_CSV'] = False
    
    with app.app_context():
        assert _get_storage_mode() == 'memory'