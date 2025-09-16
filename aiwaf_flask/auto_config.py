"""
AIWAF Auto-Configuration Module

Automatically detects Flask app configuration and data directories
without requiring user intervention.
"""

import os
import sys
import importlib
import inspect
from pathlib import Path
from typing import Optional, Tuple, Dict, Any


class AIWAFAutoConfig:
    """Automatically detect and configure AIWAF data directory."""
    
    def __init__(self):
        self.detected_config = {}
        self.data_dir = None
        self.flask_app = None
        
    def auto_detect_data_directory(self) -> str:
        """
        Automatically detect the correct data directory through multiple methods.
        Returns the absolute path to the data directory.
        """
        # Method 1: Environment variable (highest priority)
        if self._check_environment_variable():
            return self.data_dir
            
        # Method 2: Search for existing aiwaf_data directories (most reliable)
        if self._search_existing_data_directories():
            return self.data_dir
            
        # Method 3: Intelligent project structure detection
        if self._detect_project_structure():
            return self.data_dir
            
        # Method 4: Find and read Flask app configuration (complex, less reliable)
        if self._find_flask_app_config():
            return self.data_dir
            
        # Fallback: Create in most logical location
        return self._create_fallback_directory()
    
    def _check_environment_variable(self) -> bool:
        """Check if AIWAF_DATA_DIR is set in environment."""
        env_dir = os.environ.get('AIWAF_DATA_DIR')
        if env_dir and Path(env_dir).exists():
            self.data_dir = str(Path(env_dir).absolute())
            self.detected_config['method'] = 'environment_variable'
            return True
        return False
    
    def _find_flask_app_config(self) -> bool:
        """Find Flask app and read its AIWAF configuration."""
        try:
            # Look for common Flask app patterns
            app_candidates = [
                'app',
                'application', 
                'main',
                'server',
                'wsgi'
            ]
            
            # Search in current directory and subdirectories
            current_dir = Path.cwd()
            python_files = list(current_dir.rglob("*.py"))
            
            for py_file in python_files:
                if self._analyze_python_file_for_flask_app(py_file):
                    return True
                    
        except Exception as e:
            print(f"🔍 Flask app detection failed: {e}")
            
        return False
    
    def _analyze_python_file_for_flask_app(self, py_file: Path) -> bool:
        """Analyze a Python file to find Flask app configuration."""
        try:
            with open(py_file, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Look for Flask app creation and AIWAF configuration
            if 'Flask(' in content and 'AIWAF' in content:
                # Try to extract AIWAF_DATA_DIR configuration
                lines = content.split('\n')
                for line in lines:
                    if 'AIWAF_DATA_DIR' in line and '=' in line and not line.strip().startswith('#'):
                        # Extract the value (handle both quotes and variables)
                        try:
                            # Find the part after =
                            parts = line.split('=', 1)
                            if len(parts) == 2:
                                value_part = parts[1].strip()
                                
                                # Remove quotes and clean up
                                value = value_part.strip("'\"").strip()
                                
                                # Skip if it's a variable reference or environment lookup
                                if any(keyword in value for keyword in ['os.', 'environ', 'getenv', '{']):
                                    continue
                                
                                if value and value != 'aiwaf_data':  # Skip default values
                                    # Resolve relative to the file's directory
                                    if not Path(value).is_absolute():
                                        data_dir = py_file.parent / value
                                    else:
                                        data_dir = Path(value)
                                        
                                    if data_dir.exists() or self._can_create_directory(data_dir):
                                        self.data_dir = str(data_dir.absolute())
                                        self.detected_config['method'] = 'flask_app_config'
                                        self.detected_config['source_file'] = str(py_file)
                                        return True
                        except Exception:
                            continue
                        
        except Exception:
            pass
            
        return False
    
    def _search_existing_data_directories(self) -> bool:
        """Search for existing aiwaf_data directories."""
        search_paths = [
            Path.cwd(),  # Current directory
            Path.cwd().parent,  # Parent directory
            Path.home() / 'aiwaf_data',  # Home directory
        ]
        
        # Also search in common web app locations
        common_paths = [
            '/var/www',
            '/opt',
            '/home/ubuntu',
            '/app',  # Docker common path
        ]
        
        for path_str in common_paths:
            path = Path(path_str)
            if path.exists():
                search_paths.append(path)
        
        for search_path in search_paths:
            if not search_path.exists():
                continue
                
            # Look for aiwaf_data directories
            try:
                for item in search_path.rglob('aiwaf_data'):
                    if item.is_dir() and self._validate_aiwaf_data_dir(item):
                        self.data_dir = str(item.absolute())
                        self.detected_config['method'] = 'existing_directory_search'
                        self.detected_config['found_at'] = str(item)
                        return True
            except (PermissionError, OSError):
                continue
                
        return False
    
    def _validate_aiwaf_data_dir(self, path: Path) -> bool:
        """Validate that a directory looks like an AIWAF data directory."""
        # Check for characteristic files
        csv_files = ['whitelist.csv', 'blacklist.csv', 'keywords.csv']
        
        # If any CSV files exist, consider it valid
        if any((path / csv_file).exists() for csv_file in csv_files):
            return True
            
        # If directory is empty but writable, also consider valid
        try:
            if not any(path.iterdir()) and os.access(path, os.W_OK):
                return True
        except (PermissionError, OSError):
            pass
            
        return False
    
    def _detect_project_structure(self) -> bool:
        """Detect project structure and infer best data directory location."""
        current_dir = Path.cwd()
        
        # Look for project indicators
        project_indicators = [
            'setup.py',
            'pyproject.toml', 
            'requirements.txt',
            'Pipfile',
            'poetry.lock',
            'manage.py',  # Django
            'app.py',     # Flask
            'main.py',    # Generic
        ]
        
        # Find project root
        project_root = None
        for parent in [current_dir] + list(current_dir.parents)[:5]:
            if any((parent / indicator).exists() for indicator in project_indicators):
                project_root = parent
                break
        
        if project_root:
            # Create data directory in project root
            data_dir = project_root / 'aiwaf_data'
            if self._can_create_directory(data_dir):
                data_dir.mkdir(exist_ok=True)
                self.data_dir = str(data_dir.absolute())
                self.detected_config['method'] = 'project_structure_detection'
                self.detected_config['project_root'] = str(project_root)
                return True
                
        return False
    
    def _create_fallback_directory(self) -> str:
        """Create fallback directory in the most appropriate location."""
        fallback_locations = [
            Path.cwd() / 'aiwaf_data',  # Current directory
            Path.home() / '.aiwaf' / 'data',  # User home
            Path('/tmp/aiwaf_data') if os.name != 'nt' else Path.cwd() / 'aiwaf_data',  # Temp (Unix only)
        ]
        
        for location in fallback_locations:
            if self._can_create_directory(location):
                location.mkdir(parents=True, exist_ok=True)
                self.data_dir = str(location.absolute())
                self.detected_config['method'] = 'fallback_creation'
                self.detected_config['location'] = str(location)
                return self.data_dir
        
        # Last resort
        self.data_dir = 'aiwaf_data'
        self.detected_config['method'] = 'last_resort'
        return self.data_dir
    
    def _can_create_directory(self, path: Path) -> bool:
        """Check if we can create a directory at the given path."""
        try:
            if path.exists():
                return os.access(path, os.W_OK)
            else:
                # Check parent directory permissions
                parent = path.parent
                return parent.exists() and os.access(parent, os.W_OK)
        except (PermissionError, OSError):
            return False
    
    def get_config_info(self) -> Dict[str, Any]:
        """Get information about how the configuration was detected."""
        return {
            'data_directory': self.data_dir,
            'detection_method': self.detected_config.get('method', 'unknown'),
            'details': self.detected_config
        }


# Global instance for automatic configuration
_auto_config = None

def get_auto_configured_data_dir() -> Tuple[str, Dict[str, Any]]:
    """
    Get automatically configured data directory.
    Returns (data_dir_path, config_info)
    """
    global _auto_config
    if _auto_config is None:
        _auto_config = AIWAFAutoConfig()
    
    data_dir = _auto_config.auto_detect_data_directory()
    config_info = _auto_config.get_config_info()
    
    return data_dir, config_info


def print_auto_config_info(config_info: Dict[str, Any]) -> None:
    """Print user-friendly information about auto-configuration."""
    method = config_info.get('detection_method', 'unknown')
    data_dir = config_info.get('data_directory', 'unknown')
    
    method_descriptions = {
        'environment_variable': 'Found AIWAF_DATA_DIR environment variable',
        'flask_app_config': 'Detected from Flask app configuration',
        'existing_directory_search': 'Found existing aiwaf_data directory',
        'project_structure_detection': 'Detected from project structure',
        'fallback_creation': 'Created in fallback location',
        'last_resort': 'Using default relative path'
    }
    
    description = method_descriptions.get(method, 'Unknown detection method')
    print(f"📁 Auto-configured data directory: {data_dir}")
    print(f"🔍 Detection method: {description}")
    
    # Additional details based on method
    details = config_info.get('details', {})
    if method == 'flask_app_config' and 'source_file' in details:
        print(f"📄 Source: {details['source_file']}")
    elif method == 'project_structure_detection' and 'project_root' in details:
        print(f"📂 Project root: {details['project_root']}")
    elif method == 'existing_directory_search' and 'found_at' in details:
        print(f"📍 Found at: {details['found_at']}")