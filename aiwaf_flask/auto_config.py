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
        Uses deterministic approach to always return the same directory regardless of working directory.
        Returns the absolute path to the data directory.
        """
        # Method 1: Environment variable (highest priority - always consistent)
        if self._check_environment_variable():
            return self.data_dir
            
        # Method 2: Find the installed package location and use consistent relative path
        if self._use_package_based_data_directory():
            return self.data_dir
            
        # Method 3: Search for the BEST existing data directory (most data, not first found)
        if self._find_best_existing_data_directory():
            return self.data_dir
            
        # Method 4: Create in user-specific location (consistent across sessions)
        return self._create_user_data_directory()
    
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
    
    def _use_package_based_data_directory(self) -> bool:
        """Use data directory relative to the installed package location."""
        try:
            import aiwaf_flask
            package_path = Path(aiwaf_flask.__file__).parent.parent  # Go up to site-packages level
            
            # Look for data directory near the package installation
            potential_locations = [
                package_path / 'aiwaf_data',  # Next to site-packages
                package_path.parent / 'aiwaf_data',  # One level up
                Path.home() / '.aiwaf' / 'data',  # User-specific location
            ]
            
            for location in potential_locations:
                if location.exists() and self._validate_aiwaf_data_dir(location):
                    self.data_dir = str(location.absolute())
                    self.detected_config['method'] = 'package_based_location'
                    self.detected_config['package_path'] = str(package_path)
                    return True
                    
        except Exception:
            pass
            
        return False
    
    def _find_best_existing_data_directory(self) -> bool:
        """Find the existing data directory with the most data (most reliable)."""
        candidates = []
        
        # Search in common locations but prioritize by data content
        search_paths = [
            Path.home() / '.aiwaf' / 'data',  # User-specific (highest priority)
            Path.home() / 'aiwaf_data',       # User home
            Path('/var/lib/aiwaf') if os.name != 'nt' else Path('C:/ProgramData/aiwaf'),  # System-wide
        ]
        
        # Add current and parent directories but with lower priority
        current_dir = Path.cwd()
        for i in range(3):  # Check current and 2 parent levels
            search_paths.append(current_dir / 'aiwaf_data')
            if current_dir.parent != current_dir:  # Avoid infinite loop at root
                current_dir = current_dir.parent
            else:
                break
        
        # Evaluate each candidate
        for search_path in search_paths:
            if not search_path.exists():
                continue
                
            try:
                for item in search_path.rglob('aiwaf_data'):
                    if item.is_dir() and self._validate_aiwaf_data_dir(item):
                        # Count the amount of data in this directory
                        data_score = self._calculate_data_directory_score(item)
                        candidates.append((data_score, str(item.absolute()), item))
            except (PermissionError, OSError):
                continue
        
        # Choose the candidate with the highest data score
        if candidates:
            candidates.sort(reverse=True)  # Sort by score (descending)
            best_score, best_path, best_item = candidates[0]
            
            self.data_dir = best_path
            self.detected_config['method'] = 'best_existing_directory'
            self.detected_config['found_at'] = best_path
            self.detected_config['data_score'] = best_score
            self.detected_config['total_candidates'] = len(candidates)
            return True
                
        return False
    
    def _calculate_data_directory_score(self, path: Path) -> int:
        """Calculate a score for a data directory based on its contents."""
        score = 0
        csv_files = ['whitelist.csv', 'blacklist.csv', 'keywords.csv']
        
        for csv_file in csv_files:
            csv_path = path / csv_file
            if csv_path.exists():
                try:
                    # Score based on file size and line count
                    file_size = csv_path.stat().st_size
                    score += min(file_size, 1000)  # Cap size contribution
                    
                    # Count lines (more data = higher score)
                    with open(csv_path, 'r') as f:
                        line_count = sum(1 for _ in f)
                        score += line_count * 10  # Lines are worth more than just file size
                        
                except (PermissionError, OSError):
                    pass
        
        # Bonus for having all three files
        existing_files = sum(1 for csv_file in csv_files if (path / csv_file).exists())
        score += existing_files * 100
        
        return score
    
    def _create_user_data_directory(self) -> str:
        """Create data directory in user-specific location for consistency."""
        # User-specific data directory (always consistent regardless of working directory)
        user_data_locations = [
            Path.home() / '.aiwaf' / 'data',     # Unix-style hidden directory
            Path.home() / 'aiwaf_data',          # Simple user directory
        ]
        
        # On Windows, also try AppData
        if os.name == 'nt':
            appdata = os.environ.get('APPDATA')
            if appdata:
                user_data_locations.insert(0, Path(appdata) / 'aiwaf' / 'data')
        
        for location in user_data_locations:
            if self._can_create_directory(location):
                location.mkdir(parents=True, exist_ok=True)
                self.data_dir = str(location.absolute())
                self.detected_config['method'] = 'user_data_directory'
                self.detected_config['location'] = str(location)
                return self.data_dir
        
        # Absolute last resort - use temp directory with user-specific name
        import tempfile
        try:
            temp_dir = Path(tempfile.gettempdir()) / f'aiwaf_data_{os.getlogin()}'
        except:
            temp_dir = Path(tempfile.gettempdir()) / 'aiwaf_data_default'
        temp_dir.mkdir(exist_ok=True)
        self.data_dir = str(temp_dir.absolute())
        self.detected_config['method'] = 'temp_user_directory'
        self.detected_config['location'] = str(temp_dir)
        return self.data_dir


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
        'package_based_location': 'Located data directory near package installation',
        'best_existing_directory': 'Selected data directory with most existing data',
        'user_data_directory': 'Created in user-specific location for consistency',
        'temp_user_directory': 'Using temporary user-specific directory',
        # Legacy methods (still supported)
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
    elif method == 'best_existing_directory':
        print(f"📍 Selected from {details.get('total_candidates', 0)} candidates")
        print(f"📊 Data score: {details.get('data_score', 0)}")
    elif method == 'package_based_location' and 'package_path' in details:
        print(f"📦 Package location: {details['package_path']}")
    elif method in ['user_data_directory', 'temp_user_directory'] and 'location' in details:
        print(f"📂 Created at: {details['location']}")
        print(f"💡 This location is consistent regardless of working directory")