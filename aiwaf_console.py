#!/usr/bin/env python3
"""
AIWAF Flask Console Manager

Simple entry point for managing AIWAF from command line.
This standalone version doesn't require Flask to be installed.
"""

import sys
import os
from pathlib import Path

# Add the current directory to path to import the CLI directly
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

# Import CLI directly to avoid Flask dependencies
from aiwaf_flask.cli import main

if __name__ == '__main__':
    main()