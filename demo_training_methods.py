#!/usr/bin/env python3
"""
Demonstrate all the ways to invoke AIWAF Flask training
"""

import os
import subprocess
import sys

def demo_training_methods():
    """Demonstrate all training methods"""
    
    print("🎯 AIWAF Flask Training Methods Demo")
    print("=" * 50)
    
    methods = [
        {
            "name": "1. Global CLI Command (Recommended)",
            "commands": [
                "aiwaf train --help",
                "aiwaf train --disable-ai --log-dir test_logs"
            ],
            "description": "Easiest method - works from anywhere after installation"
        },
        {
            "name": "2. Standalone Training Script",
            "commands": [
                "python train_aiwaf.py --help",
                "python train_aiwaf.py --disable-ai --log-dir test_logs"
            ],
            "description": "Dedicated training script with full options"
        },
        {
            "name": "3. Module CLI Invocation",
            "commands": [
                "python -m aiwaf_flask.cli train --help",
                "python -m aiwaf_flask.cli train --disable-ai --log-dir test_logs"
            ],
            "description": "Direct module execution for development"
        },
        {
            "name": "4. Programmatic API",
            "commands": [
                # This will be shown as code, not executed
            ],
            "description": "Python code integration",
            "code": '''
from flask import Flask
from aiwaf_flask.trainer import train_from_logs

app = Flask(__name__)
app.config['AIWAF_LOG_DIR'] = 'logs'

# Train with AI (requires numpy, scikit-learn)
train_from_logs(app)

# Train with keyword learning only
train_from_logs(app, disable_ai=True)
'''
        }
    ]
    
    for method in methods:
        print(f"\n📋 {method['name']}")
        print("-" * len(method['name']))
        print(f"Description: {method['description']}")
        
        if 'code' in method:
            print(f"Usage:")
            print(method['code'])
        else:
            print(f"Commands:")
            for cmd in method['commands']:
                print(f"  $ {cmd}")
        
        print()
    
    print("✅ All training methods available!")
    print("\n🎯 Quick Start:")
    print("  $ aiwaf train --disable-ai --log-dir /path/to/logs")
    print("\n🤖 With AI (requires: pip install aiwaf-flask[ai]):")
    print("  $ aiwaf train --log-dir /path/to/logs")

if __name__ == '__main__':
    demo_training_methods()