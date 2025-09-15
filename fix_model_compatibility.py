#!/usr/bin/env python3
"""
Model compatibility checker and regeneration tool for AIWAF Flask
"""

import os
import sys
import warnings
from pathlib import Path

def check_and_fix_model():
    """Check model compatibility and regenerate if needed"""
    
    print("🔧 AIWAF Model Compatibility Checker")
    print("=" * 50)
    
    # Get model path
    package_dir = Path(__file__).parent / 'aiwaf_flask'
    model_path = package_dir / 'resources' / 'model.pkl'
    
    print(f"📁 Model path: {model_path}")
    print(f"📄 Model exists: {model_path.exists()}")
    
    if not model_path.exists():
        print("❌ No model found - please run training first")
        return False
    
    # Try to load the model
    try:
        import pickle
        import warnings
        
        print("🧪 Testing model loading...")
        
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            
            with open(model_path, 'rb') as f:
                model_data = pickle.load(f)
            
            # Check for sklearn version warnings
            sklearn_warnings = [warning for warning in w 
                              if 'sklearn' in str(warning.message).lower() 
                              and 'version' in str(warning.message).lower()]
            
            if sklearn_warnings:
                print("⚠️  Model version compatibility issues detected:")
                for warning in sklearn_warnings:
                    print(f"   {warning.message}")
                print("\n💡 Recommendation: Retrain the model with current sklearn version")
                
                # Ask if user wants to retrain
                response = input("\n🔄 Would you like to retrain the model now? (y/N): ").strip().lower()
                if response in ['y', 'yes']:
                    return retrain_model()
                else:
                    print("📝 To retrain manually, run: aiwaf train --log-dir /path/to/logs")
                    return True
            else:
                print("✅ Model loads successfully without version issues!")
                
                # Show model info
                if isinstance(model_data, dict):
                    print("📊 Model information:")
                    for key, value in model_data.items():
                        if key != 'model':
                            print(f"   {key}: {value}")
                else:
                    print("📦 Model format: Direct model object (legacy)")
                
                return True
                
    except Exception as e:
        print(f"❌ Error loading model: {e}")
        print("\n💡 The model may be corrupted or incompatible")
        
        # Ask if user wants to retrain
        response = input("\n🔄 Would you like to retrain the model? (y/N): ").strip().lower()
        if response in ['y', 'yes']:
            return retrain_model()
        else:
            print("📝 To retrain manually, run: aiwaf train --log-dir /path/to/logs")
            return False

def retrain_model():
    """Retrain the model with current dependencies"""
    
    print("\n🤖 Retraining model with current dependencies...")
    
    # Check if we have log files to train with
    log_dirs = ['test_logs', 'logs', 'aiwaf_logs']
    available_logs = []
    
    for log_dir in log_dirs:
        if os.path.exists(log_dir):
            log_files = []
            for ext in ['*.log', '*.csv', '*.json', '*.jsonl']:
                import glob
                log_files.extend(glob.glob(os.path.join(log_dir, ext)))
            if log_files:
                available_logs.append((log_dir, log_files))
    
    if not available_logs:
        print("❌ No log files found for training")
        print("📋 Please ensure you have log files in one of these directories:")
        for log_dir in log_dirs:
            print(f"   {log_dir}/")
        return False
    
    # Use the first available log directory
    log_dir, log_files = available_logs[0]
    print(f"📁 Using logs from: {log_dir}")
    print(f"📄 Found {len(log_files)} log files")
    
    # Run training
    try:
        import subprocess
        cmd = ['aiwaf', 'train', '--log-dir', log_dir, '--verbose']
        
        print(f"🚀 Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ Model retrained successfully!")
            print(result.stdout)
            return True
        else:
            print(f"❌ Training failed: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"❌ Error running training: {e}")
        print("📝 Try running manually: aiwaf train --log-dir logs")
        return False

if __name__ == '__main__':
    success = check_and_fix_model()
    if success:
        print("\n🎉 Model compatibility check completed!")
        print("✅ Your AIWAF installation should work correctly now.")
    else:
        print("\n❌ Model compatibility issues remain")
        print("📝 Please retrain the model or check your installation")
        sys.exit(1)