#!/usr/bin/env python3
"""Test AIWAF Flask middleware model loading"""

import os
from flask import Flask
from aiwaf_flask.anomaly_middleware import AIAnomalyMiddleware

def test_model_loading():
    """Test that the middleware can load the trained model"""
    
    print("🧪 Testing AIWAF Flask Model Loading")
    print("=" * 50)
    
    # Create test Flask app
    app = Flask(__name__)
    
    # Configure AIWAF
    app.config['AIWAF_DATA_DIR'] = 'aiwaf_data'
    app.config['AIWAF_LOG_DIR'] = 'aiwaf_logs'
    
    # Initialize middleware
    print("🔧 Initializing middleware...")
    middleware = AIAnomalyMiddleware()
    middleware.init_app(app)
    
    # Check if model loaded
    with app.app_context():
        if hasattr(middleware, 'model') and middleware.model is not None:
            print("✅ Model loaded successfully!")
            print(f"   Model type: {type(middleware.model).__name__}")
            
            # Test prediction capability
            try:
                import numpy as np
                # Create a simple test feature vector
                test_features = np.array([[1, 0, 0, 1, 0, 1]])  # 6 features as expected
                prediction = middleware.model.predict(test_features)
                anomaly_score = middleware.model.decision_function(test_features)
                
                print(f"   Test prediction: {prediction[0]} (1=normal, -1=anomaly)")
                print(f"   Anomaly score: {anomaly_score[0]:.3f}")
                print("✅ Model prediction working!")
                
            except Exception as e:
                print(f"⚠️  Model prediction test failed: {e}")
                
        else:
            print("❌ Model not loaded")
            
        # Test status endpoint
        try:
            status = middleware.get_status()
            print("\n📊 Middleware Status:")
            print(f"   Model loaded: {status['model_loaded']}")
            print(f"   Joblib available: {status.get('joblib_available', 'unknown')}")
            print(f"   Pickle available: {status.get('pickle_available', 'unknown')}")
            print(f"   NumPy available: {status['numpy_available']}")
            
        except Exception as e:
            print(f"⚠️  Status check failed: {e}")
    
    print("\n🎉 Model loading test completed!")

if __name__ == '__main__':
    test_model_loading()