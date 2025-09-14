#!/usr/bin/env python3
"""
Test setup.py configuration for AIWAF Flask dependencies.
"""

def test_setup_py():
    """Test that setup.py has correct dependency configuration."""
    print("🔧 Testing setup.py Configuration")
    print("=" * 35)
    
    # Read setup.py to verify configuration
    try:
        with open('setup.py', 'r') as f:
            content = f.read()
        
        print("✅ setup.py file found")
        
        # Check for AI dependencies in extras_require
        if '"ai":' in content:
            print("✅ AI extra dependencies section found")
        else:
            print("❌ AI extra dependencies missing")
            return False
        
        if 'numpy>=1.20.0' in content:
            print("✅ NumPy dependency configured")
        else:
            print("❌ NumPy dependency missing")
            return False
        
        if 'scikit-learn>=1.0.0' in content:
            print("✅ Scikit-learn dependency configured")
        else:
            print("❌ Scikit-learn dependency missing")
            return False
        
        if '"all":' in content:
            print("✅ 'all' extra dependencies section found")
        else:
            print("❌ 'all' extra dependencies missing")
            return False
        
        print("✅ setup.py configuration is correct")
        return True
        
    except FileNotFoundError:
        print("❌ setup.py not found")
        return False
    except Exception as e:
        print(f"❌ Error reading setup.py: {e}")
        return False

def test_pyproject_toml():
    """Test that pyproject.toml has correct dependency configuration."""
    print("\n🔧 Testing pyproject.toml Configuration")
    print("=" * 40)
    
    try:
        with open('pyproject.toml', 'r') as f:
            content = f.read()
        
        # Check for AI dependencies in optional-dependencies
        if 'ai =' in content:
            print("✅ AI optional dependencies section found")
        else:
            print("❌ AI optional dependencies missing")
            return False
        
        if 'numpy>=1.20.0' in content:
            print("✅ NumPy dependency configured")
        else:
            print("❌ NumPy dependency missing")
            return False
        
        if 'scikit-learn>=1.0.0' in content:
            print("✅ Scikit-learn dependency configured")
        else:
            print("❌ Scikit-learn dependency missing")
            return False
        
        if 'all =' in content:
            print("✅ 'all' optional dependencies section found")
        else:
            print("❌ 'all' optional dependencies missing")
            return False
        
        print("✅ pyproject.toml configuration is correct")
        return True
        
    except FileNotFoundError:
        print("❌ pyproject.toml not found")
        return False
    except Exception as e:
        print(f"❌ Error reading pyproject.toml: {e}")
        return False

def show_installation_commands():
    """Show the installation commands that users can use."""
    print("\n📦 Available Installation Commands")
    print("=" * 35)
    
    commands = [
        ("Basic installation", "pip install aiwaf-flask"),
        ("With AI features", "pip install aiwaf-flask[ai]"),
        ("Full installation", "pip install aiwaf-flask[all]"),
        ("Development mode", "pip install -e ."),
        ("AI only (existing install)", "pip install numpy>=1.20.0 scikit-learn>=1.0.0"),
    ]
    
    for description, command in commands:
        print(f"  {description:25} → {command}")

def main():
    """Run all configuration tests."""
    print("🚀 AIWAF Flask Setup Configuration Test")
    print("=" * 45)
    
    setup_ok = test_setup_py()
    toml_ok = test_pyproject_toml()
    
    print("\n📊 Configuration Test Summary:")
    print(f"setup.py: {'✅ PASS' if setup_ok else '❌ FAIL'}")
    print(f"pyproject.toml: {'✅ PASS' if toml_ok else '❌ FAIL'}")
    
    if setup_ok and toml_ok:
        print("\n🎉 All configuration tests passed!")
        print("✅ AI dependencies are properly configured")
        print("✅ Multiple installation options available")
    else:
        print("\n❌ Configuration issues found")
    
    show_installation_commands()
    
    print("\n💡 Dependency Groups:")
    print("  ai:  NumPy + Scikit-learn (ML features)")
    print("  dev: Testing and development tools")  
    print("  all: AI + development dependencies")

if __name__ == '__main__':
    main()