"""
Test script to verify Morpheus installation
"""

import sys
from pathlib import Path

def test_imports():
    """Test if all required modules can be imported"""
    print("Testing imports...")
    
    try:
        import pefile
        print("✓ pefile")
    except ImportError:
        print("✗ pefile - Run: pip install pefile")
        return False
    
    try:
        import lief
        print("✓ lief")
    except ImportError:
        print("✗ lief - Run: pip install lief")
        return False
    
    try:
        import torch
        print("✓ torch")
    except ImportError:
        print("✗ torch - Run: pip install torch")
        return False
    
    try:
        import sklearn
        print("✓ scikit-learn")
    except ImportError:
        print("✗ scikit-learn - Run: pip install scikit-learn")
        return False
    
    try:
        import click
        print("✓ click")
    except ImportError:
        print("✗ click - Run: pip install click")
        return False
    
    try:
        from rich import print as rprint
        print("✓ rich")
    except ImportError:
        print("✗ rich - Run: pip install rich")
        return False
    
    return True

def test_structure():
    """Test if project structure is correct"""
    print("\nTesting project structure...")
    
    required_dirs = [
        'core',
        'utils',
        'models',
        'techniques',
        'evasion',
        'cli',
        'examples',
        'config',
    ]
    
    for dir_name in required_dirs:
        if Path(dir_name).exists():
            print(f"✓ {dir_name}/")
        else:
            print(f"✗ {dir_name}/ - Missing!")
            return False
    
    required_files = [
        'morpheus.py',
        'README.md',
        'requirements.txt',
        'LICENSE',
    ]
    
    for file_name in required_files:
        if Path(file_name).exists():
            print(f"✓ {file_name}")
        else:
            print(f"✗ {file_name} - Missing!")
            return False
    
    return True

def test_modules():
    """Test if Morpheus modules can be imported"""
    print("\nTesting Morpheus modules...")
    
    try:
        from core.mutator import MalwareMutator
        print("✓ core.mutator")
    except ImportError as e:
        print(f"✗ core.mutator - {e}")
        return False
    
    try:
        from core.rl_agent import PPOAgent
        print("✓ core.rl_agent")
    except ImportError as e:
        print(f"✗ core.rl_agent - {e}")
        return False
    
    try:
        from core.gan_generator import GANGenerator
        print("✓ core.gan_generator")
    except ImportError as e:
        print(f"✗ core.gan_generator - {e}")
        return False
    
    try:
        from models.classifier import MalwareClassifier
        print("✓ models.classifier")
    except ImportError as e:
        print(f"✗ models.classifier - {e}")
        return False
    
    try:
        from utils.pe_parser import PEParser
        print("✓ utils.pe_parser")
    except ImportError as e:
        print(f"✗ utils.pe_parser - {e}")
        return False
    
    return True

def main():
    print("=" * 50)
    print("Morpheus Installation Test")
    print("=" * 50)
    
    # Test imports
    if not test_imports():
        print("\n❌ Import test failed!")
        print("Please install missing dependencies: pip install -r requirements.txt")
        return False
    
    # Test structure
    if not test_structure():
        print("\n❌ Structure test failed!")
        print("Some files or directories are missing.")
        return False
    
    # Test modules
    if not test_modules():
        print("\n❌ Module test failed!")
        print("Some Morpheus modules cannot be imported.")
        return False
    
    print("\n" + "=" * 50)
    print("✅ All tests passed!")
    print("=" * 50)
    print("\nMorpheus is ready to use!")
    print("\nQuick start:")
    print("  python morpheus.py info")
    print("  python morpheus.py mutate --input sample.exe --output mutated.exe")
    
    return True

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
