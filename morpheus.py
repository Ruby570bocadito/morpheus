#!/usr/bin/env python3
"""
Morpheus - Main entry point
"""

import sys
from pathlib import Path

# Add cli directory to path
sys.path.insert(0, str(Path(__file__).parent / 'cli'))

from morpheus_cli import cli

if __name__ == '__main__':
    cli()
