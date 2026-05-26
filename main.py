"""
Entry point for the TCP port scanner application.
"""
import sys
from scanner.cli.main import app

if __name__ == "__main__":
    # Handle potential encoding issues on Windows
    if sys.platform.startswith('win'):
        import os
        os.system('')

    app()