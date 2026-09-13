import os
import sys

# Make the src/ layout importable without an editable install.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
