# Python package initialization

from .nuclide_decay import disassemble, disassemble_file

# Import the module to access OutputFormat and Strategy dictionaries
import nuclide_decay.nuclide_decay as _mod

# Set version
__version__ = "0.1.0"

# Export the main functions
__all__ = [
    "disassemble",
    "disassemble_file",
    "OutputFormat",
    "Strategy",
]

# Create OutputFormat and Strategy as proper module-level variables
class OutputFormat:
    """Output format options for disassembly"""
    TEXT = _mod.OutputFormat["TEXT"]
    JSON = _mod.OutputFormat["JSON"]
    JSONL = _mod.OutputFormat["JSONL"]
    CSV = _mod.OutputFormat["CSV"]
    NGRAM = _mod.OutputFormat["NGRAM"]

class Strategy:
    """Disassembly strategy options"""
    LINEAR = _mod.Strategy["LINEAR"]
    RECURSIVE = _mod.Strategy["RECURSIVE"]
    SUPERSET = _mod.Strategy["SUPERSET"]
    PROBABILISTIC = _mod.Strategy["PROBABILISTIC"]