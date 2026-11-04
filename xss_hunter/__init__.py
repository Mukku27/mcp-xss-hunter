"""Context-aware XSS hunter with browser-verified execution.

The package is intentionally small: one module per stage of the verification
ladder (scope -> probe -> classify -> payload -> verify -> evidence -> result).
"""

__version__ = "0.1.0"
