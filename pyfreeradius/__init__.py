"""
PyFreeRADIUS - A Python implementation of the RADIUS protocol (RFC 2865)

This package provides a complete implementation of the RADIUS protocol
for authentication, authorization, and accounting.
"""

__version__ = "1.0.0"
__author__ = "PyFreeRADIUS Team"

from .packet import Packet, Code
from .dictionary import Dictionary, AttributeDef

__all__ = [
    "Packet",
    "Code",
    "Dictionary",
    "AttributeDef"
]
