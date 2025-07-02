"""
RADIUS Dictionary System

This module provides attribute dictionary management for RADIUS packets.
It handles attribute definitions including name, code, and type information.

Key features:
- Attribute definition storage and lookup
- Support for standard RADIUS attribute types
- Name-to-code and code-to-name mapping
- Dictionary file loading (basic implementation)
"""

from __future__ import annotations

"""Dictionary loader for pyfreeradius.

Supports a minimal subset of the FreeRADIUS dictionary syntax adequate for
packet encoding/decoding in milestone-1.

Supported directives (case-insensitive):

ATTRIBUTE <name> <code> <type> [vendor]
VALUE     <attr_name> <value_name> <number>  (ignored for now)
INCLUDE   <path>                              (relative to current file)

Lines starting with `#` are comments.  Blank lines are ignored.
"""

import pathlib
from dataclasses import dataclass
from typing import Dict, Optional, List

__all__ = [
    "AttributeDef",
    "Dictionary",
]


@dataclass(frozen=True)
class AttributeDef:
    """
    RADIUS attribute definition.

    Represents a single RADIUS attribute with its name, code, and type.
    """
    name: str
    code: int
    type: str  # string, integer, ipaddr, octets, date, etc.

    def __post_init__(self):
        """Validate attribute definition after creation."""
        if not self.name or not isinstance(self.name, str):
            raise ValueError("Attribute name must be a non-empty string")

        if not isinstance(self.code, int) or self.code < 1 or self.code > 255:
            raise ValueError("Attribute code must be an integer between 1 and 255")

        if not self.type or not isinstance(self.type, str):
            raise ValueError("Attribute type must be a non-empty string")


class Dictionary:
    """
    RADIUS attribute dictionary.

    Manages attribute definitions and provides lookup functionality
    by name or code.
    """

    def __init__(self):
        """Initialize empty dictionary."""
        self._by_name: Dict[str, AttributeDef] = {}
        self._by_code: Dict[int, AttributeDef] = {}

    def add_attribute(self, attr_def: AttributeDef) -> None:
        """
        Add an attribute definition to the dictionary.

        Args:
            attr_def: Attribute definition to add

        Raises:
            ValueError: If attribute name or code already exists
        """
        if attr_def.name in self._by_name:
            existing = self._by_name[attr_def.name]
            if existing.code != attr_def.code or existing.type != attr_def.type:
                raise ValueError(f"Attribute name '{attr_def.name}' already exists with different definition")
            # Same definition, ignore duplicate
            return

        if attr_def.code in self._by_code:
            existing = self._by_code[attr_def.code]
            if existing.name != attr_def.name or existing.type != attr_def.type:
                raise ValueError(f"Attribute code {attr_def.code} already exists with different definition")
            # Same definition, ignore duplicate
            return

        self._by_name[attr_def.name] = attr_def
        self._by_code[attr_def.code] = attr_def

    def by_name(self, name: str) -> Optional[AttributeDef]:
        """
        Look up attribute definition by name.

        Args:
            name: Attribute name

        Returns:
            Attribute definition or None if not found
        """
        return self._by_name.get(name)

    def by_code(self, code: int) -> Optional[AttributeDef]:
        """
        Look up attribute definition by code.

        Args:
            code: Attribute code

        Returns:
            Attribute definition or None if not found
        """
        return self._by_code.get(code)

    def get_all_attributes(self) -> List[AttributeDef]:
        """
        Get all attribute definitions.

        Returns:
            List of all attribute definitions
        """
        return list(self._by_code.values())

    def get_attribute_count(self) -> int:
        """
        Get the number of attributes in the dictionary.

        Returns:
            Number of attributes
        """
        return len(self._by_code)

    def remove_attribute(self, name_or_code) -> bool:
        """
        Remove an attribute from the dictionary.

        Args:
            name_or_code: Attribute name (str) or code (int)

        Returns:
            True if attribute was removed, False if not found
        """
        if isinstance(name_or_code, str):
            attr_def = self._by_name.get(name_or_code)
            if attr_def:
                del self._by_name[attr_def.name]
                del self._by_code[attr_def.code]
                return True
        elif isinstance(name_or_code, int):
            attr_def = self._by_code.get(name_or_code)
            if attr_def:
                del self._by_name[attr_def.name]
                del self._by_code[attr_def.code]
                return True
        return False

    def load_from_file(self, file_path: str) -> None:
        """
        Load attribute definitions from a dictionary file.

        Basic implementation that supports:
        - ATTRIBUTE name code type
        - Comments (lines starting with #)
        - Blank lines

        Args:
            file_path: Path to dictionary file
        """
        path = pathlib.Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Dictionary file not found: {file_path}")

        try:
            with open(path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()

                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue

                    # Parse ATTRIBUTE lines
                    tokens = line.split()
                    if len(tokens) >= 4 and tokens[0].upper() == 'ATTRIBUTE':
                        try:
                            name = tokens[1]
                            code = int(tokens[2])
                            attr_type = tokens[3].lower()

                            attr_def = AttributeDef(name, code, attr_type)
                            self.add_attribute(attr_def)

                        except (ValueError, IndexError) as e:
                            raise ValueError(f"Error parsing line {line_num}: {e}")

                    # Ignore other directive types for now (VALUE, INCLUDE, etc.)

        except Exception as e:
            raise ValueError(f"Error loading dictionary file {file_path}: {e}")

    def save_to_file(self, file_path: str) -> None:
        """
        Save attribute definitions to a dictionary file.

        Args:
            file_path: Path to output file
        """
        path = pathlib.Path(file_path)

        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write("# RADIUS Dictionary File\n")
                f.write("# Generated by PyFreeRADIUS\n\n")

                # Sort attributes by code for consistent output
                sorted_attrs = sorted(self._by_code.values(), key=lambda x: x.code)

                for attr_def in sorted_attrs:
                    f.write(f"ATTRIBUTE\t{attr_def.name}\t{attr_def.code}\t{attr_def.type}\n")

        except Exception as e:
            raise ValueError(f"Error saving dictionary file {file_path}: {e}")

    def __contains__(self, name_or_code) -> bool:
        """Check if attribute exists in dictionary."""
        if isinstance(name_or_code, str):
            return name_or_code in self._by_name
        elif isinstance(name_or_code, int):
            return name_or_code in self._by_code
        return False

    def __len__(self) -> int:
        """Get number of attributes in dictionary."""
        return len(self._by_code)

    def __str__(self) -> str:
        """String representation of dictionary."""
        return f"Dictionary({len(self._by_code)} attributes)"

    def __repr__(self) -> str:
        """Detailed representation of dictionary."""
        return f"Dictionary(attributes={len(self._by_code)})"


def create_standard_dictionary() -> Dictionary:
    """
    Create a dictionary with standard RADIUS attributes.

    Returns:
        Dictionary with common RFC 2865 attributes
    """
    dictionary = Dictionary()

    # Standard RADIUS attributes from RFC 2865 and extensions
    standard_attributes = [
        # RFC 2865 Core Attributes (1-39)
        AttributeDef("User-Name", 1, "string"),
        AttributeDef("User-Password", 2, "string"),
        AttributeDef("CHAP-Password", 3, "octets"),
        AttributeDef("NAS-IP-Address", 4, "ipaddr"),
        AttributeDef("NAS-Port", 5, "integer"),
        AttributeDef("Service-Type", 6, "integer"),
        AttributeDef("Framed-Protocol", 7, "integer"),
        AttributeDef("Framed-IP-Address", 8, "ipaddr"),
        AttributeDef("Framed-IP-Netmask", 9, "ipaddr"),
        AttributeDef("Framed-Routing", 10, "integer"),
        AttributeDef("Filter-Id", 11, "string"),
        AttributeDef("Framed-MTU", 12, "integer"),
        AttributeDef("Framed-Compression", 13, "integer"),
        AttributeDef("Login-IP-Host", 14, "ipaddr"),
        AttributeDef("Login-Service", 15, "integer"),
        AttributeDef("Login-TCP-Port", 16, "integer"),
        # Attribute 17 is unassigned
        AttributeDef("Reply-Message", 18, "string"),
        AttributeDef("Callback-Number", 19, "string"),
        AttributeDef("Callback-Id", 20, "string"),
        # Attribute 21 is unassigned
        AttributeDef("Framed-Route", 22, "string"),
        AttributeDef("Framed-IPX-Network", 23, "ipaddr"),
        AttributeDef("State", 24, "octets"),
        AttributeDef("Class", 25, "octets"),
        AttributeDef("Vendor-Specific", 26, "octets"),
        AttributeDef("Session-Timeout", 27, "integer"),
        AttributeDef("Idle-Timeout", 28, "integer"),
        AttributeDef("Termination-Action", 29, "integer"),
        AttributeDef("Called-Station-Id", 30, "string"),
        AttributeDef("Calling-Station-Id", 31, "string"),
        AttributeDef("NAS-Identifier", 32, "string"),
        AttributeDef("Proxy-State", 33, "octets"),
        AttributeDef("Login-LAT-Service", 34, "string"),
        AttributeDef("Login-LAT-Node", 35, "string"),
        AttributeDef("Login-LAT-Group", 36, "octets"),
        AttributeDef("Framed-AppleTalk-Link", 37, "integer"),
        AttributeDef("Framed-AppleTalk-Network", 38, "integer"),
        AttributeDef("Framed-AppleTalk-Zone", 39, "string"),

                # Accounting attributes (40-49)
        AttributeDef("Acct-Status-Type", 40, "integer"),
        AttributeDef("Acct-Delay-Time", 41, "integer"),
        AttributeDef("Acct-Input-Octets", 42, "integer"),
        AttributeDef("Acct-Output-Octets", 43, "integer"),
        AttributeDef("Acct-Session-Id", 44, "string"),
        AttributeDef("Acct-Authentic", 45, "integer"),
        AttributeDef("Acct-Session-Time", 46, "integer"),
        AttributeDef("Acct-Input-Packets", 47, "integer"),
        AttributeDef("Acct-Output-Packets", 48, "integer"),
        AttributeDef("Acct-Terminate-Cause", 49, "integer"),
        AttributeDef("Acct-Multi-Session-Id", 50, "string"),
        AttributeDef("Acct-Link-Count", 51, "integer"),

        # Common vendor attributes and extensions (55, 60-85)
        AttributeDef("Event-Timestamp", 55, "integer"),
        AttributeDef("CHAP-Challenge", 60, "octets"),
        AttributeDef("NAS-Port-Type", 61, "integer"),
        AttributeDef("Port-Limit", 62, "integer"),
        AttributeDef("Login-LAT-Port", 63, "string"),
        AttributeDef("Tunnel-Type", 64, "integer"),
        AttributeDef("Tunnel-Medium-Type", 65, "integer"),
        AttributeDef("Tunnel-Client-Endpoint", 66, "string"),
        AttributeDef("Tunnel-Server-Endpoint", 67, "string"),
        AttributeDef("Acct-Tunnel-Connection", 68, "string"),
        AttributeDef("Tunnel-Password", 69, "string"),
        AttributeDef("ARAP-Password", 70, "octets"),
        AttributeDef("ARAP-Features", 71, "octets"),
        AttributeDef("ARAP-Zone-Access", 72, "integer"),
        AttributeDef("ARAP-Security", 73, "integer"),
        AttributeDef("ARAP-Security-Data", 74, "string"),
        AttributeDef("Password-Retry", 75, "integer"),
        AttributeDef("Prompt", 76, "integer"),
        AttributeDef("Connect-Info", 77, "string"),
        AttributeDef("Configuration-Token", 78, "string"),
        AttributeDef("EAP-Message", 79, "octets"),
        AttributeDef("Message-Authenticator", 80, "octets"),
        AttributeDef("Tunnel-Private-Group-Id", 81, "string"),
        AttributeDef("Tunnel-Assignment-Id", 82, "string"),
        AttributeDef("Tunnel-Preference", 83, "integer"),
                AttributeDef("ARAP-Challenge-Response", 84, "octets"),
        AttributeDef("Acct-Interim-Interval", 85, "integer"),

        # Additional common attributes
        AttributeDef("NAS-Port-Id", 87, "string"),
        AttributeDef("Framed-Pool", 88, "string"),
        AttributeDef("Chargeable-User-Identity", 89, "string"),
        AttributeDef("NAS-IPv6-Address", 95, "octets"),
        AttributeDef("Framed-Interface-Id", 96, "octets"),
        AttributeDef("Framed-IPv6-Prefix", 97, "octets"),
        AttributeDef("Login-IPv6-Host", 98, "octets"),
        AttributeDef("Framed-IPv6-Route", 99, "string"),
        AttributeDef("Framed-IPv6-Pool", 100, "string"),
    ]

    for attr_def in standard_attributes:
        dictionary.add_attribute(attr_def)

    return dictionary
