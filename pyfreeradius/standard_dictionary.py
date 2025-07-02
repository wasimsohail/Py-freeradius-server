#!/usr/bin/env python3

"""
Standard RADIUS Dictionary (RFC 2865)

This module provides a pre-loaded dictionary with all standard RADIUS attributes
as defined in RFC 2865 and common extensions. This eliminates the need to load
external dictionary files for basic RADIUS operations.

Usage:
    >>> from pyfreeradius.standard_dictionary import get_standard_dictionary
    >>> dictionary = get_standard_dictionary()
    >>> attr = dictionary.by_name('User-Name')
    >>> print(f"User-Name: code={attr.code}, type={attr.type}")
"""

from .dictionary import Dictionary, AttributeDef

# Standard RADIUS attributes from RFC 2865
STANDARD_ATTRIBUTES = [
    # Core attributes (1-39)
    AttributeDef('User-Name', 1, 'string'),
    AttributeDef('User-Password', 2, 'string'),
    AttributeDef('CHAP-Password', 3, 'octets'),
    AttributeDef('NAS-IP-Address', 4, 'ipaddr'),
    AttributeDef('NAS-Port', 5, 'integer'),
    AttributeDef('Service-Type', 6, 'integer'),
    AttributeDef('Framed-Protocol', 7, 'integer'),
    AttributeDef('Framed-IP-Address', 8, 'ipaddr'),
    AttributeDef('Framed-IP-Netmask', 9, 'ipaddr'),
    AttributeDef('Framed-Routing', 10, 'integer'),
    AttributeDef('Filter-Id', 11, 'string'),
    AttributeDef('Framed-MTU', 12, 'integer'),
    AttributeDef('Framed-Compression', 13, 'integer'),
    AttributeDef('Login-IP-Host', 14, 'ipaddr'),
    AttributeDef('Login-Service', 15, 'integer'),
    AttributeDef('Login-TCP-Port', 16, 'integer'),
    # 17 is unassigned
    AttributeDef('Reply-Message', 18, 'string'),
    AttributeDef('Callback-Number', 19, 'string'),
    AttributeDef('Callback-Id', 20, 'string'),
    # 21 is unassigned
    AttributeDef('Framed-Route', 22, 'string'),
    AttributeDef('Framed-IPX-Network', 23, 'ipaddr'),
    AttributeDef('State', 24, 'octets'),
    AttributeDef('Class', 25, 'octets'),
    AttributeDef('Vendor-Specific', 26, 'octets'),
    AttributeDef('Session-Timeout', 27, 'integer'),
    AttributeDef('Idle-Timeout', 28, 'integer'),
    AttributeDef('Termination-Action', 29, 'integer'),
    AttributeDef('Called-Station-Id', 30, 'string'),
    AttributeDef('Calling-Station-Id', 31, 'string'),
    AttributeDef('NAS-Identifier', 32, 'string'),
    AttributeDef('Proxy-State', 33, 'octets'),
    AttributeDef('Login-LAT-Service', 34, 'string'),
    AttributeDef('Login-LAT-Node', 35, 'string'),
    AttributeDef('Login-LAT-Group', 36, 'octets'),
    AttributeDef('Framed-AppleTalk-Link', 37, 'integer'),
    AttributeDef('Framed-AppleTalk-Network', 38, 'integer'),
    AttributeDef('Framed-AppleTalk-Zone', 39, 'string'),

    # Extended attributes (40-59) - Common extensions
    AttributeDef('CHAP-Challenge', 40, 'octets'),
    AttributeDef('NAS-Port-Type', 41, 'integer'),
    AttributeDef('Port-Limit', 42, 'integer'),
    AttributeDef('Login-LAT-Port', 43, 'string'),

    # Accounting attributes (40-59)
    AttributeDef('Acct-Status-Type', 40, 'integer'),
    AttributeDef('Acct-Delay-Time', 41, 'integer'),
    AttributeDef('Acct-Input-Octets', 42, 'integer'),
    AttributeDef('Acct-Output-Octets', 43, 'integer'),
    AttributeDef('Acct-Session-Id', 44, 'string'),
    AttributeDef('Acct-Authentic', 45, 'integer'),
    AttributeDef('Acct-Session-Time', 46, 'integer'),
    AttributeDef('Acct-Input-Packets', 47, 'integer'),
    AttributeDef('Acct-Output-Packets', 48, 'integer'),
    AttributeDef('Acct-Terminate-Cause', 49, 'integer'),
    AttributeDef('Acct-Multi-Session-Id', 50, 'string'),
    AttributeDef('Acct-Link-Count', 51, 'integer'),

    # Additional common attributes (60-89)
    AttributeDef('CHAP-Challenge', 60, 'octets'),
    AttributeDef('NAS-Port-Type', 61, 'integer'),
    AttributeDef('Port-Limit', 62, 'integer'),
    AttributeDef('Login-LAT-Port', 63, 'string'),
    AttributeDef('Tunnel-Type', 64, 'integer'),
    AttributeDef('Tunnel-Medium-Type', 65, 'integer'),
    AttributeDef('Tunnel-Client-Endpoint', 66, 'string'),
    AttributeDef('Tunnel-Server-Endpoint', 67, 'string'),
    AttributeDef('Acct-Tunnel-Connection', 68, 'string'),
    AttributeDef('Tunnel-Password', 69, 'string'),
    AttributeDef('ARAP-Password', 70, 'octets'),
    AttributeDef('ARAP-Features', 71, 'octets'),
    AttributeDef('ARAP-Zone-Access', 72, 'integer'),
    AttributeDef('ARAP-Security', 73, 'integer'),
    AttributeDef('ARAP-Security-Data', 74, 'string'),
    AttributeDef('Password-Retry', 75, 'integer'),
    AttributeDef('Prompt', 76, 'integer'),
    AttributeDef('Connect-Info', 77, 'string'),
    AttributeDef('Configuration-Token', 78, 'string'),
    AttributeDef('EAP-Message', 79, 'octets'),
    AttributeDef('Message-Authenticator', 80, 'octets'),

    # Tunnel attributes (81-89)
    AttributeDef('Tunnel-Private-Group-Id', 81, 'string'),
    AttributeDef('Tunnel-Assignment-Id', 82, 'string'),
    AttributeDef('Tunnel-Preference', 83, 'integer'),
    AttributeDef('ARAP-Challenge-Response', 84, 'octets'),
    AttributeDef('Acct-Interim-Interval', 85, 'integer'),
    AttributeDef('Acct-Tunnel-Packets-Lost', 86, 'integer'),
    AttributeDef('NAS-Port-Id', 87, 'string'),
    AttributeDef('Framed-Pool', 88, 'string'),
    AttributeDef('CUI', 89, 'octets'),

    # Extended attributes (90-99)
    AttributeDef('Tunnel-Client-Auth-Id', 90, 'string'),
    AttributeDef('Tunnel-Server-Auth-Id', 91, 'string'),
    AttributeDef('NAS-Filter-Rule', 92, 'string'),
    AttributeDef('Originating-Line-Info', 94, 'octets'),
    AttributeDef('NAS-IPv6-Address', 95, 'octets'),
    AttributeDef('Framed-Interface-Id', 96, 'octets'),
    AttributeDef('Framed-IPv6-Prefix', 97, 'octets'),
    AttributeDef('Login-IPv6-Host', 98, 'octets'),
    AttributeDef('Framed-IPv6-Route', 99, 'string'),
    AttributeDef('Framed-IPv6-Pool', 100, 'string'),
]

# Service-Type values
SERVICE_TYPE_VALUES = {
    'Login-User': 1,
    'Framed-User': 2,
    'Callback-Login-User': 3,
    'Callback-Framed-User': 4,
    'Outbound-User': 5,
    'Administrative-User': 6,
    'NAS-Prompt-User': 7,
    'Authenticate-Only': 8,
    'Callback-NAS-Prompt': 9,
    'Call-Check': 10,
    'Callback-Administrative': 11,
}

# Framed-Protocol values
FRAMED_PROTOCOL_VALUES = {
    'PPP': 1,
    'SLIP': 2,
    'ARAP': 3,
    'Gandalf': 4,
    'Xylogics': 5,
    'X.75': 6,
}

# NAS-Port-Type values
NAS_PORT_TYPE_VALUES = {
    'Async': 0,
    'Sync': 1,
    'ISDN-Sync': 2,
    'ISDN-Async-V.120': 3,
    'ISDN-Async-V.110': 4,
    'Virtual': 5,
    'PIAFS': 6,
    'HDLC-Clear-Channel': 7,
    'X.25': 8,
    'X.75': 9,
    'G.3-Fax': 10,
    'SDSL': 11,
    'ADSL-CAP': 12,
    'ADSL-DMT': 13,
    'IDSL': 14,
    'Ethernet': 15,
    'xDSL': 16,
    'Cable': 17,
    'Wireless-Other': 18,
    'Wireless-IEEE-802.11': 19,
}

# Acct-Status-Type values
ACCT_STATUS_TYPE_VALUES = {
    'Start': 1,
    'Stop': 2,
    'Interim-Update': 3,
    'Accounting-On': 7,
    'Accounting-Off': 8,
}

# Acct-Authentic values
ACCT_AUTHENTIC_VALUES = {
    'RADIUS': 1,
    'Local': 2,
    'Remote': 3,
    'Diameter': 4,
}

# Termination-Action values
TERMINATION_ACTION_VALUES = {
    'Default': 0,
    'RADIUS-Request': 1,
}

def get_standard_dictionary() -> Dictionary:
    """
    Create and return a dictionary with all standard RADIUS attributes.

    Returns:
        Dictionary: Pre-loaded dictionary with RFC 2865 attributes
    """
    dictionary = Dictionary()

    # Add all standard attributes
    for attr_def in STANDARD_ATTRIBUTES:
        dictionary.add_attribute(attr_def)

    return dictionary

def get_attribute_by_name(name: str) -> AttributeDef:
    """
    Get a standard attribute definition by name.

    Args:
        name: Attribute name (case-sensitive)

    Returns:
        AttributeDef: Attribute definition

    Raises:
        KeyError: If attribute name is not found
    """
    for attr_def in STANDARD_ATTRIBUTES:
        if attr_def.name == name:
            return attr_def
    raise KeyError(f"Unknown attribute name: {name}")

def get_attribute_by_code(code: int) -> AttributeDef:
    """
    Get a standard attribute definition by code.

    Args:
        code: Attribute code

    Returns:
        AttributeDef: Attribute definition

    Raises:
        KeyError: If attribute code is not found
    """
    for attr_def in STANDARD_ATTRIBUTES:
        if attr_def.code == code:
            return attr_def
    raise KeyError(f"Unknown attribute code: {code}")

def list_standard_attributes() -> list[AttributeDef]:
    """
    Get a list of all standard attribute definitions.

    Returns:
        List of AttributeDef objects
    """
    return STANDARD_ATTRIBUTES.copy()

def get_service_type_value(name: str) -> int:
    """Get Service-Type enumerated value by name."""
    return SERVICE_TYPE_VALUES[name]

def get_framed_protocol_value(name: str) -> int:
    """Get Framed-Protocol enumerated value by name."""
    return FRAMED_PROTOCOL_VALUES[name]

def get_nas_port_type_value(name: str) -> int:
    """Get NAS-Port-Type enumerated value by name."""
    return NAS_PORT_TYPE_VALUES[name]

def get_acct_status_type_value(name: str) -> int:
    """Get Acct-Status-Type enumerated value by name."""
    return ACCT_STATUS_TYPE_VALUES[name]

def get_acct_authentic_value(name: str) -> int:
    """Get Acct-Authentic enumerated value by name."""
    return ACCT_AUTHENTIC_VALUES[name]

def get_termination_action_value(name: str) -> int:
    """Get Termination-Action enumerated value by name."""
    return TERMINATION_ACTION_VALUES[name]

# Convenience function for quick setup
def create_basic_dictionary() -> Dictionary:
    """
    Create a dictionary with the most commonly used RADIUS attributes.

    This includes User-Name, User-Password, NAS-IP-Address, NAS-Port,
    Reply-Message, and other essential attributes.

    Returns:
        Dictionary: Dictionary with basic attributes
    """
    dictionary = Dictionary()

    # Essential attributes for basic authentication
    essential_attrs = [
        AttributeDef('User-Name', 1, 'string'),
        AttributeDef('User-Password', 2, 'string'),
        AttributeDef('CHAP-Password', 3, 'octets'),
        AttributeDef('NAS-IP-Address', 4, 'ipaddr'),
        AttributeDef('NAS-Port', 5, 'integer'),
        AttributeDef('Service-Type', 6, 'integer'),
        AttributeDef('Framed-Protocol', 7, 'integer'),
        AttributeDef('Framed-IP-Address', 8, 'ipaddr'),
        AttributeDef('Reply-Message', 18, 'string'),
        AttributeDef('State', 24, 'octets'),
        AttributeDef('Class', 25, 'octets'),
        AttributeDef('Session-Timeout', 27, 'integer'),
        AttributeDef('Idle-Timeout', 28, 'integer'),
        AttributeDef('Called-Station-Id', 30, 'string'),
        AttributeDef('Calling-Station-Id', 31, 'string'),
        AttributeDef('NAS-Identifier', 32, 'string'),
    ]

    for attr_def in essential_attrs:
        dictionary.add_attribute(attr_def)

    return dictionary

# Module-level convenience instance
_standard_dictionary = None

def get_cached_standard_dictionary() -> Dictionary:
    """
    Get a cached instance of the standard dictionary.

    This avoids recreating the dictionary on every call.

    Returns:
        Dictionary: Cached standard dictionary
    """
    global _standard_dictionary
    if _standard_dictionary is None:
        _standard_dictionary = get_standard_dictionary()
    return _standard_dictionary

if __name__ == "__main__":
    # Demo usage
    print("Standard RADIUS Dictionary Demo")
    print("=" * 40)

    # Create standard dictionary
    dictionary = get_standard_dictionary()
    print(f"Loaded {len(STANDARD_ATTRIBUTES)} standard attributes")

    # Show some examples
    examples = ['User-Name', 'User-Password', 'NAS-IP-Address', 'Reply-Message', 'Session-Timeout']

    print("\nExample attributes:")
    for name in examples:
        try:
            attr = dictionary.by_name(name)
            if attr:
                print(f"  {attr.name} (code={attr.code}, type={attr.type})")
            else:
                print(f"  {name}: Not found")
        except:
            print(f"  {name}: Not found")

    # Show service type values
    print(f"\nService-Type values:")
    for name, value in list(SERVICE_TYPE_VALUES.items())[:5]:
        print(f"  {name}: {value}")

    print("\n✅ Standard dictionary working correctly!")
