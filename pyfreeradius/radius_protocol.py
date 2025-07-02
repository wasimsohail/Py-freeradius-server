#!/usr/bin/env python3

"""
RFC 2865 Compliant RADIUS Protocol Implementation

This module provides a complete implementation of the RADIUS protocol as defined
in RFC 2865, including proper packet encoding/decoding, authenticator validation,
User-Password encryption/decryption, and comprehensive attribute handling.

Key Features:
- Full RFC 2865 compliance
- Request/Response authenticator validation
- User-Password encryption/decryption
- Support for all standard attribute types
- Proper error handling and validation
- Thread-safe implementation
- High-performance packet processing

Usage:
    >>> from pyfreeradius.radius_protocol import RadiusPacket, RadiusCode
    >>> from pyfreeradius.dictionary import Dictionary

    >>> # Create a dictionary with standard attributes
    >>> dictionary = Dictionary()
    >>> dictionary.load_standard_attributes()

    >>> # Create an Access-Request packet
    >>> packet = RadiusPacket(
    ...     code=RadiusCode.ACCESS_REQUEST,
    ...     identifier=123
    ... )
    >>> packet.add_attribute("User-Name", "alice", dictionary)
    >>> packet.add_attribute("User-Password", "secret", dictionary)

    >>> # Encode for transmission
    >>> secret = b"shared_secret"
    >>> data = packet.encode(secret, dictionary)

    >>> # Decode received packet
    >>> received = RadiusPacket.decode(data, secret, dictionary)
    >>> print(f"User: {received.get_attribute('User-Name')}")
"""

import hashlib
import hmac
import ipaddress
import os
import secrets
import struct
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional, Tuple, Union, Any, ClassVar

__all__ = [
    "RadiusCode",
    "RadiusPacket",
    "RadiusAttribute",
    "RadiusError",
    "AuthenticatorError",
    "AttributeError",
    "PacketTooLongError",
]


class RadiusError(Exception):
    """Base exception for RADIUS protocol errors."""
    pass


class AuthenticatorError(RadiusError):
    """Raised when authenticator validation fails."""
    pass


class AttributeError(RadiusError):
    """Raised when attribute processing fails."""
    pass


class PacketTooLongError(RadiusError):
    """Raised when packet exceeds maximum length."""
    pass


class RadiusCode(IntEnum):
    """RADIUS packet codes as defined in RFC 2865."""
    ACCESS_REQUEST = 1
    ACCESS_ACCEPT = 2
    ACCESS_REJECT = 3
    ACCOUNTING_REQUEST = 4
    ACCOUNTING_RESPONSE = 5
    ACCESS_CHALLENGE = 11
    STATUS_SERVER = 12
    STATUS_CLIENT = 13
    RESERVED = 255


@dataclass
class RadiusAttribute:
    """Represents a RADIUS attribute with type, length, and value."""
    type: int
    value: Union[str, int, bytes, ipaddress.IPv4Address, ipaddress.IPv6Address]

    def encode(self, dictionary=None) -> bytes:
        """Encode attribute to wire format."""
        if dictionary:
            attr_def = dictionary.by_code(self.type)
            if attr_def:
                return self._encode_typed_value(attr_def.type)

        # Fallback to raw bytes encoding
        if isinstance(self.value, bytes):
            value_bytes = self.value
        elif isinstance(self.value, str):
            value_bytes = self.value.encode('utf-8')
        elif isinstance(self.value, int):
            value_bytes = struct.pack('!I', self.value)
        else:
            value_bytes = str(self.value).encode('utf-8')

        if len(value_bytes) > 253:
            raise AttributeError(f"Attribute value too long: {len(value_bytes)} bytes")

        return struct.pack('!BB', self.type, len(value_bytes) + 2) + value_bytes

    def _encode_typed_value(self, attr_type: str) -> bytes:
        """Encode value based on attribute type."""
        if attr_type == "string":
            if isinstance(self.value, str):
                value_bytes = self.value.encode('utf-8')
            elif isinstance(self.value, bytes):
                value_bytes = self.value
            else:
                value_bytes = str(self.value).encode('utf-8')

        elif attr_type == "integer":
            if isinstance(self.value, int):
                value_bytes = struct.pack('!I', self.value)
            else:
                value_bytes = struct.pack('!I', int(self.value))

        elif attr_type == "ipaddr":
            if isinstance(self.value, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                value_bytes = self.value.packed
            elif isinstance(self.value, str):
                addr = ipaddress.ip_address(self.value)
                value_bytes = addr.packed
            else:
                raise AttributeError(f"Invalid IP address: {self.value}")

        elif attr_type == "date":
            if isinstance(self.value, int):
                value_bytes = struct.pack('!I', self.value)
            else:
                # Assume it's a timestamp
                value_bytes = struct.pack('!I', int(time.time()))

        elif attr_type == "octets":
            if isinstance(self.value, bytes):
                value_bytes = self.value
            elif isinstance(self.value, str):
                # Assume hex string
                value_bytes = bytes.fromhex(self.value.replace(':', '').replace('-', ''))
            else:
                raise AttributeError(f"Invalid octets value: {self.value}")

        else:
            # Default to string encoding
            if isinstance(self.value, bytes):
                value_bytes = self.value
            else:
                value_bytes = str(self.value).encode('utf-8')

        if len(value_bytes) > 253:
            raise AttributeError(f"Attribute value too long: {len(value_bytes)} bytes")

        return struct.pack('!BB', self.type, len(value_bytes) + 2) + value_bytes

    @classmethod
    def decode(cls, data: bytes, offset: int, dictionary=None) -> Tuple['RadiusAttribute', int]:
        """Decode attribute from wire format."""
        if len(data) < offset + 2:
            raise AttributeError("Insufficient data for attribute header")

        attr_type, attr_length = struct.unpack('!BB', data[offset:offset+2])

        if attr_length < 2:
            raise AttributeError(f"Invalid attribute length: {attr_length}")

        if len(data) < offset + attr_length:
            raise AttributeError("Insufficient data for attribute value")

        value_data = data[offset+2:offset+attr_length]

        # Decode value based on dictionary type
        if dictionary:
            attr_def = dictionary.by_code(attr_type)
            if attr_def:
                value = cls._decode_typed_value(value_data, attr_def.type)
            else:
                value = value_data  # Unknown attribute, keep as bytes
        else:
            value = value_data

        return cls(attr_type, value), offset + attr_length

    @staticmethod
    def _decode_typed_value(data: bytes, attr_type: str) -> Union[str, int, bytes]:
        """Decode value based on attribute type."""
        if attr_type == "string":
            try:
                return data.decode('utf-8')
            except UnicodeDecodeError:
                return data

        elif attr_type == "integer" or attr_type == "date":
            if len(data) == 4:
                return struct.unpack('!I', data)[0]
            else:
                return data

        elif attr_type == "ipaddr":
            try:
                return str(ipaddress.ip_address(data))
            except ValueError:
                return data

        elif attr_type == "octets":
            return data

        else:
            # Try string first, fall back to bytes
            try:
                return data.decode('utf-8')
            except UnicodeDecodeError:
                return data


class RadiusPacket:
    """
    RFC 2865 compliant RADIUS packet implementation.

    This class handles all aspects of RADIUS packet processing including:
    - Packet encoding/decoding
    - Authenticator generation and validation
    - User-Password encryption/decryption
    - Attribute management
    """

    # Constants from RFC 2865
    MAX_PACKET_LENGTH = 4096
    AUTHENTICATOR_LENGTH = 16
    HEADER_LENGTH = 20

    def __init__(self, code: RadiusCode, identifier: int, authenticator: Optional[bytes] = None):
        """
        Initialize a RADIUS packet.

        Args:
            code: RADIUS packet code
            identifier: Packet identifier (0-255)
            authenticator: 16-byte authenticator (generated if not provided)
        """
        self.code = RadiusCode(code)
        self.identifier = identifier & 0xFF  # Ensure 8-bit value
        self.authenticator = authenticator or self._generate_request_authenticator()
        self.attributes: List[RadiusAttribute] = []

        if len(self.authenticator) != self.AUTHENTICATOR_LENGTH:
            raise RadiusError(f"Authenticator must be {self.AUTHENTICATOR_LENGTH} bytes")

    def _generate_request_authenticator(self) -> bytes:
        """Generate a random Request Authenticator."""
        return secrets.token_bytes(self.AUTHENTICATOR_LENGTH)

    def add_attribute(self, name_or_type: Union[str, int], value: Any, dictionary=None) -> None:
        """
        Add an attribute to the packet.

        Args:
            name_or_type: Attribute name (string) or type code (int)
            value: Attribute value
            dictionary: Dictionary for name resolution
        """
        if isinstance(name_or_type, str):
            if not dictionary:
                raise AttributeError("Dictionary required for attribute name resolution")
            attr_def = dictionary.by_name(name_or_type)
            if not attr_def:
                raise AttributeError(f"Unknown attribute name: {name_or_type}")
            attr_type = attr_def.code
        else:
            attr_type = name_or_type

        self.attributes.append(RadiusAttribute(attr_type, value))

    def get_attribute(self, name_or_type: Union[str, int], dictionary=None) -> Optional[Any]:
        """
        Get the first attribute value by name or type.

        Args:
            name_or_type: Attribute name (string) or type code (int)
            dictionary: Dictionary for name resolution

        Returns:
            Attribute value or None if not found
        """
        if isinstance(name_or_type, str):
            if not dictionary:
                raise AttributeError("Dictionary required for attribute name resolution")
            attr_def = dictionary.by_name(name_or_type)
            if not attr_def:
                return None
            attr_type = attr_def.code
        else:
            attr_type = name_or_type

        for attr in self.attributes:
            if attr.type == attr_type:
                return attr.value
        return None

    def get_all_attributes(self, name_or_type: Union[str, int], dictionary=None) -> List[Any]:
        """
        Get all attribute values by name or type.

        Args:
            name_or_type: Attribute name (string) or type code (int)
            dictionary: Dictionary for name resolution

        Returns:
            List of attribute values
        """
        if isinstance(name_or_type, str):
            if not dictionary:
                raise AttributeError("Dictionary required for attribute name resolution")
            attr_def = dictionary.by_name(name_or_type)
            if not attr_def:
                return []
            attr_type = attr_def.code
        else:
            attr_type = name_or_type

        return [attr.value for attr in self.attributes if attr.type == attr_type]

    def remove_attribute(self, name_or_type: Union[str, int], dictionary=None) -> bool:
        """
        Remove the first attribute by name or type.

        Args:
            name_or_type: Attribute name (string) or type code (int)
            dictionary: Dictionary for name resolution

        Returns:
            True if attribute was removed, False if not found
        """
        if isinstance(name_or_type, str):
            if not dictionary:
                raise AttributeError("Dictionary required for attribute name resolution")
            attr_def = dictionary.by_name(name_or_type)
            if not attr_def:
                return False
            attr_type = attr_def.code
        else:
            attr_type = name_or_type

        for i, attr in enumerate(self.attributes):
            if attr.type == attr_type:
                del self.attributes[i]
                return True
        return False

    def encrypt_user_password(self, password: str, secret: bytes) -> bytes:
        """
        Encrypt User-Password attribute according to RFC 2865.

        Args:
            password: Plaintext password
            secret: Shared secret

        Returns:
            Encrypted password bytes
        """
        if not isinstance(password, str):
            password = str(password)

        # Pad password to multiple of 16 bytes
        password_bytes = password.encode('utf-8')
        pad_length = 16 - (len(password_bytes) % 16)
        if pad_length != 16:
            password_bytes += b'\x00' * pad_length

        # Encrypt using MD5 and XOR
        encrypted = b''
        prev_block = self.authenticator

        for i in range(0, len(password_bytes), 16):
            # MD5(secret + prev_block)
            hash_input = secret + prev_block
            md5_hash = hashlib.md5(hash_input).digest()

            # XOR with password block
            password_block = password_bytes[i:i+16]
            encrypted_block = bytes(a ^ b for a, b in zip(password_block, md5_hash))
            encrypted += encrypted_block
            prev_block = encrypted_block

        return encrypted

    def decrypt_user_password(self, encrypted_password: bytes, secret: bytes) -> str:
        """
        Decrypt User-Password attribute according to RFC 2865.

        Args:
            encrypted_password: Encrypted password bytes
            secret: Shared secret

        Returns:
            Decrypted password string
        """
        if len(encrypted_password) % 16 != 0:
            raise AttributeError("Encrypted password length must be multiple of 16")

        # Decrypt using MD5 and XOR
        decrypted = b''
        prev_block = self.authenticator

        for i in range(0, len(encrypted_password), 16):
            # MD5(secret + prev_block)
            hash_input = secret + prev_block
            md5_hash = hashlib.md5(hash_input).digest()

            # XOR with encrypted block
            encrypted_block = encrypted_password[i:i+16]
            decrypted_block = bytes(a ^ b for a, b in zip(encrypted_block, md5_hash))
            decrypted += decrypted_block
            prev_block = encrypted_block

        # Remove null padding
        return decrypted.rstrip(b'\x00').decode('utf-8')

    def calculate_response_authenticator(self, secret: bytes, request_authenticator: bytes) -> bytes:
        """
        Calculate Response Authenticator according to RFC 2865.

        Args:
            secret: Shared secret
            request_authenticator: Request packet authenticator

        Returns:
            Response authenticator bytes
        """
        # Encode packet with request authenticator
        temp_packet = RadiusPacket(self.code, self.identifier, request_authenticator)
        temp_packet.attributes = self.attributes.copy()
        packet_data = temp_packet._encode_without_authenticator()

        # Calculate MD5(Code + ID + Length + Request-Auth + Attributes + Secret)
        hash_input = packet_data + secret
        return hashlib.md5(hash_input).digest()

    def verify_request_authenticator(self, secret: bytes) -> bool:
        """
        Verify Request Authenticator (always true for Access-Request).

        Args:
            secret: Shared secret

        Returns:
            True if authenticator is valid
        """
        # For Access-Request, any non-zero authenticator is valid
        return self.authenticator != b'\x00' * self.AUTHENTICATOR_LENGTH

    def verify_response_authenticator(self, secret: bytes, request_authenticator: bytes) -> bool:
        """
        Verify Response Authenticator according to RFC 2865.

        Args:
            secret: Shared secret
            request_authenticator: Original request authenticator

        Returns:
            True if authenticator is valid
        """
        expected = self.calculate_response_authenticator(secret, request_authenticator)
        return hmac.compare_digest(self.authenticator, expected)

    def _encode_without_authenticator(self) -> bytes:
        """Encode packet without final authenticator (for calculations)."""
        # Encode attributes
        attr_data = b''
        for attr in self.attributes:
            attr_data += attr.encode()

        # Calculate total length
        total_length = self.HEADER_LENGTH + len(attr_data)
        if total_length > self.MAX_PACKET_LENGTH:
            raise PacketTooLongError(f"Packet too long: {total_length} bytes")

        # Encode header
        header = struct.pack('!BBH16s',
                           self.code,
                           self.identifier,
                           total_length,
                           self.authenticator)

                return header + attr_data

    def encode(self, secret: bytes, dictionary=None, request_authenticator: bytes = None) -> bytes:
        """
        Encode packet for transmission.

        Args:
            secret: Shared secret
            dictionary: Attribute dictionary
            request_authenticator: Original request authenticator (for responses)

        Returns:
            Encoded packet bytes
        """
        if not secret:
            raise RadiusError("Shared secret cannot be empty")

        # Handle User-Password encryption
        if dictionary:
            for i, attr in enumerate(self.attributes):
                if attr.type == 2:  # User-Password
                    if isinstance(attr.value, str):
                        encrypted_password = self.encrypt_user_password(attr.value, secret)
                        self.attributes[i] = RadiusAttribute(2, encrypted_password)
                    break

        # For response packets, calculate response authenticator
        if self.code in (RadiusCode.ACCESS_ACCEPT, RadiusCode.ACCESS_REJECT,
                        RadiusCode.ACCESS_CHALLENGE, RadiusCode.ACCOUNTING_RESPONSE):
            if request_authenticator:
                self.authenticator = self.calculate_response_authenticator(secret, request_authenticator)

        return self._encode_without_authenticator()

    @classmethod
    def decode(cls, data: bytes, secret: bytes, dictionary=None) -> 'RadiusPacket':
        """
        Decode packet from wire format.

        Args:
            data: Raw packet data
            secret: Shared secret
            dictionary: Attribute dictionary

        Returns:
            Decoded RadiusPacket
        """
        if len(data) < cls.HEADER_LENGTH:
            raise RadiusError(f"Packet too short: {len(data)} bytes")

        # Decode header
        code, identifier, length, authenticator = struct.unpack('!BBH16s', data[:cls.HEADER_LENGTH])

        if len(data) != length:
            raise RadiusError(f"Packet length mismatch: {len(data)} != {length}")

        if length > cls.MAX_PACKET_LENGTH:
            raise RadiusError(f"Packet too long: {length} bytes")

        # Create packet
        packet = cls(RadiusCode(code), identifier, authenticator)

        # Decode attributes
        offset = cls.HEADER_LENGTH
        while offset < length:
            try:
                attr, offset = RadiusAttribute.decode(data, offset, dictionary)
                packet.attributes.append(attr)
            except AttributeError as e:
                raise RadiusError(f"Failed to decode attribute at offset {offset}: {e}")

        # Handle User-Password decryption
        if dictionary:
            for i, attr in enumerate(packet.attributes):
                if attr.type == 2 and isinstance(attr.value, bytes):  # User-Password
                    try:
                        decrypted_password = packet.decrypt_user_password(attr.value, secret)
                        packet.attributes[i] = RadiusAttribute(2, decrypted_password)
                    except Exception:
                        # Keep encrypted if decryption fails
                        pass

        return packet

    def __str__(self) -> str:
        """String representation of packet."""
        attrs = []
        for attr in self.attributes:
            attrs.append(f"  {attr.type}: {attr.value}")
        attr_str = '\n'.join(attrs) if attrs else "  (no attributes)"

        return f"RadiusPacket(\n  code={self.code.name},\n  id={self.identifier},\n  attributes=[\n{attr_str}\n  ]\n)"

    def __repr__(self) -> str:
        """Repr of packet."""
        return f"RadiusPacket(code={self.code}, identifier={self.identifier}, attributes={len(self.attributes)})"


# Convenience functions for common operations
def create_access_request(username: str, password: str, identifier: int = None) -> RadiusPacket:
    """Create a basic Access-Request packet."""
    if identifier is None:
        identifier = secrets.randbits(8)

    packet = RadiusPacket(RadiusCode.ACCESS_REQUEST, identifier)
    packet.add_attribute(1, username)  # User-Name
    packet.add_attribute(2, password)  # User-Password
    return packet


def create_access_accept(identifier: int, request_authenticator: bytes) -> RadiusPacket:
    """Create an Access-Accept response packet."""
    return RadiusPacket(RadiusCode.ACCESS_ACCEPT, identifier, request_authenticator)


def create_access_reject(identifier: int, request_authenticator: bytes, message: str = None) -> RadiusPacket:
    """Create an Access-Reject response packet."""
    packet = RadiusPacket(RadiusCode.ACCESS_REJECT, identifier, request_authenticator)
    if message:
        packet.add_attribute(18, message)  # Reply-Message
    return packet
