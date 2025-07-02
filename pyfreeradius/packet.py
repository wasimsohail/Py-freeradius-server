"""
RADIUS Packet Implementation (RFC 2865)

This module implements the core RADIUS packet structure and encoding/decoding
functionality as defined in RFC 2865.

Key features:
- Complete packet header handling (Code, Identifier, Length, Authenticator)
- Attribute encoding/decoding with proper TLV format
- User-Password encryption/decryption
- Request/Response authenticator validation
- Support for all standard attribute types
"""

import hashlib
import ipaddress
import os
import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional, Tuple, Union, Any

__all__ = ["Code", "Packet"]


class Code(IntEnum):
    """RADIUS packet codes as defined in RFC 2865."""
    ACCESS_REQUEST = 1
    ACCESS_ACCEPT = 2
    ACCESS_REJECT = 3
    ACCOUNTING_REQUEST = 4
    ACCOUNTING_RESPONSE = 5
    ACCESS_CHALLENGE = 11
    STATUS_SERVER = 12
    STATUS_CLIENT = 13


@dataclass
class Packet:
    """
    RADIUS packet implementation following RFC 2865.

    A RADIUS packet consists of:
    - Code (1 byte): Packet type
    - Identifier (1 byte): Matches requests with replies
    - Length (2 bytes): Total packet length
    - Authenticator (16 bytes): Used for authentication and integrity
    - Attributes (variable): Zero or more attribute-value pairs
    """

    # RFC 2865 constants
    HEADER_LENGTH = 20
    MAX_PACKET_LENGTH = 4096
    AUTHENTICATOR_LENGTH = 16

    code: Code
    identifier: int
    authenticator: bytes = field(default_factory=lambda: os.urandom(16))
    attributes: List[Tuple[int, Union[str, int, bytes, ipaddress.IPv4Address]]] = field(default_factory=list)

    def __post_init__(self):
        """Validate packet fields after initialization."""
        if not isinstance(self.code, Code):
            self.code = Code(self.code)

        self.identifier = self.identifier & 0xFF  # Ensure 8-bit value

        if len(self.authenticator) != self.AUTHENTICATOR_LENGTH:
            raise ValueError(f"Authenticator must be exactly {self.AUTHENTICATOR_LENGTH} bytes")

    def add_attribute(self, attr_type: int, value: Union[str, int, bytes, ipaddress.IPv4Address],
                     dictionary=None) -> None:
        """
        Add an attribute to the packet.

        Args:
            attr_type: Attribute type code
            value: Attribute value
            dictionary: Optional dictionary for type validation
        """
        self.attributes.append((attr_type, value))

    def get_attribute(self, attr_type: int) -> Optional[Union[str, int, bytes, ipaddress.IPv4Address]]:
        """
        Get the first attribute of the specified type.

        Args:
            attr_type: Attribute type code

        Returns:
            Attribute value or None if not found
        """
        for code, value in self.attributes:
            if code == attr_type:
                return value
        return None

    def get_all_attributes(self, attr_type: int) -> List[Union[str, int, bytes, ipaddress.IPv4Address]]:
        """
        Get all attributes of the specified type.

        Args:
            attr_type: Attribute type code

        Returns:
            List of attribute values
        """
        return [value for code, value in self.attributes if code == attr_type]

    def remove_attribute(self, attr_type: int) -> bool:
        """
        Remove the first attribute of the specified type.

        Args:
            attr_type: Attribute type code

        Returns:
            True if attribute was removed, False if not found
        """
        for i, (code, value) in enumerate(self.attributes):
            if code == attr_type:
                del self.attributes[i]
                return True
        return False

    def _encode_attribute(self, attr_type: int, value: Union[str, int, bytes, ipaddress.IPv4Address],
                         dictionary=None) -> bytes:
        """
        Encode a single attribute in TLV format.

        Args:
            attr_type: Attribute type code
            value: Attribute value
            dictionary: Optional dictionary for type information

        Returns:
            Encoded attribute bytes
        """
        # Determine attribute type and encode value
        if dictionary:
            attr_def = dictionary.by_code(attr_type)
            if attr_def:
                value_bytes = self._encode_typed_value(value, attr_def.type)
            else:
                value_bytes = self._encode_generic_value(value)
        else:
            value_bytes = self._encode_generic_value(value)

        # Check maximum attribute length (255 - 2 for type and length)
        if len(value_bytes) > 253:
            raise ValueError(f"Attribute value too long: {len(value_bytes)} bytes (max 253)")

        # Encode as Type-Length-Value
        return struct.pack("!BB", attr_type, len(value_bytes) + 2) + value_bytes

    def _encode_typed_value(self, value: Any, attr_type: str) -> bytes:
        """Encode value based on dictionary type information."""
        if attr_type == "string":
            if isinstance(value, str):
                return value.encode('utf-8')
            elif isinstance(value, bytes):
                return value
            else:
                return str(value).encode('utf-8')

        elif attr_type == "integer":
            if isinstance(value, int):
                return struct.pack("!I", value)
            else:
                return struct.pack("!I", int(value))

        elif attr_type == "ipaddr":
            if isinstance(value, ipaddress.IPv4Address):
                return value.packed
            elif isinstance(value, str):
                return ipaddress.IPv4Address(value).packed
            else:
                return ipaddress.IPv4Address(str(value)).packed

        elif attr_type == "octets":
            if isinstance(value, bytes):
                return value
            elif isinstance(value, str):
                # Try to decode as hex string
                try:
                    return bytes.fromhex(value.replace(':', '').replace('-', ''))
                except ValueError:
                    return value.encode('utf-8')
            else:
                return str(value).encode('utf-8')

        else:
            # Default to string encoding
            return self._encode_generic_value(value)

    def _encode_generic_value(self, value: Any) -> bytes:
        """Encode value without type information."""
        if isinstance(value, bytes):
            return value
        elif isinstance(value, str):
            return value.encode('utf-8')
        elif isinstance(value, int):
            return struct.pack("!I", value)
        elif isinstance(value, ipaddress.IPv4Address):
            return value.packed
        else:
            return str(value).encode('utf-8')

    def _decode_attribute(self, data: bytes, offset: int, dictionary=None) -> Tuple[int, Any, int]:
        """
        Decode a single attribute from packet data.

        Args:
            data: Packet data
            offset: Current offset in data
            dictionary: Optional dictionary for type information

        Returns:
            Tuple of (attr_type, value, new_offset)
        """
        if offset + 2 > len(data):
            raise ValueError("Insufficient data for attribute header")

        attr_type, attr_length = struct.unpack("!BB", data[offset:offset+2])

        if attr_length < 2:
            raise ValueError(f"Invalid attribute length: {attr_length}")

        if offset + attr_length > len(data):
            raise ValueError("Insufficient data for attribute value")

        value_data = data[offset+2:offset+attr_length]

        # Decode value based on dictionary type
        if dictionary:
            attr_def = dictionary.by_code(attr_type)
            if attr_def:
                value = self._decode_typed_value(value_data, attr_def.type)
            else:
                value = value_data  # Keep as bytes for unknown attributes
        else:
            value = self._decode_generic_value(value_data)

        return attr_type, value, offset + attr_length

    def _decode_typed_value(self, data: bytes, attr_type: str) -> Union[str, int, bytes]:
        """Decode value based on dictionary type information."""
        if attr_type == "string":
            try:
                return data.decode('utf-8')
            except UnicodeDecodeError:
                return data

        elif attr_type == "integer":
            if len(data) == 4:
                return struct.unpack("!I", data)[0]
            else:
                return data  # Invalid integer, return as bytes

        elif attr_type == "ipaddr":
            if len(data) == 4:
                return str(ipaddress.IPv4Address(data))
            else:
                return data  # Invalid IP address, return as bytes

        elif attr_type == "octets":
            return data

        else:
            # Try string first, fall back to bytes
            try:
                return data.decode('utf-8')
            except UnicodeDecodeError:
                return data

    def _decode_generic_value(self, data: bytes) -> Union[str, bytes]:
        """Decode value without type information."""
        try:
            return data.decode('utf-8')
        except UnicodeDecodeError:
            return data

    def encrypt_user_password(self, password: str, secret: bytes) -> bytes:
        """
        Encrypt User-Password attribute according to RFC 2865 Section 5.2.

        The User-Password is encrypted using a stream cipher based on MD5.

        Args:
            password: Plaintext password
            secret: Shared secret

        Returns:
            Encrypted password bytes
        """
        if not isinstance(password, str):
            password = str(password)

        # Convert password to bytes and pad to 16-byte boundary
        password_bytes = password.encode('utf-8')
        pad_length = 16 - (len(password_bytes) % 16)
        if pad_length != 16:
            password_bytes += b'\x00' * pad_length

        # Encrypt using MD5-based stream cipher
        encrypted = b''
        prev_block = self.authenticator

        for i in range(0, len(password_bytes), 16):
            # Calculate MD5(secret + prev_block)
            hash_input = secret + prev_block
            md5_hash = hashlib.md5(hash_input).digest()

            # XOR password block with MD5 hash
            password_block = password_bytes[i:i+16]
            encrypted_block = bytes(a ^ b for a, b in zip(password_block, md5_hash))
            encrypted += encrypted_block

            # Use encrypted block as input for next iteration
            prev_block = encrypted_block

        return encrypted

    def decrypt_user_password(self, encrypted_password: bytes, secret: bytes) -> str:
        """
        Decrypt User-Password attribute according to RFC 2865 Section 5.2.

        Args:
            encrypted_password: Encrypted password bytes
            secret: Shared secret

        Returns:
            Decrypted password string
        """
        if len(encrypted_password) % 16 != 0:
            raise ValueError("Encrypted password length must be multiple of 16")

        # Decrypt using MD5-based stream cipher
        decrypted = b''
        prev_block = self.authenticator

        for i in range(0, len(encrypted_password), 16):
            # Calculate MD5(secret + prev_block)
            hash_input = secret + prev_block
            md5_hash = hashlib.md5(hash_input).digest()

            # XOR encrypted block with MD5 hash
            encrypted_block = encrypted_password[i:i+16]
            decrypted_block = bytes(a ^ b for a, b in zip(encrypted_block, md5_hash))
            decrypted += decrypted_block

            # Use encrypted block as input for next iteration
            prev_block = encrypted_block

        # Remove null padding and decode
        return decrypted.rstrip(b'\x00').decode('utf-8')

    def calculate_response_authenticator(self, secret: bytes, request_authenticator: bytes) -> bytes:
        """
        Calculate Response Authenticator according to RFC 2865 Section 3.

        Response Authenticator = MD5(Code + ID + Length + Request Authenticator +
                                    Response Attributes + Secret)

        Args:
            secret: Shared secret
            request_authenticator: Request packet authenticator

        Returns:
            Response authenticator bytes
        """
        # Create temporary packet with request authenticator for calculation
        temp_packet = Packet(self.code, self.identifier, request_authenticator)
        temp_packet.attributes = self.attributes.copy()

        # Encode packet without final authenticator calculation
        packet_data = temp_packet._encode_packet_data(secret, skip_auth_calc=True)

        # Calculate MD5 hash
        hash_input = packet_data + secret
        return hashlib.md5(hash_input).digest()

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
        return self.authenticator == expected

    def _encode_packet_data(self, secret: bytes, dictionary=None, skip_auth_calc: bool = False) -> bytes:
        """
        Encode packet data for transmission.

        Args:
            secret: Shared secret
            dictionary: Optional dictionary for attribute encoding
            skip_auth_calc: Skip authenticator calculation (for internal use)

        Returns:
            Encoded packet bytes
        """
        # Handle User-Password encryption
        encrypted_attributes = []
        for attr_type, value in self.attributes:
            if attr_type == 2 and isinstance(value, str):  # User-Password
                encrypted_value = self.encrypt_user_password(value, secret)
                encrypted_attributes.append((attr_type, encrypted_value))
            else:
                encrypted_attributes.append((attr_type, value))

        # Encode all attributes
        attr_data = b''
        for attr_type, value in encrypted_attributes:
            attr_data += self._encode_attribute(attr_type, value, dictionary)

        # Calculate total packet length
        total_length = self.HEADER_LENGTH + len(attr_data)
        if total_length > self.MAX_PACKET_LENGTH:
            raise ValueError(f"Packet too long: {total_length} bytes (max {self.MAX_PACKET_LENGTH})")

        # Encode packet header
        header = struct.pack("!BBH16s", self.code, self.identifier, total_length, self.authenticator)

        return header + attr_data

    def encode(self, secret: bytes, dictionary=None, request_authenticator: bytes = None) -> bytes:
        """
        Encode packet for transmission.

        Args:
            secret: Shared secret
            dictionary: Optional dictionary for attribute encoding
            request_authenticator: Original request authenticator (for response packets)

        Returns:
            Encoded packet bytes
        """
        if not secret:
            raise ValueError("Shared secret cannot be empty")

        # For response packets, calculate response authenticator
        if self.code in (Code.ACCESS_ACCEPT, Code.ACCESS_REJECT, Code.ACCESS_CHALLENGE,
                        Code.ACCOUNTING_RESPONSE) and request_authenticator is not None:
            self.authenticator = self.calculate_response_authenticator(secret, request_authenticator)

        return self._encode_packet_data(secret, dictionary)

    @classmethod
    def decode(cls, data: bytes, secret: bytes, dictionary=None) -> 'Packet':
        """
        Decode packet from wire format.

        Args:
            data: Raw packet data
            secret: Shared secret
            dictionary: Optional dictionary for attribute decoding

        Returns:
            Decoded Packet object
        """
        if len(data) < cls.HEADER_LENGTH:
            raise ValueError(f"Packet too short: {len(data)} bytes (minimum {cls.HEADER_LENGTH})")

        # Decode packet header
        code, identifier, length, authenticator = struct.unpack("!BBH16s", data[:cls.HEADER_LENGTH])

        if len(data) != length:
            raise ValueError(f"Packet length mismatch: received {len(data)}, expected {length}")

        if length > cls.MAX_PACKET_LENGTH:
            raise ValueError(f"Packet too long: {length} bytes (max {cls.MAX_PACKET_LENGTH})")

        # Create packet object
        packet = cls(Code(code), identifier, authenticator)

        # Decode attributes
        offset = cls.HEADER_LENGTH
        while offset < length:
            attr_type, value, offset = packet._decode_attribute(data, offset, dictionary)
            packet.attributes.append((attr_type, value))

        # Handle User-Password decryption
        decrypted_attributes = []
        for attr_type, value in packet.attributes:
            if attr_type == 2 and isinstance(value, bytes):  # User-Password
                try:
                    decrypted_value = packet.decrypt_user_password(value, secret)
                    decrypted_attributes.append((attr_type, decrypted_value))
                except Exception:
                    # If decryption fails, keep encrypted value
                    decrypted_attributes.append((attr_type, value))
            else:
                decrypted_attributes.append((attr_type, value))

        packet.attributes = decrypted_attributes
        return packet

    def __str__(self) -> str:
        """String representation of packet."""
        attr_strs = []
        for attr_type, value in self.attributes:
            if isinstance(value, bytes):
                value_str = value.hex()
            else:
                value_str = str(value)
            attr_strs.append(f"{attr_type}={value_str}")

        return f"Packet(code={self.code.name}, id={self.identifier}, attrs=[{', '.join(attr_strs)}])"

    def __repr__(self) -> str:
        """Detailed representation of packet."""
        return f"Packet(code={self.code}, identifier={self.identifier}, " \
               f"authenticator={self.authenticator.hex()}, attributes={len(self.attributes)})"
