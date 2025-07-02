from __future__ import annotations

"""Minimal RADIUS packet encode / decode engine.

Implements the essentials needed for milestone-1.  Only RFC 2865 basic types
are supported: *string*, *integer*, *ipaddr*, *octets*.

Usage
-----
>>> from pyfreeradius.packet import Packet, Code
>>> from pyfreeradius.dictionary import Dictionary
>>> d = Dictionary(); d.add_attribute(AttributeDef('User-Name', 1, 'string'))
>>> pkt = Packet(Code.ACCESS_REQUEST, identifier=123)
>>> pkt.add('User-Name', 'alice', dictionary=d)
>>> raw = pkt.encode(secret=b'secret', dictionary=d)
>>> Packet.decode(raw, secret=b'secret', dictionary=d)
<Packet code=1 id=123 attrs={'User-Name': 'alice'}>
"""

import ipaddress
import os
import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Tuple, Union, ClassVar, Optional

from .dictionary import Dictionary, AttributeDef

__all__ = [
    "Code",
    "Packet",
]


class Code(IntEnum):
    ACCESS_REQUEST = 1
    ACCESS_ACCEPT = 2
    ACCESS_REJECT = 3
    ACCOUNTING_REQUEST = 4
    ACCOUNTING_RESPONSE = 5
    # ... not exhaustive for milestone-1


@dataclass
class Packet:
    code: Code
    identifier: int
    authenticator: bytes = field(default_factory=lambda: os.urandom(16))
    attributes: List[Tuple[int, Union[str, int, bytes, ipaddress.IPv4Address, ipaddress.IPv6Address]]] = field(default_factory=list)

    _HEADER_STRUCT: ClassVar[struct.Struct] = struct.Struct("!BBH16s")  # code, id, len, auth

    # ------------------------------------------------------------
    # Attribute helpers
    # ------------------------------------------------------------

    def add(self, name_or_code: Union[str, int], value: Union[str, int, bytes, ipaddress.IPv4Address, ipaddress.IPv6Address], *, dictionary: Dictionary) -> None:
        """Append an attribute (by name or numeric code)."""
        if isinstance(name_or_code, str):
            attr_def = dictionary.by_name(name_or_code)
            if not attr_def:
                raise KeyError(f"Unknown attribute name: {name_or_code}")
        else:
            attr_def = dictionary.by_code(name_or_code)
            if not attr_def:
                raise KeyError(f"Unknown attribute code: {name_or_code}")

        self.attributes.append((attr_def.code, value))

    # ------------------------------------------------------------
    # Encoding / decoding
    # ------------------------------------------------------------

    def encode(self, *, secret: bytes, dictionary: Dictionary) -> bytes:
        """Return raw bytes suitable for sending on the wire."""
        if len(secret) == 0:
            raise ValueError("secret must not be empty")

        attr_bytes = b"".join(self._encode_attr(code, value, dictionary) for code, value in self.attributes)
        length = self._HEADER_STRUCT.size + len(attr_bytes)
        header = self._HEADER_STRUCT.pack(self.code, self.identifier, length, self.authenticator)
        return header + attr_bytes

    @classmethod
    def decode(cls, raw: bytes, *, secret: bytes, dictionary: Dictionary) -> "Packet":
        if len(raw) < cls._HEADER_STRUCT.size:
            raise ValueError("raw data too short to be a RADIUS packet")
        code, identifier, length, authenticator = cls._HEADER_STRUCT.unpack(raw[: cls._HEADER_STRUCT.size])
        if len(raw) != length:
            raise ValueError("RADIUS length mismatch")

        pkt = cls(Code(code), identifier, authenticator)
        offset = cls._HEADER_STRUCT.size
        while offset < length:
            if offset + 2 > length:
                raise ValueError("Malformed attribute (too short for TL)")
            type_code = raw[offset]
            attr_len = raw[offset + 1]
            if attr_len < 2 or offset + attr_len > length:
                raise ValueError("Malformed attribute length")
            value_bytes = raw[offset + 2 : offset + attr_len]
            value = cls._decode_attr(type_code, value_bytes, dictionary)
            pkt.attributes.append((type_code, value))
            offset += attr_len
        return pkt

    # ------------------------------------------------------------
    # Inner helpers
    # ------------------------------------------------------------

    def _encode_attr(self, code: int, value: Union[str, int, bytes, ipaddress.IPv4Address, ipaddress.IPv6Address], dictionary: Dictionary) -> bytes:
        attr_def = dictionary.by_code(code)
        if not attr_def:
            raise KeyError(f"No dictionary entry for attribute code {code}")
        typ = attr_def.type

        if typ == "string":
            if isinstance(value, str):
                value_bytes = value.encode()
            elif isinstance(value, bytes):
                value_bytes = value
            else:
                raise TypeError("string attribute value must be str or bytes")
        elif typ == "integer":
            if not isinstance(value, int):
                raise TypeError("integer attribute value must be int")
            value_bytes = struct.pack("!I", value)
        elif typ == "ipaddr":
            if isinstance(value, str):
                value = ipaddress.ip_address(value)
            if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                value_bytes = value.packed
            else:
                raise TypeError("ipaddr attribute must be IPv4/IPv6 or string")
        elif typ == "octets":
            if isinstance(value, bytes):
                value_bytes = value
            else:
                raise TypeError("octets attribute must be bytes")
        else:
            raise NotImplementedError(f"Encoding for type '{typ}' not implemented in milestone-1")

        # Attribute format: type (1), length (1), value (n)
        if len(value_bytes) > 253:
            raise ValueError("attribute value too long")
        return struct.pack("!BB", code, len(value_bytes) + 2) + value_bytes

    @staticmethod
    def _decode_attr(code: int, value_bytes: bytes, dictionary: Dictionary) -> Union[str, int, bytes, str]:
        attr_def = dictionary.by_code(code)
        if not attr_def:
            return value_bytes  # Unknown attr stays raw bytes
        typ = attr_def.type
        if typ == "string":
            try:
                return value_bytes.decode()
            except UnicodeDecodeError:
                return value_bytes
        elif typ == "integer":
            if len(value_bytes) != 4:
                return value_bytes
            return struct.unpack("!I", value_bytes)[0]
        elif typ == "ipaddr":
            return str(ipaddress.ip_address(value_bytes))
        elif typ == "octets":
            return value_bytes
        return value_bytes  # fallback

    # ------------------------------------------------------------
    # Representation helpers
    # ------------------------------------------------------------

    def __repr__(self) -> str:  # pragma: no cover
        attr_strs = []
        for code, value in self.attributes:
            attr_strs.append(f"{code}: {value!r}")
        attrs = ", ".join(attr_strs)
        return f"<Packet code={self.code} id={self.identifier} attrs={{ {attrs} }}>"
