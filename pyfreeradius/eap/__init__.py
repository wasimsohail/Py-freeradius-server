from __future__ import annotations

"""pyfreeradius EAP framework – initial skeleton supporting EAP-TLS.

This sub-package provides:
  • Core constants and helper functions (RFC 3748).
  • A minimal in-memory session state machine (`EAPSession`).
  • EAP-TLS engine that wraps Python's `ssl` library with MemoryBIOs so the
    handshake can run over RADIUS/EAP message fragmentation.

Only the pieces strictly necessary to negotiate EAP-TLS up to the point where
`ssl` reports handshake success are implemented.  Client-certificate
validation, crypto-binding and MSK export will follow in later milestones.
"""

from enum import IntEnum

__all__ = [
    "EAPCode",
    "EAPType",
    "build_eap_packet",
]


class EAPCode(IntEnum):
    REQUEST = 1
    RESPONSE = 2
    SUCCESS = 3
    FAILURE = 4


class EAPType(IntEnum):
    IDENTITY = 1
    NOTIFICATION = 2
    NAK = 3
    TLS = 13  # RFC 5216


HEADER_LEN = 4  # Code (1) + Identifier (1) + Length (2)

def build_eap_packet(code: EAPCode, identifier: int, eap_type: int | None, data: bytes = b"") -> bytes:
    """Return a serialized EAP packet."""
    if eap_type is None:
        payload = data
    else:
        payload = bytes([eap_type]) + data
    length = HEADER_LEN + len(payload)
    return bytes([code, identifier]) + length.to_bytes(2, "big") + payload
