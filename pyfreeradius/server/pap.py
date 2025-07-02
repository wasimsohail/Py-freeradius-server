from __future__ import annotations

import hashlib
import math


def decode_user_password(encrypted: bytes, secret: bytes, request_authenticator: bytes) -> str:
    """Return the clear-text password from *encrypted* User-Password attribute.

    Implements RFC 2865 §5.2.  Raises *ValueError* for malformed inputs.
    """
    if len(encrypted) % 16 != 0 or len(encrypted) == 0:
        raise ValueError("User-Password must be a multiple of 16 octets")
    if len(request_authenticator) != 16:
        raise ValueError("Request Authenticator must be 16 octets")

    blocks = len(encrypted) // 16
    clear = b""
    last = request_authenticator
    for i in range(blocks):
        hash_ = hashlib.md5(secret + last).digest()
        segment = encrypted[i * 16 : (i + 1) * 16]
        clear += bytes(a ^ b for a, b in zip(segment, hash_))
        last = segment

    # Remove padding zeros per spec
    clear = clear.rstrip(b"\x00")
    return clear.decode(errors="ignore")
