from __future__ import annotations

"""Helpers for CHAP authentication."""

import hashlib


def verify_chap_response(chap_id: int, chap_response: bytes, cleartext_password: str, request_authenticator: bytes) -> bool:
    """Return *True* if *chap_response* matches expectation.

    The expected value is MD5( chap_id + cleartext_password + RequestAuth ).
    """
    if len(chap_response) != 16 or len(request_authenticator) != 16:
        return False
    md5 = hashlib.md5()
    md5.update(bytes([chap_id]))
    md5.update(cleartext_password.encode())
    md5.update(request_authenticator)
    expected = md5.digest()
    return expected == chap_response
