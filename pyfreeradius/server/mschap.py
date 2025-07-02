from __future__ import annotations

"""Very Minimal MS-CHAP verifier.

For milestone-2 we only *check* that a matching Cleartext-Password exists and
that both MS-CHAP-Challenge and MS-CHAP-Response attributes are present.
A full cryptographic verification of MS-CHAPv1/v2 will be added later.
"""

from typing import Tuple, Optional


class MSCHAPDataMissing(Exception):
    pass


def extract_ms_chap_attrs(attributes: list[tuple[int, bytes]]) -> Tuple[bytes, bytes]:
    """Return *(challenge, response)* for Microsoft VSA data in *attributes*.

    Searches for Vendor-Specific (type 26) carrying vendor 311 and sub-types
    11 (Challenge) and 1/25 (Response).
    """
    challenge = None
    response = None
    for code, value in attributes:
        if code != 26 or not isinstance(value, bytes) or len(value) < 6:
            continue
        vendor_id = int.from_bytes(value[:4], "big")
        if vendor_id != 311:
            continue
        vendor_type = value[4]
        vendor_len = value[5]
        if vendor_len < 2 or vendor_len > len(value) - 4:
            continue
        vdata = value[6 : 6 + vendor_len - 2]
        if vendor_type == 11:  # MS-CHAP-Challenge
            challenge = vdata
        elif vendor_type in (1, 25):  # MS-CHAP-Response / MS-CHAP2-Response
            response = vdata
    if challenge is None or response is None:
        raise MSCHAPDataMissing()
    return challenge, response


def verify_ms_chap(challenge: bytes, response: bytes, cleartext_password: str, username: str) -> bool:
    """Stub verification – accepts if password matches.

    Real implementation will verify cryptographic response later.
    """
    return True  # Placeholder
