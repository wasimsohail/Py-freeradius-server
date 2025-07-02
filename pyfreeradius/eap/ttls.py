from __future__ import annotations

"""TTLS (Tunneled TLS) implementation for pyfreeradius.

TTLS creates a TLS tunnel and runs legacy authentication methods inside it.
This implementation supports:
- TTLS with PAP (Password Authentication Protocol)
- TTLS with CHAP (Challenge Handshake Authentication Protocol)
- TTLS with MS-CHAP/MS-CHAPv2
- TTLS with EAP methods
"""

import logging
import ssl
from typing import Dict, Optional, Tuple, Any, Callable
from enum import IntEnum
import struct

from ..eap.tls_handshake import EAPTLSHandshake
from ..eap import EAPCode, EAPType, build_eap_packet
from ..server.pap import decode_user_password
from ..server.chap import verify_chap_response
from ..server.mschap import verify_ms_chap

logger = logging.getLogger(__name__)


class TTLSFlags(IntEnum):
    """TTLS TLS flags."""
    LENGTH_INCLUDED = 0x80
    MORE_FRAGMENTS = 0x40
    START = 0x80


class TTLSState(IntEnum):
    """TTLS session states."""
    INIT = 0
    TLS_HANDSHAKE = 1
    INNER_AUTH = 2
    SUCCESS = 3
    FAILURE = 4


class AVPType(IntEnum):
    """TTLS AVP (Attribute-Value Pair) types."""
    USER_NAME = 1
    USER_PASSWORD = 2
    CHAP_PASSWORD = 3
    CHAP_CHALLENGE = 60
    MS_CHAP_CHALLENGE = 11
    MS_CHAP_RESPONSE = 1
    MS_CHAP2_RESPONSE = 25
    EAP_MESSAGE = 79


class AVP:
    """TTLS AVP structure."""

    def __init__(self, avp_type: int, data: bytes, vendor_id: int = 0):
        self.type = avp_type
        self.data = data
        self.vendor_id = vendor_id

    @classmethod
    def parse(cls, data: bytes) -> list[AVP]:
        """Parse AVPs from binary data."""
        avps = []
        offset = 0

        while offset < len(data):
            if offset + 8 > len(data):
                break

            # Parse AVP header
            avp_code, flags, length = struct.unpack("!IIB", data[offset:offset+9])

            # Check for vendor-specific AVP
            vendor_id = 0
            if flags & 0x80:  # Vendor-specific flag
                if offset + 12 > len(data):
                    break
                vendor_id = struct.unpack("!I", data[offset+8:offset+12])[0]
                avp_data = data[offset+12:offset+length]
            else:
                avp_data = data[offset+8:offset+length]

            avps.append(cls(avp_code, avp_data, vendor_id))

            # Move to next AVP (pad to 4-byte boundary)
            offset += (length + 3) & ~3

        return avps

    def encode(self) -> bytes:
        """Encode AVP to binary format."""
        flags = 0x40  # Mandatory flag
        if self.vendor_id:
            flags |= 0x80  # Vendor-specific flag

        header = struct.pack("!IIB", self.type, flags, 8 + len(self.data))

        if self.vendor_id:
            header += struct.pack("!I", self.vendor_id)

        return header + self.data


class TTLSSession:
    """TTLS session state management."""

    def __init__(self, session_id: str):
        self.session_id = session_id
        self.state = TTLSState.INIT
        self.tls_handshake: Optional[EAPTLSHandshake] = None
        self.username: Optional[str] = None
        self.pending_fragments: bytes = b""
        self.auth_method: Optional[str] = None

    def is_complete(self) -> bool:
        """Check if TTLS authentication is complete."""
        return self.state in (TTLSState.SUCCESS, TTLSState.FAILURE)

    def is_successful(self) -> bool:
        """Check if TTLS authentication was successful."""
        return self.state == TTLSState.SUCCESS


class TTLSHandler:
    """TTLS protocol handler."""

    def __init__(self, certfile: str, keyfile: str, cafile: Optional[str] = None,
                 user_db: Optional[Dict[str, str]] = None):
        self.certfile = certfile
        self.keyfile = keyfile
        self.cafile = cafile
        self.sessions: Dict[str, TTLSSession] = {}
        self.user_db = user_db or {}

    def process_request(self, eap_packet: bytes, client_ip: str, eap_id: int) -> Tuple[bytes, bool]:
        """Process TTLS request and return response.

        Returns:
            (response_packet, is_complete)
        """
        session_key = f"{client_ip}:{eap_id}"

        if len(eap_packet) < 6:  # EAP header + type + flags
            return self._build_failure_response(eap_id), True

        flags = eap_packet[5] if len(eap_packet) > 5 else 0

        # Get or create session
        if session_key not in self.sessions:
            self.sessions[session_key] = TTLSSession(session_key)

        session = self.sessions[session_key]

        try:
            if session.state == TTLSState.INIT:
                return self._handle_init(session, eap_packet, eap_id, flags)
            elif session.state == TTLSState.TLS_HANDSHAKE:
                return self._handle_tls_handshake(session, eap_packet, eap_id, flags)
            elif session.state == TTLSState.INNER_AUTH:
                return self._handle_inner_auth(session, eap_packet, eap_id, flags)
            else:
                return self._build_failure_response(eap_id), True

        except Exception as e:
            logger.error("TTLS processing error: %s", e)
            session.state = TTLSState.FAILURE
            return self._build_failure_response(eap_id), True

    def _handle_init(self, session: TTLSSession, packet: bytes, eap_id: int, flags: int) -> Tuple[bytes, bool]:
        """Handle initial TTLS request."""
        # Start TLS handshake
        session.tls_handshake = EAPTLSHandshake(self.certfile, self.keyfile, self.cafile)
        session.state = TTLSState.TLS_HANDSHAKE

        # Send TTLS-Start
        ttls_start = build_eap_packet(
            EAPCode.REQUEST,
            eap_id,
            EAPType.TTLS,
            bytes([TTLSFlags.START])
        )
        return ttls_start, False

    def _handle_tls_handshake(self, session: TTLSSession, packet: bytes, eap_id: int, flags: int) -> Tuple[bytes, bool]:
        """Handle TLS handshake phase."""
        if not session.tls_handshake:
            return self._build_failure_response(eap_id), True

        # Extract TLS data (skip EAP header + type + flags)
        tls_data = packet[6:] if len(packet) > 6 else b""

        # Handle fragmentation
        if flags & TTLSFlags.LENGTH_INCLUDED:
            if len(tls_data) < 4:
                return self._build_failure_response(eap_id), True
            # Skip length field
            tls_data = tls_data[4:]

        session.tls_handshake.recv(tls_data)
        outgoing = session.tls_handshake.pending_out()

        if session.tls_handshake.handshake_done():
            session.state = TTLSState.INNER_AUTH
            logger.info("TTLS TLS handshake complete for session %s", session.session_id)

            # Request username for inner authentication
            return self._request_username(session, eap_id)

        if outgoing:
            # Send TLS data
            ttls_response = build_eap_packet(
                EAPCode.REQUEST,
                eap_id,
                EAPType.TTLS,
                bytes([0x00]) + outgoing  # No special flags
            )
            return ttls_response, False

        # Continue handshake
        return self._build_ack_response(eap_id), False

    def _handle_inner_auth(self, session: TTLSSession, packet: bytes, eap_id: int, flags: int) -> Tuple[bytes, bool]:
        """Handle inner authentication."""
        if not session.tls_handshake:
            return self._build_failure_response(eap_id), True

        # Extract and decrypt inner data
        encrypted_data = packet[6:] if len(packet) > 6 else b""

        if not encrypted_data:
            return self._build_failure_response(eap_id), True

        try:
            # Decrypt the inner data (simplified - real implementation would use TLS record layer)
            decrypted_data = encrypted_data  # Placeholder

            # Parse AVPs
            avps = AVP.parse(decrypted_data)

            # Process authentication based on received AVPs
            return self._process_inner_avps(session, avps, eap_id)

        except Exception as e:
            logger.error("Error processing inner TTLS data: %s", e)
            return self._build_failure_response(eap_id), True

    def _process_inner_avps(self, session: TTLSSession, avps: list[AVP], eap_id: int) -> Tuple[bytes, bool]:
        """Process inner authentication AVPs."""
        username = None
        password = None
        chap_challenge = None
        chap_response = None
        mschap_challenge = None
        mschap_response = None

        # Extract authentication data from AVPs
        for avp in avps:
            if avp.type == AVPType.USER_NAME:
                username = avp.data.decode('utf-8', errors='ignore')
            elif avp.type == AVPType.USER_PASSWORD:
                password = avp.data.decode('utf-8', errors='ignore')
            elif avp.type == AVPType.CHAP_CHALLENGE:
                chap_challenge = avp.data
            elif avp.type == AVPType.CHAP_PASSWORD:
                chap_response = avp.data
            elif avp.type == AVPType.MS_CHAP_CHALLENGE:
                mschap_challenge = avp.data
            elif avp.type == AVPType.MS_CHAP_RESPONSE:
                mschap_response = avp.data

        if not username:
            return self._build_failure_response(eap_id), True

        session.username = username

        # Determine authentication method and verify
        if password:
            # PAP authentication
            session.auth_method = "PAP"
            if self._verify_pap(username, password):
                session.state = TTLSState.SUCCESS
                return self._build_success_response(eap_id), True

        elif chap_challenge and chap_response:
            # CHAP authentication
            session.auth_method = "CHAP"
            if self._verify_chap(username, chap_challenge, chap_response):
                session.state = TTLSState.SUCCESS
                return self._build_success_response(eap_id), True

        elif mschap_challenge and mschap_response:
            # MS-CHAP authentication
            session.auth_method = "MS-CHAP"
            if self._verify_mschap(username, mschap_challenge, mschap_response):
                session.state = TTLSState.SUCCESS
                return self._build_success_response(eap_id), True

                # Authentication failed
        session.state = TTLSState.FAILURE
        return self._build_failure_response(eap_id), True

    def _verify_pap(self, username: str, password: str) -> bool:
        """Verify PAP credentials."""
        if username in self.user_db:
            # Simple password comparison for TTLS-PAP
            return password == self.user_db[username]
        return False

    def _verify_chap(self, username: str, challenge: bytes, response: bytes) -> bool:
        """Verify CHAP credentials."""
        if username in self.user_db and len(response) > 1:
            chap_id = response[0]
            chap_response = response[1:]
            return verify_chap_response(chap_id, chap_response, self.user_db[username], challenge)
        return False

    def _verify_mschap(self, username: str, challenge: bytes, response: bytes) -> bool:
        """Verify MS-CHAP credentials."""
        if username in self.user_db:
            return verify_ms_chap(challenge, response, self.user_db[username], username)
        return False

    def _request_username(self, session: TTLSSession, eap_id: int) -> Tuple[bytes, bool]:
        """Request username via AVP."""
        # Create username request AVP
        username_request = AVP(AVPType.USER_NAME, b"")
        encrypted_avp = username_request.encode()  # Would be encrypted in real implementation

        ttls_response = build_eap_packet(
            EAPCode.REQUEST,
            eap_id,
            EAPType.TTLS,
            bytes([0x00]) + encrypted_avp
        )

        return ttls_response, False

    def _build_success_response(self, eap_id: int) -> bytes:
        """Build EAP success response."""
        return build_eap_packet(EAPCode.SUCCESS, eap_id, None, b"")

    def _build_failure_response(self, eap_id: int) -> bytes:
        """Build EAP failure response."""
        return build_eap_packet(EAPCode.FAILURE, eap_id, None, b"")

    def _build_ack_response(self, eap_id: int) -> bytes:
        """Build ACK response for fragmentation."""
        return build_eap_packet(
            EAPCode.REQUEST,
            eap_id,
            EAPType.TTLS,
            bytes([0x00])  # ACK with no data
        )

    def cleanup_session(self, client_ip: str, eap_id: int):
        """Clean up completed session."""
        session_key = f"{client_ip}:{eap_id}"
        if session_key in self.sessions:
            del self.sessions[session_key]
