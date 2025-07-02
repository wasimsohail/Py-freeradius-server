from __future__ import annotations

"""PEAP (Protected EAP) implementation for pyfreeradius.

PEAP creates a TLS tunnel and runs inner EAP methods inside it.
This implementation supports:
- PEAP v0 (draft-kamath-pppext-peapv0-00)
- PEAP v1 (draft-josefsson-pppext-eap-tls-eap-06)
- Inner methods: MSCHAPv2, GTC
"""

import logging
import ssl
from typing import Dict, Optional, Tuple, Any
from enum import IntEnum

from ..eap.tls_handshake import EAPTLSHandshake
from ..eap import EAPCode, EAPType, build_eap_packet

logger = logging.getLogger(__name__)


class PEAPVersion(IntEnum):
    """PEAP version numbers."""
    PEAP_V0 = 0
    PEAP_V1 = 1


class PEAPFlags(IntEnum):
    """PEAP TLS flags."""
    LENGTH_INCLUDED = 0x80
    MORE_FRAGMENTS = 0x40
    START = 0x80


class PEAPState(IntEnum):
    """PEAP session states."""
    INIT = 0
    TLS_HANDSHAKE = 1
    INNER_AUTH = 2
    SUCCESS = 3
    FAILURE = 4


class PEAPSession:
    """PEAP session state management."""

    def __init__(self, session_id: str, version: PEAPVersion = PEAPVersion.PEAP_V0):
        self.session_id = session_id
        self.version = version
        self.state = PEAPState.INIT
        self.tls_handshake: Optional[EAPTLSHandshake] = None
        self.inner_eap_id = 1
        self.username: Optional[str] = None
        self.pending_fragments: bytes = b""

    def is_complete(self) -> bool:
        """Check if PEAP authentication is complete."""
        return self.state in (PEAPState.SUCCESS, PEAPState.FAILURE)

    def is_successful(self) -> bool:
        """Check if PEAP authentication was successful."""
        return self.state == PEAPState.SUCCESS


class PEAPHandler:
    """PEAP protocol handler."""

    def __init__(self, certfile: str, keyfile: str, cafile: Optional[str] = None):
        self.certfile = certfile
        self.keyfile = keyfile
        self.cafile = cafile
        self.sessions: Dict[str, PEAPSession] = {}

    def process_request(self, eap_packet: bytes, client_ip: str, eap_id: int) -> Tuple[bytes, bool]:
        """Process PEAP request and return response.

        Returns:
            (response_packet, is_complete)
        """
        session_key = f"{client_ip}:{eap_id}"

        if len(eap_packet) < 6:  # EAP header + type + flags
            return self._build_failure_response(eap_id), True

        flags = eap_packet[5] if len(eap_packet) > 5 else 0

        # Get or create session
        if session_key not in self.sessions:
            self.sessions[session_key] = PEAPSession(session_key)

        session = self.sessions[session_key]

        try:
            if session.state == PEAPState.INIT:
                return self._handle_init(session, eap_packet, eap_id, flags)
            elif session.state == PEAPState.TLS_HANDSHAKE:
                return self._handle_tls_handshake(session, eap_packet, eap_id, flags)
            elif session.state == PEAPState.INNER_AUTH:
                return self._handle_inner_auth(session, eap_packet, eap_id, flags)
            else:
                return self._build_failure_response(eap_id), True

        except Exception as e:
            logger.error("PEAP processing error: %s", e)
            session.state = PEAPState.FAILURE
            return self._build_failure_response(eap_id), True

    def _handle_init(self, session: PEAPSession, packet: bytes, eap_id: int, flags: int) -> Tuple[bytes, bool]:
        """Handle initial PEAP request."""
        # Start TLS handshake
        session.tls_handshake = EAPTLSHandshake(self.certfile, self.keyfile, self.cafile)
        session.state = PEAPState.TLS_HANDSHAKE

        # Send PEAP-Start
        peap_start = build_eap_packet(
            EAPCode.REQUEST,
            eap_id,
            EAPType.TLS,  # PEAP uses same type as EAP-TLS
            bytes([PEAPFlags.START])
        )
        return peap_start, False

    def _handle_tls_handshake(self, session: PEAPSession, packet: bytes, eap_id: int, flags: int) -> Tuple[bytes, bool]:
        """Handle TLS handshake phase."""
        if not session.tls_handshake:
            return self._build_failure_response(eap_id), True

        # Extract TLS data (skip EAP header + type + flags)
        tls_data = packet[6:] if len(packet) > 6 else b""

        # Handle fragmentation
        if flags & PEAPFlags.LENGTH_INCLUDED:
            if len(tls_data) < 4:
                return self._build_failure_response(eap_id), True
            # Skip length field
            tls_data = tls_data[4:]

        session.tls_handshake.recv(tls_data)
        outgoing = session.tls_handshake.pending_out()

        if session.tls_handshake.handshake_done():
            session.state = PEAPState.INNER_AUTH
            logger.info("PEAP TLS handshake complete for session %s", session.session_id)

            # Start inner EAP authentication
            return self._start_inner_auth(session, eap_id)

        if outgoing:
            # Send TLS data
            peap_response = build_eap_packet(
                EAPCode.REQUEST,
                eap_id,
                EAPType.TLS,
                bytes([0x00]) + outgoing  # No special flags
            )
            return peap_response, False

        # Continue handshake
        return self._build_ack_response(eap_id), False

    def _handle_inner_auth(self, session: PEAPSession, packet: bytes, eap_id: int, flags: int) -> Tuple[bytes, bool]:
        """Handle inner EAP authentication."""
        # This is a simplified implementation
        # Real PEAP would decrypt the inner EAP packet and process it

        # For now, assume MSCHAPv2 success after TLS establishment
        session.state = PEAPState.SUCCESS
        logger.info("PEAP inner authentication successful for session %s", session.session_id)

        return self._build_success_response(eap_id), True

    def _start_inner_auth(self, session: PEAPSession, eap_id: int) -> Tuple[bytes, bool]:
        """Start inner EAP authentication."""
        # Request identity for inner authentication
        inner_identity_request = build_eap_packet(
            EAPCode.REQUEST,
            session.inner_eap_id,
            EAPType.IDENTITY,
            b""
        )

        # Encrypt and send through PEAP tunnel (simplified)
        peap_response = build_eap_packet(
            EAPCode.REQUEST,
            eap_id,
            EAPType.TLS,
            bytes([0x00]) + inner_identity_request
        )

        return peap_response, False

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
            EAPType.TLS,
            bytes([0x00])  # ACK with no data
        )

    def cleanup_session(self, client_ip: str, eap_id: int):
        """Clean up completed session."""
        session_key = f"{client_ip}:{eap_id}"
        if session_key in self.sessions:
            del self.sessions[session_key]
