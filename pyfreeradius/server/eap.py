from __future__ import annotations

import logging
from typing import Dict, Tuple, Any, Optional

from pyfreeradius.dictionary import Dictionary
from pyfreeradius.packet import Packet, Code
from pyfreeradius.eap import EAPCode, EAPType, build_eap_packet
from pyfreeradius.eap.tls_handshake import EAPTLSHandshake
from pyfreeradius.eap.peap import PEAPHandler
from pyfreeradius.eap.ttls import TTLSHandler

logger = logging.getLogger(__name__)

EAP_MESSAGE_ATTR = 79  # RADIUS attribute for carrying EAP packets


class EAPHandler:
    """EAP method dispatcher supporting TLS, PEAP, and TTLS."""

    def __init__(self, dictionary: Dictionary, certfile: str, keyfile: str, cafile: str | None = None,
                 user_db: Optional[Dict[str, str]] = None):
        self.dictionary = dictionary
        self.tls_sessions: Dict[Tuple[str, int], EAPTLSHandshake] = {}
        self.certfile = certfile
        self.keyfile = keyfile
        self.cafile = cafile
        self.user_db = user_db or {}

        # Initialize EAP method handlers
        self.peap_handler = PEAPHandler(certfile, keyfile, cafile)
        self.ttls_handler = TTLSHandler(certfile, keyfile, cafile, user_db)

    # ------------------------------------------------------------------
    def process(self, packet: Packet, addr: Tuple[str, int], secret: bytes) -> Tuple[Code, list[Tuple[int, Any]]]:
        """Process Access-Request containing EAP-Message.

        Returns (response_code, attribute_list) for RADIUS reply.
        """
        eap_parts = [value for code, value in packet.attributes if code == EAP_MESSAGE_ATTR and isinstance(value, bytes)]
        eap_data = b"".join(eap_parts)
        if not eap_data:
            raise ValueError("No EAP-Message present")

        if len(eap_data) < 4:
            return Code.ACCESS_REJECT, []

        code = eap_data[0]
        identifier = eap_data[1]
        length = int.from_bytes(eap_data[2:4], "big")

        if len(eap_data) < length:
            return Code.ACCESS_REJECT, []

        eap_payload = eap_data[4:length] if length > 4 else b""
        key = (addr[0], identifier)

        if code == EAPCode.RESPONSE and eap_payload and eap_payload[0] == EAPType.IDENTITY:
            # Start with PEAP (most secure tunneled method)
            start_packet = build_eap_packet(EAPCode.REQUEST, identifier, EAPType.PEAP, bytes([0x80]))  # Flags: Start
            return Code.ACCESS_CHALLENGE, [(EAP_MESSAGE_ATTR, start_packet)]

        # Determine EAP method from payload
        if not eap_payload:
            return Code.ACCESS_REJECT, []

        eap_type = eap_payload[0]

        # Handle different EAP methods
        if eap_type == EAPType.TLS:
            return self._handle_eap_tls(eap_data, key, identifier)
        elif eap_type == EAPType.PEAP:
            return self._handle_eap_peap(eap_data, addr, identifier)
        elif eap_type == EAPType.TTLS:
            return self._handle_eap_ttls(eap_data, addr, identifier)
        else:
            logger.warning("Unsupported EAP method: %d", eap_type)
            return Code.ACCESS_REJECT, []

    def _handle_eap_tls(self, eap_data: bytes, key: Tuple[str, int], identifier: int) -> Tuple[Code, list[Tuple[int, Any]]]:
        """Handle EAP-TLS."""
        # Existing TLS session?
        hs = self.tls_sessions.get(key)
        if not hs:
            # Create new TLS session
            hs = EAPTLSHandshake(self.certfile, self.keyfile, self.cafile)
            self.tls_sessions[key] = hs

        # Extract TLS payload (skip EAP header + type + flags)
        tls_payload = eap_data[6:] if len(eap_data) > 6 else b""

        hs.recv(tls_payload)
        outgoing = hs.pending_out()

        if outgoing:
            # Send TLS data inside EAP-Request TLS (Flags = 0)
            eap_req = build_eap_packet(EAPCode.REQUEST, identifier, EAPType.TLS, bytes([0x00]) + outgoing)
            return Code.ACCESS_CHALLENGE, [(EAP_MESSAGE_ATTR, eap_req)]

        if hs.handshake_done():
            logger.info("EAP-TLS handshake complete for %s", key[0])
            # Clean up session
            del self.tls_sessions[key]
            return Code.ACCESS_ACCEPT, []

        return Code.ACCESS_REJECT, []

    def _handle_eap_peap(self, eap_data: bytes, addr: Tuple[str, int], identifier: int) -> Tuple[Code, list[Tuple[int, Any]]]:
        """Handle PEAP."""
        try:
            response, is_complete = self.peap_handler.process_request(eap_data, addr[0], identifier)

            if is_complete:
                self.peap_handler.cleanup_session(addr[0], identifier)
                # Check if successful (simplified check)
                if response[0] == EAPCode.SUCCESS:
                    return Code.ACCESS_ACCEPT, [(EAP_MESSAGE_ATTR, response)]
                else:
                    return Code.ACCESS_REJECT, [(EAP_MESSAGE_ATTR, response)]
            else:
                return Code.ACCESS_CHALLENGE, [(EAP_MESSAGE_ATTR, response)]

        except Exception as e:
            logger.error("PEAP processing error: %s", e)
            return Code.ACCESS_REJECT, []

    def _handle_eap_ttls(self, eap_data: bytes, addr: Tuple[str, int], identifier: int) -> Tuple[Code, list[Tuple[int, Any]]]:
        """Handle TTLS."""
        try:
            response, is_complete = self.ttls_handler.process_request(eap_data, addr[0], identifier)

            if is_complete:
                self.ttls_handler.cleanup_session(addr[0], identifier)
                # Check if successful (simplified check)
                if response[0] == EAPCode.SUCCESS:
                    return Code.ACCESS_ACCEPT, [(EAP_MESSAGE_ATTR, response)]
                else:
                    return Code.ACCESS_REJECT, [(EAP_MESSAGE_ATTR, response)]
            else:
                return Code.ACCESS_CHALLENGE, [(EAP_MESSAGE_ATTR, response)]

        except Exception as e:
            logger.error("TTLS processing error: %s", e)
            return Code.ACCESS_REJECT, []
