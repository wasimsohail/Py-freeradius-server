from __future__ import annotations

import logging
from typing import Dict, Tuple, Any

from pyfreeradius.dictionary import Dictionary
from pyfreeradius.packet import Packet, Code
from pyfreeradius.eap import EAPCode, EAPType, build_eap_packet
from pyfreeradius.eap.tls_handshake import EAPTLSHandshake

logger = logging.getLogger(__name__)

EAP_MESSAGE_ATTR = 79  # RADIUS attribute for carrying EAP packets


class EAPHandler:
    """Keeps EAP sessions keyed by (client_ip, identifier)."""

    def __init__(self, dictionary: Dictionary, certfile: str, keyfile: str, cafile: str | None = None):
        self.dictionary = dictionary
        self.sessions: Dict[Tuple[str, int], EAPTLSHandshake] = {}
        self.certfile = certfile
        self.keyfile = keyfile
        self.cafile = cafile

    # ------------------------------------------------------------------
    def process(self, packet: Packet, addr: Tuple[str, int], secret: bytes) -> Tuple[Code, list[Tuple[int, Any]]]:
        """Process Access-Request containing EAP-Message.

        Returns (response_code, attribute_list) for RADIUS reply.
        """
        eap_parts = [value for code, value in packet.attributes if code == EAP_MESSAGE_ATTR and isinstance(value, bytes)]
        eap_data = b"".join(eap_parts)
        if not eap_data:
            raise ValueError("No EAP-Message present")

        code = eap_data[0]
        identifier = eap_data[1]
        length = int.from_bytes(eap_data[2:4], "big")
        eap_payload = eap_data[4:length]
        key = (addr[0], identifier)

        if code == EAPCode.RESPONSE and eap_payload and eap_payload[0] == EAPType.IDENTITY:
            # Start new TLS session -> send EAP-Request (TLS Start)
            handshake = EAPTLSHandshake(self.certfile, self.keyfile, self.cafile)
            self.sessions[key] = handshake
            start_packet = build_eap_packet(EAPCode.REQUEST, identifier, EAPType.TLS, bytes([0x80]))  # Flags: Start
            return Code.ACCESS_CHALLENGE, [(EAP_MESSAGE_ATTR, start_packet)]

        # Existing session?
        hs = self.sessions.get(key)
        if not hs:
            logger.warning("No handshake found for key %s", key)
            return Code.ACCESS_REJECT, []

        hs.recv(eap_payload)
        outgoing = hs.pending_out()
        if outgoing:
            # Send TLS data inside EAP-Request TLS (Flags = 0)
            eap_req = build_eap_packet(EAPCode.REQUEST, identifier, EAPType.TLS, bytes([0x00]) + outgoing)
            return Code.ACCESS_CHALLENGE, [(EAP_MESSAGE_ATTR, eap_req)]

        if hs.handshake_done():
            logger.info("EAP-TLS handshake complete for %s", key[0])
            return Code.ACCESS_ACCEPT, []

        return Code.ACCESS_REJECT, []
