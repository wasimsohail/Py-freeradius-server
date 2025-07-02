from __future__ import annotations

"""Async UDP RADIUS server for pyfreeradius (milestone-2).

Usage (from CLI):
$ python3 -m pyfreeradius.server.main --clients raddb/clients.conf --users tests/users.txt -d raddb/dictionary
"""

import argparse
import asyncio
import hashlib
import logging
import pathlib
import sys
import ipaddress
from typing import Optional, Union, List, Tuple

from pyfreeradius.dictionary import Dictionary
from pyfreeradius.packet import Code, Packet

from .config import Config
from .pap import decode_user_password
from .chap import verify_chap_response
from .mschap import extract_ms_chap_attrs, verify_ms_chap, MSCHAPDataMissing

logger = logging.getLogger("pyfreeradius.server")


# ---------------------------------------------------------------------------
# Helper – compute response authenticator
# ---------------------------------------------------------------------------

PacketValue = Union[str, int, bytes, ipaddress.IPv4Address, ipaddress.IPv6Address]

def build_response_packet(
    request: Packet,
    secret: bytes,
    reply_code: Code,
    dictionary: Dictionary,
    attributes: Optional[List[Tuple[int, PacketValue]]] = None,
) -> bytes:
    """Create a response packet bytes sequence."""
    if attributes is None:
        attributes = []
    reply = Packet(reply_code, request.identifier, authenticator=b"\x00" * 16)
    reply.attributes.extend(attributes)  # type: ignore[arg-type]

    # Build attribute bytes first
    attr_bytes = b"".join(reply._encode_attr(code, value, dictionary) for code, value in reply.attributes)
    length = Packet._HEADER_STRUCT.size + len(attr_bytes)
    # Header for hash uses RequestAuth
    pseudo_header = Packet._HEADER_STRUCT.pack(reply_code, request.identifier, length, request.authenticator)
    response_auth = hashlib.md5(pseudo_header + attr_bytes + secret).digest()
    final_header = Packet._HEADER_STRUCT.pack(reply_code, request.identifier, length, response_auth)
    return final_header + attr_bytes


# ---------------------------------------------------------------------------
# Async protocol implementation
# ---------------------------------------------------------------------------

class RadiusDatagramProtocol(asyncio.DatagramProtocol):
    def __init__(self, config: Config, dictionary: Dictionary):
        self.transport: Optional[asyncio.transports.DatagramTransport] = None
        self.config = config
        self.dictionary = dictionary

    # lifecycle
    def connection_made(self, transport: asyncio.BaseTransport) -> None:  # type: ignore[override]
        self.transport = transport  # type: ignore[assignment]
        sockname = transport.get_extra_info("sockname")
        logger.info("Listening on %s", sockname)

    def datagram_received(self, data: bytes, addr):  # type: ignore[override]
        peer_ip, peer_port = addr
        logger.debug("Received %d bytes from %s:%d", len(data), peer_ip, peer_port)
        secret_str = self.config.find_secret_for_ip(peer_ip)
        if secret_str is None:
            logger.warning("No client secret configured for %s – packet ignored", peer_ip)
            return
        secret = secret_str.encode()
        try:
            request = Packet.decode(data, secret=secret, dictionary=self.dictionary)
        except Exception as ex:
            logger.error("Failed to decode packet from %s – %s", peer_ip, ex)
            return
        logger.debug("Decoded packet: %s", request)

        if request.code == Code.ACCESS_REQUEST:
            self.handle_auth_request(request, addr, secret)
        elif request.code == Code.ACCOUNTING_REQUEST:
            self.handle_accounting_request(request, addr, secret)
        else:
            logger.warning("Unhandled packet code %s", request.code)

    # specialized handlers
    def handle_auth_request(self, packet: Packet, addr, secret: bytes) -> None:
        # Determine auth method presence
        user_name = None
        pap_pw_encrypted = None
        chap_attr = None
        # Let's keep vendor-specific raw attributes list for ms-chap parsing
        for code, value in packet.attributes:
            if code == 1:  # User-Name
                user_name = value
            elif code == 2:  # User-Password (PAP)
                pap_pw_encrypted = value
            elif code == 3:  # CHAP-Password
                chap_attr = value

        if isinstance(user_name, bytes):
            try:
                user_name = user_name.decode()
            except UnicodeDecodeError:
                user_name = user_name.hex()

        # Determine which method
        if chap_attr is not None:
            self._handle_chap(packet, user_name, chap_attr, addr, secret)
            return

        try:
            challenge, mschap_response = extract_ms_chap_attrs(packet.attributes)  # type: ignore[arg-type]
            self._handle_ms_chap(packet, user_name, challenge, mschap_response, addr, secret)
            return
        except MSCHAPDataMissing:
            pass  # not MS-CHAP; fall through

        if pap_pw_encrypted is not None:
            self._handle_pap(packet, user_name, pap_pw_encrypted, addr, secret)
            return

        logger.warning("Unsupported authentication method")

    # ---------------- PAP / CHAP / MS-CHAP helpers -----------------

    def _handle_pap(self, packet: Packet, username, encrypted_pw, addr, secret):
        if not isinstance(encrypted_pw, bytes):
            logger.warning("User-Password attribute expected bytes got %r", encrypted_pw)
            return
        try:
            clear_pw = decode_user_password(encrypted_pw, secret, packet.authenticator)
        except Exception as ex:
            logger.error("Could not decode User-Password: %s", ex)
            return
        if self.config.check_user_password(str(username), clear_pw):
            self._send_accept(packet, addr, secret)
        else:
            self._send_reject(packet, addr, secret, "Invalid credentials")

    def _handle_chap(self, packet: Packet, username, chap_attr, addr, secret):
        if not isinstance(chap_attr, bytes) or len(chap_attr) != 17:
            logger.warning("Invalid CHAP-Password length")
            return
        chap_id = chap_attr[0]
        chap_response = chap_attr[1:]

        # For CHAP, password must be looked up first (cleartext)
        # We don't have encrypted password; but we can check if user exists
        password = self.config.users.get(username)
        if not password:
            self._send_reject(packet, addr, secret, "Unknown user")
            return
        if verify_chap_response(chap_id, chap_response, password, packet.authenticator):
            self._send_accept(packet, addr, secret)
        else:
            self._send_reject(packet, addr, secret, "CHAP auth failed")

    def _handle_ms_chap(self, packet: Packet, username, challenge, response, addr, secret):
        password = self.config.users.get(username)
        if not password:
            self._send_reject(packet, addr, secret, "Unknown user")
            return
        if verify_ms_chap(challenge, response, password, username):
            self._send_accept(packet, addr, secret)
        else:
            self._send_reject(packet, addr, secret, "MS-CHAP auth failed")

    # ------------- helper to issue accept/reject -------------

    def _send_accept(self, packet, addr, secret):
        resp_bytes = build_response_packet(packet, secret, Code.ACCESS_ACCEPT, self.dictionary, attributes=[(18, "Access granted")])
        if self.transport:
            self.transport.sendto(resp_bytes, addr)  # type: ignore[arg-type]

    def _send_reject(self, packet, addr, secret, msg):
        resp_bytes = build_response_packet(packet, secret, Code.ACCESS_REJECT, self.dictionary, attributes=[(18, msg)])
        if self.transport:
            self.transport.sendto(resp_bytes, addr)  # type: ignore[arg-type]

    # ------------- accounting -------------

    def handle_accounting_request(self, packet: Packet, addr, secret: bytes):
        logger.info("Accounting request with %d attributes from %s", len(packet.attributes), addr[0])
        resp_bytes = build_response_packet(packet, secret, Code.ACCOUNTING_RESPONSE, self.dictionary)
        if self.transport:
            self.transport.sendto(resp_bytes, addr)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def parse_args(argv=None):
    p = argparse.ArgumentParser("pyfreeradiusd", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument("--host", default="0.0.0.0", help="Bind address")
    p.add_argument("--port", type=int, default=1812, help="UDP port")
    p.add_argument("--dictionary", "-d", default="raddb/dictionary", help="Dictionary file path")
    p.add_argument("--clients", default="raddb/clients.conf", help="clients.conf path")
    p.add_argument("--users", default=None, help="users file path (optional)")
    p.add_argument("-X", action="store_true", help="Verbose debug logging like radiusd -X")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.X else logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    dictionary = Dictionary()
    dictionary.load(pathlib.Path(args.dictionary))

    config = Config.load(args.clients, args.users)

    loop = asyncio.get_event_loop()
    listen = loop.create_datagram_endpoint(
        lambda: RadiusDatagramProtocol(config, dictionary),
        local_addr=(args.host, args.port),
    )
    transport, protocol = loop.run_until_complete(listen)
    logger.info("pyfreeradius server started")
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        logger.info("Server interrupted – shutting down")
    finally:
        transport.close()
        loop.close()


if __name__ == "__main__":
    main()
