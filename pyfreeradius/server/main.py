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
        else:
            logger.warning("Unhandled packet code %s", request.code)

    # specialized handlers
    def handle_auth_request(self, packet: Packet, addr, secret: bytes) -> None:
        # Extract username and password
        username = None
        encrypted_password = None
        for code, value in packet.attributes:
            if code == 1:  # User-Name
                username = value
            elif code == 2:  # User-Password (encrypted bytes)
                encrypted_password = value
        if username is None or encrypted_password is None:
            logger.warning("Malformed Access-Request missing User-Name or User-Password")
            return
        if isinstance(username, bytes):
            try:
                username = username.decode()
            except UnicodeDecodeError:
                username = username.hex()
        if not isinstance(encrypted_password, bytes):
            logger.warning("User-Password attribute expected bytes got %r", encrypted_password)
            return
        try:
            clear_pw = decode_user_password(encrypted_password, secret, packet.authenticator)
        except Exception as ex:
            logger.error("Could not decode User-Password: %s", ex)
            return
        logger.info("Auth request '%s' password='%s'", username, clear_pw)
        if self.config.check_user_password(str(username), clear_pw):
            # Accept
            msg = "Access granted"
            resp_bytes = build_response_packet(
                packet,
                secret,
                Code.ACCESS_ACCEPT,
                self.dictionary,
                attributes=[(18, msg)],  # Reply-Message
            )
        else:
            # Reject
            msg = "Access denied"
            resp_bytes = build_response_packet(
                packet,
                secret,
                Code.ACCESS_REJECT,
                self.dictionary,
                attributes=[(18, msg)],
            )
        self.transport.sendto(resp_bytes, addr)  # type: ignore[arg-type]


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
