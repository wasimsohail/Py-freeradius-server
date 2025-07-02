#!/usr/bin/env python3

"""
Simple RADIUS Server Implementation

This module provides a basic async UDP server for handling RADIUS packets.
It demonstrates the core server functionality needed for RADIUS authentication.

Key features:
- Async UDP packet handling
- Client configuration management
- Basic authentication flow
- Request/Response packet processing
- Configurable server settings
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple, Any

from ..packet import Packet, Code
from ..dictionary import Dictionary, create_standard_dictionary

__all__ = ["ServerConfig", "SimpleRadiusServer"]

logger = logging.getLogger(__name__)


@dataclass
class ClientConfig:
    """Configuration for a RADIUS client."""
    secret: bytes
    name: str = "unknown"
    nas_type: str = "other"


@dataclass
class ServerConfig:
    """Configuration for the RADIUS server."""
    bind_address: str = "0.0.0.0"
    bind_port: int = 1812
    clients: Dict[str, ClientConfig] = field(default_factory=dict)
    dictionary: Optional[Dictionary] = None

    def __post_init__(self):
        """Initialize default values after creation."""
        if self.dictionary is None:
            self.dictionary = create_standard_dictionary()

        # Add default localhost client if no clients configured
        if not self.clients:
            self.clients["127.0.0.1"] = ClientConfig(
                secret=b"testing123",
                name="localhost",
                nas_type="test"
            )

    def add_client(self, ip_address: str, secret: bytes, name: str = "unknown",
                   nas_type: str = "other") -> None:
        """Add a client configuration."""
        self.clients[ip_address] = ClientConfig(secret, name, nas_type)

    def get_client(self, ip_address: str) -> Optional[ClientConfig]:
        """Get client configuration by IP address."""
        return self.clients.get(ip_address)


class SimpleRadiusServer:
    """
    Simple RADIUS server implementation.

    Provides basic RADIUS packet handling with async UDP networking.
    Suitable for testing and simple authentication scenarios.
    """

    def __init__(self, config: ServerConfig):
        """
        Initialize the server.

        Args:
            config: Server configuration
        """
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.SimpleRadiusServer")
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.protocol: Optional['RadiusProtocol'] = None
        self.stats = {
            'packets_received': 0,
            'packets_sent': 0,
            'access_requests': 0,
            'access_accepts': 0,
            'access_rejects': 0,
            'errors': 0,
            'start_time': time.time()
        }

    async def start(self) -> None:
        """Start the RADIUS server."""
        loop = asyncio.get_event_loop()

        self.logger.info(f"Starting RADIUS server on {self.config.bind_address}:{self.config.bind_port}")

        # Create UDP endpoint
        self.transport, self.protocol = await loop.create_datagram_endpoint(
            lambda: RadiusProtocol(self),
            local_addr=(self.config.bind_address, self.config.bind_port)
        )

        self.logger.info("RADIUS server started successfully")

    async def stop(self) -> None:
        """Stop the RADIUS server."""
        if self.transport:
            self.transport.close()
            self.transport = None
            self.protocol = None

        self.logger.info("RADIUS server stopped")

    async def handle_packet(self, data: bytes, client_address: Tuple[str, int]) -> Optional[bytes]:
        """
        Handle an incoming RADIUS packet.

        Args:
            data: Raw packet data
            client_address: Client IP and port

        Returns:
            Response packet data or None
        """
        client_ip = client_address[0]
        self.stats['packets_received'] += 1

        try:
            # Get client configuration
            client_config = self.config.get_client(client_ip)
            if not client_config:
                self.logger.warning(f"Unknown client: {client_ip}")
                self.stats['errors'] += 1
                return None

            # Decode packet
            try:
                packet = Packet.decode(data, client_config.secret, self.config.dictionary)
            except Exception as e:
                self.logger.error(f"Failed to decode packet from {client_ip}: {e}")
                self.stats['errors'] += 1
                return None

            self.logger.debug(f"Received {packet.code.name} from {client_ip} (ID: {packet.identifier})")

            # Handle different packet types
            if packet.code == Code.ACCESS_REQUEST:
                response = await self._handle_access_request(packet, client_config)
                self.stats['access_requests'] += 1
            elif packet.code == Code.ACCOUNTING_REQUEST:
                response = await self._handle_accounting_request(packet, client_config)
            else:
                self.logger.warning(f"Unsupported packet type: {packet.code}")
                self.stats['errors'] += 1
                return None

            # Encode response
            if response:
                response_data = response.encode(
                    client_config.secret,
                    self.config.dictionary,
                    packet.authenticator
                )
                self.stats['packets_sent'] += 1

                if response.code == Code.ACCESS_ACCEPT:
                    self.stats['access_accepts'] += 1
                elif response.code == Code.ACCESS_REJECT:
                    self.stats['access_rejects'] += 1

                self.logger.debug(f"Sending {response.code.name} to {client_ip} (ID: {response.identifier})")
                return response_data

        except Exception as e:
            self.logger.error(f"Error processing packet from {client_ip}: {e}")
            self.stats['errors'] += 1

        return None

    async def _handle_access_request(self, packet: Packet, client_config: ClientConfig) -> Optional[Packet]:
        """
        Handle an Access-Request packet.

        Args:
            packet: Access-Request packet
            client_config: Client configuration

        Returns:
            Access-Accept or Access-Reject packet
        """
        # Extract authentication attributes
        username = packet.get_attribute(1)  # User-Name
        password = packet.get_attribute(2)  # User-Password

        if username is None:
            self.logger.warning("Access-Request missing User-Name attribute")
            return self._create_access_reject(packet, "Missing username")

        if password is None:
            self.logger.warning(f"Access-Request from {username} missing User-Password attribute")
            return self._create_access_reject(packet, "Missing password")

        # Simple authentication logic (override in subclass for real authentication)
        if await self._authenticate_user(str(username), str(password)):
            self.logger.info(f"Authentication successful for user: {username}")
            return self._create_access_accept(packet, f"Welcome {username}")
        else:
            self.logger.info(f"Authentication failed for user: {username}")
            return self._create_access_reject(packet, "Invalid credentials")

    async def _handle_accounting_request(self, packet: Packet, client_config: ClientConfig) -> Optional[Packet]:
        """
        Handle an Accounting-Request packet.

        Args:
            packet: Accounting-Request packet
            client_config: Client configuration

        Returns:
            Accounting-Response packet
        """
        # Create accounting response
        response = Packet(Code.ACCOUNTING_RESPONSE, packet.identifier)

        self.logger.debug(f"Processed accounting request (ID: {packet.identifier})")
        return response

    async def _authenticate_user(self, username: str, password: str) -> bool:
        """
        Authenticate a user.

        Basic implementation that accepts any user with password length >= 6.
        Override this method for real authentication logic.

        Args:
            username: Username
            password: Password

        Returns:
            True if authentication successful
        """
        # Simple demo authentication - accept if password is at least 6 characters
        return len(password) >= 6

    def _create_access_accept(self, request: Packet, message: str = None) -> Packet:
        """Create an Access-Accept response."""
        response = Packet(Code.ACCESS_ACCEPT, request.identifier)

        if message:
            response.add_attribute(18, message)  # Reply-Message

        # Add some default attributes
        response.add_attribute(27, 3600)  # Session-Timeout (1 hour)

        return response

    def _create_access_reject(self, request: Packet, message: str = None) -> Packet:
        """Create an Access-Reject response."""
        response = Packet(Code.ACCESS_REJECT, request.identifier)

        if message:
            response.add_attribute(18, message)  # Reply-Message

        return response

    def get_stats(self) -> Dict[str, Any]:
        """Get server statistics."""
        uptime = time.time() - self.stats['start_time']
        stats = self.stats.copy()
        stats['uptime_seconds'] = uptime
        stats['packets_per_second'] = stats['packets_received'] / uptime if uptime > 0 else 0
        return stats


class RadiusProtocol(asyncio.DatagramProtocol):
    """UDP protocol handler for RADIUS packets."""

    def __init__(self, server: SimpleRadiusServer):
        """Initialize protocol with server reference."""
        self.server = server
        self.transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """Called when connection is established."""
        if isinstance(transport, asyncio.DatagramTransport):
            self.transport = transport
        self.server.logger.debug("UDP transport established")

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        """Called when a datagram is received."""
        # Handle packet asynchronously
        asyncio.create_task(self._handle_datagram(data, addr))

    async def _handle_datagram(self, data: bytes, addr: Tuple[str, int]) -> None:
        """Handle received datagram."""
        try:
            response_data = await self.server.handle_packet(data, addr)
            if response_data and self.transport:
                self.transport.sendto(response_data, addr)
        except Exception as e:
            self.server.logger.error(f"Error handling datagram from {addr}: {e}")

    def error_received(self, exc: Exception) -> None:
        """Called when an error is received."""
        self.server.logger.error(f"UDP transport error: {exc}")

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """Called when connection is lost."""
        if exc:
            self.server.logger.error(f"UDP connection lost: {exc}")
        else:
            self.server.logger.debug("UDP connection closed")


async def create_simple_server(bind_address: str = "0.0.0.0", bind_port: int = 1812,
                              clients: Optional[Dict[str, bytes]] = None) -> SimpleRadiusServer:
    """
    Create and start a simple RADIUS server.

    Args:
        bind_address: Address to bind to
        bind_port: Port to bind to
        clients: Dictionary of client IP -> secret mappings

    Returns:
        Started SimpleRadiusServer instance
    """
    config = ServerConfig(bind_address=bind_address, bind_port=bind_port)

    # Add clients if provided
    if clients:
        for ip, secret in clients.items():
            if isinstance(secret, str):
                secret = secret.encode('utf-8')
            config.add_client(ip, secret)

    server = SimpleRadiusServer(config)
    await server.start()
    return server


# Example usage
if __name__ == "__main__":
    async def main():
        """Example server startup."""
        logging.basicConfig(level=logging.INFO)

        # Create server with test client
        clients = {
            "127.0.0.1": b"testing123",
            "192.168.1.0/24": b"network_secret"
        }

        server = await create_simple_server(clients=clients)

        try:
            print("RADIUS server running on port 1812")
            print("Press Ctrl+C to stop")

            # Keep server running
            while True:
                await asyncio.sleep(1)

        except KeyboardInterrupt:
            print("\nShutting down server...")
            await server.stop()

    asyncio.run(main())
