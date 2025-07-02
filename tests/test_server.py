"""
Unit tests for RADIUS server functionality

This module tests the server implementation including configuration,
packet handling, authentication, and statistics.
"""

import asyncio
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import time

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from pyfreeradius.server.main import RadiusDatagramProtocol, build_response_packet
from pyfreeradius.server.config import Config
from pyfreeradius.dictionary import Dictionary, AttributeDef, create_standard_dictionary
from pyfreeradius.packet import Packet, Code
from pyfreeradius.server.simple_server import (
    SimpleRadiusServer, ServerConfig, ClientConfig,
    RadiusProtocol, create_simple_server
)


RADCLIENT_PATH = shutil.which("radclient")

pytestmark = pytest.mark.skipif(RADCLIENT_PATH is None, reason="radclient binary not available")


@pytest.fixture(scope="module")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
async def running_server(tmp_path, event_loop):
    # Prepare dictionary with necessary attrs
    dictionary = Dictionary()
    dictionary.add_attribute(AttributeDef("User-Name", 1, "string"))
    dictionary.add_attribute(AttributeDef("User-Password", 2, "string"))
    dictionary.add_attribute(AttributeDef("Reply-Message", 18, "string"))

    # Config: allow 127.0.0.1 with secret testing123, user alice/password
    clients_conf = tmp_path / "clients.conf"
    clients_conf.write_text(
        """
client localhost {
    ipaddr = 127.0.0.1
    secret = testing123
}
""",
        encoding="utf-8",
    )
    users_file = tmp_path / "users"
    users_file.write_text("alice Cleartext-Password := \"password\"\n", encoding="utf-8")

    config = Config.load(clients_conf, users_file)

    # Find free UDP port
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    _, port = sock.getsockname()
    sock.close()

    listen = event_loop.create_datagram_endpoint(
        lambda: RadiusDatagramProtocol(config, dictionary),
        local_addr=("127.0.0.1", port),
    )
    transport, protocol = await listen
    try:
        yield port
    finally:
        transport.close()


def test_radclient_auth(running_server):
    port = running_server
    req = "User-Name = \"alice\"\nUser-Password = \"password\"\n"
    req_path = pathlib.Path("/tmp/radius_request.txt")
    req_path.write_text(req, encoding="utf-8")
    cmd = [RADCLIENT_PATH, f"127.0.0.1:{port}", "auth", "testing123", "-f", str(req_path)]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    # radclient returns exit code 0 on Access-Accept, 1 on Access-Reject
    assert result.returncode == 0, f"radclient failed: {result.stderr}"
    assert "Access-Accept" in result.stdout


class TestServerConfig:
    """Test server configuration."""

    def test_default_config(self):
        """Test default server configuration."""
        config = ServerConfig()

        assert config.bind_address == "0.0.0.0"
        assert config.bind_port == 1812
        assert config.dictionary is not None
        assert len(config.clients) == 1  # Default localhost client
        assert "127.0.0.1" in config.clients

    def test_add_client(self):
        """Test adding clients to configuration."""
        config = ServerConfig()

        config.add_client("192.168.1.100", b"secret123", "nas1", "cisco")

        assert "192.168.1.100" in config.clients
        client = config.get_client("192.168.1.100")
        assert client is not None
        assert client.secret == b"secret123"
        assert client.name == "nas1"
        assert client.nas_type == "cisco"

    def test_get_unknown_client(self):
        """Test getting unknown client returns None."""
        config = ServerConfig()

        client = config.get_client("192.168.1.999")
        assert client is None


class TestClientConfig:
    """Test client configuration."""

    def test_client_config_creation(self):
        """Test creating client configuration."""
        client = ClientConfig(secret=b"test_secret", name="test_client", nas_type="test")

        assert client.secret == b"test_secret"
        assert client.name == "test_client"
        assert client.nas_type == "test"

    def test_client_config_defaults(self):
        """Test client configuration with defaults."""
        client = ClientConfig(secret=b"test_secret")

        assert client.secret == b"test_secret"
        assert client.name == "unknown"
        assert client.nas_type == "other"


class TestSimpleRadiusServer:
    """Test SimpleRadiusServer functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.config = ServerConfig()
        self.server = SimpleRadiusServer(self.config)

    def test_server_initialization(self):
        """Test server initialization."""
        assert self.server.config is self.config
        assert self.server.transport is None
        assert self.server.protocol is None
        assert self.server.stats['packets_received'] == 0
        assert self.server.stats['packets_sent'] == 0

    @pytest.mark.asyncio
    async def test_server_start_stop(self):
        """Test server start and stop."""
        # Mock the event loop and transport creation
        mock_transport = MagicMock()
        mock_protocol = MagicMock()

        with patch('asyncio.get_event_loop') as mock_loop:
            mock_loop.return_value.create_datagram_endpoint = AsyncMock(
                return_value=(mock_transport, mock_protocol)
            )

            await self.server.start()

            assert self.server.transport is mock_transport
            assert self.server.protocol is mock_protocol

            await self.server.stop()

            assert self.server.transport is None
            assert self.server.protocol is None
            mock_transport.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_unknown_client(self):
        """Test handling packet from unknown client."""
        data = b"test_packet_data"
        client_address = ("192.168.1.999", 12345)

        response = await self.server.handle_packet(data, client_address)

        assert response is None
        assert self.server.stats['errors'] == 1

    @pytest.mark.asyncio
    async def test_handle_invalid_packet(self):
        """Test handling invalid packet data."""
        data = b"invalid_packet"
        client_address = ("127.0.0.1", 12345)

        response = await self.server.handle_packet(data, client_address)

        assert response is None
        assert self.server.stats['errors'] == 1

    @pytest.mark.asyncio
    async def test_handle_access_request(self):
        """Test handling valid Access-Request packet."""
        # Create a valid Access-Request packet
        packet = Packet(Code.ACCESS_REQUEST, 123)
        packet.add_attribute(1, "testuser")
        packet.add_attribute(2, "validpassword")  # >= 6 chars for default auth

        secret = b"testing123"
        dictionary = create_standard_dictionary()
        data = packet.encode(secret, dictionary)

        client_address = ("127.0.0.1", 12345)

        response_data = await self.server.handle_packet(data, client_address)

        assert response_data is not None
        assert self.server.stats['packets_received'] == 1
        assert self.server.stats['packets_sent'] == 1
        assert self.server.stats['access_requests'] == 1
        assert self.server.stats['access_accepts'] == 1

        # Decode response
        response = Packet.decode(response_data, secret, dictionary)
        assert response.code == Code.ACCESS_ACCEPT
        assert response.identifier == 123

    @pytest.mark.asyncio
    async def test_handle_access_request_invalid_password(self):
        """Test handling Access-Request with invalid password."""
        # Create packet with short password (< 6 chars)
        packet = Packet(Code.ACCESS_REQUEST, 123)
        packet.add_attribute(1, "testuser")
        packet.add_attribute(2, "bad")  # < 6 chars for default auth

        secret = b"testing123"
        dictionary = create_standard_dictionary()
        data = packet.encode(secret, dictionary)

        client_address = ("127.0.0.1", 12345)

        response_data = await self.server.handle_packet(data, client_address)

        assert response_data is not None
        assert self.server.stats['access_rejects'] == 1

        # Decode response
        response = Packet.decode(response_data, secret, dictionary)
        assert response.code == Code.ACCESS_REJECT

    @pytest.mark.asyncio
    async def test_handle_access_request_missing_username(self):
        """Test handling Access-Request missing username."""
        packet = Packet(Code.ACCESS_REQUEST, 123)
        packet.add_attribute(2, "validpassword")

        secret = b"testing123"
        dictionary = create_standard_dictionary()
        data = packet.encode(secret, dictionary)

        client_address = ("127.0.0.1", 12345)

        response_data = await self.server.handle_packet(data, client_address)

        assert response_data is not None

        # Decode response
        response = Packet.decode(response_data, secret, dictionary)
        assert response.code == Code.ACCESS_REJECT

    @pytest.mark.asyncio
    async def test_handle_accounting_request(self):
        """Test handling Accounting-Request packet."""
        packet = Packet(Code.ACCOUNTING_REQUEST, 123)
        packet.add_attribute(1, "testuser")
        packet.add_attribute(44, "session123")  # Acct-Session-Id

        secret = b"testing123"
        dictionary = create_standard_dictionary()
        data = packet.encode(secret, dictionary)

        client_address = ("127.0.0.1", 12345)

        response_data = await self.server.handle_packet(data, client_address)

        assert response_data is not None

        # Decode response
        response = Packet.decode(response_data, secret, dictionary)
        assert response.code == Code.ACCOUNTING_RESPONSE
        assert response.identifier == 123

    @pytest.mark.asyncio
    async def test_handle_unsupported_packet_type(self):
        """Test handling unsupported packet type."""
        packet = Packet(Code.STATUS_SERVER, 123)

        secret = b"testing123"
        dictionary = create_standard_dictionary()
        data = packet.encode(secret, dictionary)

        client_address = ("127.0.0.1", 12345)

        response_data = await self.server.handle_packet(data, client_address)

        assert response_data is None
        assert self.server.stats['errors'] == 1

    @pytest.mark.asyncio
    async def test_authenticate_user_default(self):
        """Test default authentication logic."""
        # Valid password (>= 6 chars)
        result = await self.server._authenticate_user("testuser", "validpass")
        assert result is True

        # Invalid password (< 6 chars)
        result = await self.server._authenticate_user("testuser", "bad")
        assert result is False

    def test_create_access_accept(self):
        """Test creating Access-Accept response."""
        request = Packet(Code.ACCESS_REQUEST, 123)

        response = self.server._create_access_accept(request, "Welcome!")

        assert response.code == Code.ACCESS_ACCEPT
        assert response.identifier == 123
        assert response.get_attribute(18) == "Welcome!"  # Reply-Message
        assert response.get_attribute(27) == 3600  # Session-Timeout

    def test_create_access_reject(self):
        """Test creating Access-Reject response."""
        request = Packet(Code.ACCESS_REQUEST, 123)

        response = self.server._create_access_reject(request, "Login failed")

        assert response.code == Code.ACCESS_REJECT
        assert response.identifier == 123
        assert response.get_attribute(18) == "Login failed"  # Reply-Message

    def test_get_stats(self):
        """Test getting server statistics."""
        # Simulate some activity
        self.server.stats['packets_received'] = 10
        self.server.stats['packets_sent'] = 8
        self.server.stats['access_accepts'] = 5
        self.server.stats['access_rejects'] = 3

        stats = self.server.get_stats()

        assert stats['packets_received'] == 10
        assert stats['packets_sent'] == 8
        assert stats['access_accepts'] == 5
        assert stats['access_rejects'] == 3
        assert 'uptime_seconds' in stats
        assert 'packets_per_second' in stats


class TestRadiusProtocol:
    """Test RadiusProtocol UDP handler."""

    def setup_method(self):
        """Set up test fixtures."""
        self.server = MagicMock()
        self.protocol = RadiusProtocol(self.server)

    def test_protocol_initialization(self):
        """Test protocol initialization."""
        assert self.protocol.server is self.server
        assert self.protocol.transport is None

    def test_connection_made(self):
        """Test connection_made callback."""
        mock_transport = MagicMock()

        self.protocol.connection_made(mock_transport)

        assert self.protocol.transport is mock_transport

    def test_connection_made_wrong_type(self):
        """Test connection_made with wrong transport type."""
        mock_transport = MagicMock()
        mock_transport.__class__ = object  # Not DatagramTransport

        self.protocol.connection_made(mock_transport)

        # Should not set transport for wrong type
        assert self.protocol.transport is None

    def test_datagram_received(self):
        """Test datagram_received callback."""
        data = b"test_data"
        addr = ("127.0.0.1", 12345)

        with patch('asyncio.create_task') as mock_create_task:
            self.protocol.datagram_received(data, addr)
            mock_create_task.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_datagram(self):
        """Test _handle_datagram method."""
        data = b"test_data"
        addr = ("127.0.0.1", 12345)
        response_data = b"response_data"

        # Mock server and transport
        self.server.handle_packet = AsyncMock(return_value=response_data)
        mock_transport = MagicMock()
        self.protocol.transport = mock_transport

        await self.protocol._handle_datagram(data, addr)

        self.server.handle_packet.assert_called_once_with(data, addr)
        mock_transport.sendto.assert_called_once_with(response_data, addr)

    @pytest.mark.asyncio
    async def test_handle_datagram_no_response(self):
        """Test _handle_datagram with no response."""
        data = b"test_data"
        addr = ("127.0.0.1", 12345)

        # Mock server returning None
        self.server.handle_packet = AsyncMock(return_value=None)
        mock_transport = MagicMock()
        self.protocol.transport = mock_transport

        await self.protocol._handle_datagram(data, addr)

        self.server.handle_packet.assert_called_once_with(data, addr)
        mock_transport.sendto.assert_not_called()

    @pytest.mark.asyncio
    async def test_handle_datagram_exception(self):
        """Test _handle_datagram with exception."""
        data = b"test_data"
        addr = ("127.0.0.1", 12345)

        # Mock server raising exception
        self.server.handle_packet = AsyncMock(side_effect=Exception("Test error"))

        # Should not raise exception
        await self.protocol._handle_datagram(data, addr)

        self.server.logger.error.assert_called_once()

    def test_error_received(self):
        """Test error_received callback."""
        exc = Exception("Test error")

        self.protocol.error_received(exc)

        self.server.logger.error.assert_called_once()

    def test_connection_lost(self):
        """Test connection_lost callback."""
        # Test with exception
        exc = Exception("Connection lost")
        self.protocol.connection_lost(exc)
        self.server.logger.error.assert_called_once()

        # Reset mock
        self.server.logger.reset_mock()

        # Test without exception
        self.protocol.connection_lost(None)
        self.server.logger.debug.assert_called_once()


class TestCreateSimpleServer:
    """Test create_simple_server helper function."""

    @pytest.mark.asyncio
    async def test_create_simple_server_defaults(self):
        """Test creating server with default parameters."""
        with patch.object(SimpleRadiusServer, 'start') as mock_start:
            server = await create_simple_server()

            assert isinstance(server, SimpleRadiusServer)
            assert server.config.bind_address == "0.0.0.0"
            assert server.config.bind_port == 1812
            mock_start.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_simple_server_custom_params(self):
        """Test creating server with custom parameters."""
        clients = {
            "192.168.1.100": b"secret1",
            "10.0.0.1": "secret2"  # Test string conversion
        }

        with patch.object(SimpleRadiusServer, 'start') as mock_start:
            server = await create_simple_server(
                bind_address="192.168.1.1",
                bind_port=1813,
                clients=clients
            )

            assert server.config.bind_address == "192.168.1.1"
            assert server.config.bind_port == 1813

            # Check clients were added
            client1 = server.config.get_client("192.168.1.100")
            assert client1 is not None
            assert client1.secret == b"secret1"

            client2 = server.config.get_client("10.0.0.1")
            assert client2 is not None
            assert client2.secret == b"secret2"  # String converted to bytes

            mock_start.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_simple_server_no_clients(self):
        """Test creating server with None clients."""
        with patch.object(SimpleRadiusServer, 'start') as mock_start:
            server = await create_simple_server(clients=None)

            # Should have default localhost client
            assert len(server.config.clients) == 1
            assert "127.0.0.1" in server.config.clients

            mock_start.assert_called_once()


class TestServerIntegration:
    """Integration tests for server functionality."""

    @pytest.mark.asyncio
    async def test_full_authentication_flow(self):
        """Test complete authentication flow."""
        # Create server configuration
        config = ServerConfig()
        config.add_client("192.168.1.100", b"test_secret", "test_nas")

        server = SimpleRadiusServer(config)

        # Create Access-Request
        request = Packet(Code.ACCESS_REQUEST, 42)
        request.add_attribute(1, "testuser")  # User-Name
        request.add_attribute(2, "validpassword")  # User-Password
        request.add_attribute(4, "192.168.1.100")  # NAS-IP-Address
        request.add_attribute(32, "test_nas")  # NAS-Identifier

        # Encode packet
        dictionary = create_standard_dictionary()
        secret = b"test_secret"
        request_data = request.encode(secret, dictionary)

        # Handle packet
        client_address = ("192.168.1.100", 12345)
        response_data = await server.handle_packet(request_data, client_address)

        # Verify response
        assert response_data is not None

        response = Packet.decode(response_data, secret, dictionary)
        assert response.code == Code.ACCESS_ACCEPT
        assert response.identifier == 42

        # Check response attributes
        reply_message = response.get_attribute(18)  # Reply-Message
        assert "Welcome testuser" in reply_message

        session_timeout = response.get_attribute(27)  # Session-Timeout
        assert session_timeout == 3600

        # Verify statistics
        stats = server.get_stats()
        assert stats['packets_received'] == 1
        assert stats['packets_sent'] == 1
        assert stats['access_requests'] == 1
        assert stats['access_accepts'] == 1
        assert stats['access_rejects'] == 0
        assert stats['errors'] == 0
