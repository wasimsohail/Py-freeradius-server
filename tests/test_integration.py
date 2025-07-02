"""
Integration tests for PyFreeRADIUS

This module tests the complete system integration including packet encoding,
dictionary functionality, and server operation.
"""

import asyncio
import pytest

from pyfreeradius.packet import Packet, Code
from pyfreeradius.dictionary import create_standard_dictionary
from pyfreeradius.server.simple_server import SimpleRadiusServer, ServerConfig


class TestSystemIntegration:
    """Test complete system integration."""

    def test_packet_with_enhanced_dictionary(self):
        """Test packet encoding with enhanced dictionary."""
        dictionary = create_standard_dictionary()

        # Create a comprehensive Access-Request packet
        packet = Packet(Code.ACCESS_REQUEST, 42)
        packet.add_attribute(1, "testuser")              # User-Name
        packet.add_attribute(2, "testpassword")          # User-Password
        packet.add_attribute(4, "192.168.1.100")         # NAS-IP-Address
        packet.add_attribute(5, 123)                     # NAS-Port
        packet.add_attribute(32, "test-nas")             # NAS-Identifier
        packet.add_attribute(31, "00-11-22-33-44-55")    # Calling-Station-Id
        packet.add_attribute(61, 15)                     # NAS-Port-Type (Ethernet)

        secret = b"testing123"

        # Encode packet
        data = packet.encode(secret, dictionary)

        # Decode packet
        decoded = Packet.decode(data, secret, dictionary)

        # Verify all attributes preserved
        assert decoded.code == Code.ACCESS_REQUEST
        assert decoded.identifier == 42
        assert decoded.get_attribute(1) == "testuser"
        assert decoded.get_attribute(2) == "testpassword"
        assert decoded.get_attribute(4) == "192.168.1.100"
        assert decoded.get_attribute(5) == 123
        assert decoded.get_attribute(32) == "test-nas"
        assert decoded.get_attribute(31) == "00-11-22-33-44-55"
        assert decoded.get_attribute(61) == 15

    @pytest.mark.asyncio
    async def test_full_authentication_scenario(self):
        """Test complete authentication scenario."""
        # Setup server
        config = ServerConfig()
        config.add_client("192.168.1.100", b"secret123", "test-nas", "cisco")

        server = SimpleRadiusServer(config)
        dictionary = create_standard_dictionary()

        # Create Access-Request with multiple attributes
        request = Packet(Code.ACCESS_REQUEST, 100)
        request.add_attribute(1, "alice")                    # User-Name
        request.add_attribute(2, "validpassword")            # User-Password (8 chars, should pass)
        request.add_attribute(4, "192.168.1.100")            # NAS-IP-Address
        request.add_attribute(5, 1234)                       # NAS-Port
        request.add_attribute(32, "cisco-nas-01")            # NAS-Identifier
        request.add_attribute(31, "00:11:22:33:44:55")       # Calling-Station-Id
        request.add_attribute(30, "192.168.1.200")           # Called-Station-Id
        request.add_attribute(61, 15)                        # NAS-Port-Type (Ethernet)

        # Encode request
        secret = b"secret123"
        request_data = request.encode(secret, dictionary)

        # Process request
        client_address = ("192.168.1.100", 12345)
        response_data = await server.handle_packet(request_data, client_address)

        # Verify response
        assert response_data is not None

        response = Packet.decode(response_data, secret, dictionary)
        assert response.code == Code.ACCESS_ACCEPT
        assert response.identifier == 100

        # Check response attributes
        reply_message = response.get_attribute(18)  # Reply-Message
        assert reply_message is not None and "Welcome alice" in str(reply_message)

        session_timeout = response.get_attribute(27)  # Session-Timeout
        assert session_timeout == 3600

        # Verify server statistics
        stats = server.get_stats()
        assert stats['packets_received'] == 1
        assert stats['packets_sent'] == 1
        assert stats['access_requests'] == 1
        assert stats['access_accepts'] == 1
        assert stats['access_rejects'] == 0
        assert stats['errors'] == 0

    @pytest.mark.asyncio
    async def test_authentication_failure_scenario(self):
        """Test authentication failure scenario."""
        # Setup server
        config = ServerConfig()
        config.add_client("10.0.0.1", b"network_secret", "internal-nas")

        server = SimpleRadiusServer(config)
        dictionary = create_standard_dictionary()

        # Create Access-Request with invalid password
        request = Packet(Code.ACCESS_REQUEST, 200)
        request.add_attribute(1, "bob")                      # User-Name
        request.add_attribute(2, "bad")                      # User-Password (too short)
        request.add_attribute(4, "10.0.0.1")                # NAS-IP-Address
        request.add_attribute(32, "internal-nas")           # NAS-Identifier

        # Encode request
        secret = b"network_secret"
        request_data = request.encode(secret, dictionary)

        # Process request
        client_address = ("10.0.0.1", 54321)
        response_data = await server.handle_packet(request_data, client_address)

        # Verify response
        assert response_data is not None

        response = Packet.decode(response_data, secret, dictionary)
        assert response.code == Code.ACCESS_REJECT
        assert response.identifier == 200

        # Check response attributes
        reply_message = response.get_attribute(18)  # Reply-Message
        assert reply_message is not None and "Invalid credentials" in str(reply_message)

        # Verify server statistics
        stats = server.get_stats()
        assert stats['access_rejects'] == 1
        assert stats['access_accepts'] == 0

    @pytest.mark.asyncio
    async def test_accounting_scenario(self):
        """Test accounting packet handling."""
        # Setup server
        config = ServerConfig()
        server = SimpleRadiusServer(config)
        dictionary = create_standard_dictionary()

        # Create Accounting-Request
        request = Packet(Code.ACCOUNTING_REQUEST, 300)
        request.add_attribute(1, "carol")                    # User-Name
        request.add_attribute(44, "session-12345")          # Acct-Session-Id
        request.add_attribute(40, 1)                        # Acct-Status-Type (Start)
        request.add_attribute(4, "127.0.0.1")               # NAS-IP-Address
        request.add_attribute(42, 0)                        # Acct-Input-Octets
        request.add_attribute(43, 0)                        # Acct-Output-Octets

        # Encode request
        secret = b"testing123"
        request_data = request.encode(secret, dictionary)

        # Process request
        client_address = ("127.0.0.1", 11111)
        response_data = await server.handle_packet(request_data, client_address)

        # Verify response
        assert response_data is not None

        response = Packet.decode(response_data, secret, dictionary)
        assert response.code == Code.ACCOUNTING_RESPONSE
        assert response.identifier == 300

    @pytest.mark.asyncio
    async def test_multiple_clients_scenario(self):
        """Test handling multiple clients with different secrets."""
        # Setup server with multiple clients
        config = ServerConfig()
        config.add_client("192.168.1.10", b"secret1", "nas1", "cisco")
        config.add_client("192.168.1.20", b"secret2", "nas2", "juniper")
        config.add_client("10.0.0.100", b"secret3", "nas3", "mikrotik")

        server = SimpleRadiusServer(config)
        dictionary = create_standard_dictionary()

        # Test requests from different clients
        test_cases = [
            ("192.168.1.10", b"secret1", "user1"),
            ("192.168.1.20", b"secret2", "user2"),
            ("10.0.0.100", b"secret3", "user3"),
        ]

        for i, (client_ip, secret, username) in enumerate(test_cases):
            # Create request
            request = Packet(Code.ACCESS_REQUEST, 400 + i)
            request.add_attribute(1, username)
            request.add_attribute(2, "validpassword123")
            request.add_attribute(4, client_ip)

            # Encode and process
            request_data = request.encode(secret, dictionary)
            client_address = (client_ip, 20000 + i)
            response_data = await server.handle_packet(request_data, client_address)

            # Verify response
            assert response_data is not None

            response = Packet.decode(response_data, secret, dictionary)
            assert response.code == Code.ACCESS_ACCEPT
            assert response.identifier == 400 + i

                         reply_message = response.get_attribute(18)
             assert reply_message is not None and f"Welcome {username}" in str(reply_message)

        # Verify final statistics
        stats = server.get_stats()
        assert stats['packets_received'] == 3
        assert stats['packets_sent'] == 3
        assert stats['access_accepts'] == 3
        assert stats['access_rejects'] == 0
        assert stats['errors'] == 0

    def test_dictionary_comprehensive_coverage(self):
        """Test that the dictionary has comprehensive coverage."""
        dictionary = create_standard_dictionary()

        # Test that we have a good coverage of attribute types
        string_attrs = []
        integer_attrs = []
        ipaddr_attrs = []
        octets_attrs = []

        for attr in dictionary.get_all_attributes():
            if attr.type == "string":
                string_attrs.append(attr.code)
            elif attr.type == "integer":
                integer_attrs.append(attr.code)
            elif attr.type == "ipaddr":
                ipaddr_attrs.append(attr.code)
            elif attr.type == "octets":
                octets_attrs.append(attr.code)

        # Should have good representation of each type
        assert len(string_attrs) >= 10, f"Only {len(string_attrs)} string attributes"
        assert len(integer_attrs) >= 10, f"Only {len(integer_attrs)} integer attributes"
        assert len(ipaddr_attrs) >= 3, f"Only {len(ipaddr_attrs)} ipaddr attributes"
        assert len(octets_attrs) >= 5, f"Only {len(octets_attrs)} octets attributes"

        # Test specific important attributes exist
        important_attrs = {
            1: "User-Name",
            2: "User-Password",
            4: "NAS-IP-Address",
            18: "Reply-Message",
            27: "Session-Timeout",
            40: "Acct-Status-Type",
            44: "Acct-Session-Id",
            79: "EAP-Message",
            80: "Message-Authenticator",
        }

        for code, name in important_attrs.items():
            attr = dictionary.by_code(code)
            assert attr is not None, f"Missing important attribute {code}"
            assert attr.name == name, f"Wrong name for attribute {code}: {attr.name} != {name}"

    def test_packet_size_limits(self):
        """Test packet size handling."""
        dictionary = create_standard_dictionary()

        # Create packet that should be within limits
        packet = Packet(Code.ACCESS_REQUEST, 1)

        # Add many small attributes
        for i in range(50):
            packet.add_attribute(18, f"Message {i}")  # Reply-Message

        secret = b"testing123"

        # Should encode successfully
        data = packet.encode(secret, dictionary)
        assert len(data) < 4096  # Should be under the limit

        # Should decode successfully
        decoded = Packet.decode(data, secret, dictionary)
        assert decoded.code == Code.ACCESS_REQUEST
        assert len(decoded.attributes) == 50

    def test_unicode_handling_integration(self):
        """Test Unicode string handling in full integration."""
        dictionary = create_standard_dictionary()

        # Create packet with Unicode strings
        packet = Packet(Code.ACCESS_REQUEST, 999)
        packet.add_attribute(1, "tëst_üsér")         # User-Name with Unicode
        packet.add_attribute(2, "pässwörd123")       # User-Password with Unicode
        packet.add_attribute(18, "Wëlcömë mëssägë")  # Reply-Message with Unicode
        packet.add_attribute(32, "nås_idëntifiër")   # NAS-Identifier with Unicode

        secret = b"testing123"

        # Encode and decode
        data = packet.encode(secret, dictionary)
        decoded = Packet.decode(data, secret, dictionary)

        # Verify Unicode preserved
        assert decoded.get_attribute(1) == "tëst_üsér"
        assert decoded.get_attribute(2) == "pässwörd123"
        assert decoded.get_attribute(18) == "Wëlcömë mëssägë"
        assert decoded.get_attribute(32) == "nås_idëntifiër"
