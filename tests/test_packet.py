"""
Unit tests for RADIUS packet handling (RFC 2865)

This module tests the core packet encoding/decoding functionality
to ensure RFC 2865 compliance.
"""

import pytest
from pyfreeradius.packet import Packet, Code
from pyfreeradius.dictionary import Dictionary, AttributeDef, create_standard_dictionary


class TestPacketBasics:
    """Test basic packet functionality."""

    def test_packet_creation(self):
        """Test basic packet creation."""
        packet = Packet(Code.ACCESS_REQUEST, 123)
        assert packet.code == Code.ACCESS_REQUEST
        assert packet.identifier == 123
        assert len(packet.authenticator) == 16
        assert len(packet.attributes) == 0

    def test_packet_attributes(self):
        """Test adding and getting attributes."""
        packet = Packet(Code.ACCESS_REQUEST, 123)
        packet.add_attribute(1, "testuser")
        packet.add_attribute(2, "testpass")

        assert len(packet.attributes) == 2
        assert packet.get_attribute(1) == "testuser"
        assert packet.get_attribute(2) == "testpass"
        assert packet.get_attribute(99) is None


class TestPacketEncoding:
    """Test packet encoding/decoding."""

    def test_encode_decode_roundtrip(self):
        """Test that encoding then decoding preserves data."""
        # Create original packet
        original = Packet(Code.ACCESS_REQUEST, 123)
        original.add_attribute(1, "testuser")
        original.add_attribute(2, "testpass")

        secret = b"testing123"

        # Encode then decode
        data = original.encode(secret)
        decoded = Packet.decode(data, secret)

        # Verify everything matches
        assert decoded.code == original.code
        assert decoded.identifier == original.identifier
        assert decoded.get_attribute(1) == "testuser"
        assert decoded.get_attribute(2) == "testpass"

    def test_encode_with_dictionary(self):
        """Test encoding with dictionary."""
        dictionary = create_standard_dictionary()

        packet = Packet(Code.ACCESS_REQUEST, 123)
        packet.add_attribute(1, "testuser")  # User-Name
        packet.add_attribute(4, "192.168.1.1")  # NAS-IP-Address

        secret = b"testing123"
        data = packet.encode(secret, dictionary)

        # Should encode successfully
        assert len(data) > 20
        assert data[0] == 1  # ACCESS_REQUEST


class TestUserPasswordEncryption:
    """Test User-Password encryption/decryption."""

    def test_password_encryption(self):
        """Test password encryption and decryption."""
        packet = Packet(Code.ACCESS_REQUEST, 123)
        secret = b"testing123"
        password = "mypassword"

        # Encrypt password
        encrypted = packet.encrypt_user_password(password, secret)

        # Should be padded to 16-byte boundary
        assert len(encrypted) == 16
        assert encrypted != password.encode('utf-8')

        # Decrypt password
        decrypted = packet.decrypt_user_password(encrypted, secret)
        assert decrypted == password


class TestResponseAuthenticator:
    """Test Response Authenticator calculation."""

    def test_response_authenticator(self):
        """Test calculating response authenticator."""
        secret = b"testing123"
        request_auth = b'1234567890123456'

        # Create response packet
        response = Packet(Code.ACCESS_ACCEPT, 123)
        response.add_attribute(18, "Welcome")  # Reply-Message

        # Calculate response authenticator
        resp_auth = response.calculate_response_authenticator(secret, request_auth)

        assert len(resp_auth) == 16
        assert resp_auth != request_auth

        # Verify authenticator
        response.authenticator = resp_auth
        assert response.verify_response_authenticator(secret, request_auth) is True


class TestPacketErrors:
    """Test error conditions."""

    def test_invalid_packet_data(self):
        """Test decoding invalid packet data."""
        secret = b"testing123"

        # Too short
        with pytest.raises(ValueError, match="Packet too short"):
            Packet.decode(b"short", secret)

    def test_empty_secret(self):
        """Test encoding with empty secret."""
        packet = Packet(Code.ACCESS_REQUEST, 123)

        with pytest.raises(ValueError, match="Shared secret cannot be empty"):
            packet.encode(b"")

    def test_invalid_authenticator(self):
        """Test packet with invalid authenticator length."""
        with pytest.raises(ValueError, match="Authenticator must be exactly 16 bytes"):
            Packet(Code.ACCESS_REQUEST, 123, b'short')
