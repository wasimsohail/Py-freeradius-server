import pytest
from pyfreeradius.server.mschap import (
    nt_password_hash,
    verify_ms_chap_v1,
    verify_ms_chap_v2,
    verify_ms_chap,
    extract_ms_chap_attrs,
    MSCHAPDataMissing,
    generate_ms_chap_success
)


class TestMSCHAPCrypto:
    """Test MS-CHAP cryptographic functions."""

    def test_nt_password_hash(self):
        """Test NT password hash generation."""
        # Test with known password
        password = "password"
        nt_hash = nt_password_hash(password)

        # NT hash should be 16 bytes
        assert len(nt_hash) == 16

        # Same password should produce same hash
        assert nt_password_hash(password) == nt_hash

        # Different password should produce different hash
        assert nt_password_hash("different") != nt_hash

    def test_nt_password_hash_unicode(self):
        """Test NT password hash with unicode characters."""
        password = "pässwörd"
        nt_hash = nt_password_hash(password)
        assert len(nt_hash) == 16

    def test_ms_chap_v1_validation(self):
        """Test MS-CHAPv1 response validation."""
        challenge = b'\x01\x02\x03\x04\x05\x06\x07\x08'
        password = "testpass"
        username = "testuser"

        # Create a mock response (50 bytes total)
        ident = 1
        flags = 0
        lm_response = b'\x00' * 24  # LM response (deprecated)
        nt_response = b'\x11' * 24  # NT response

        response = bytes([ident, flags]) + lm_response + nt_response

        # This will fail because we're using mock data, but should not crash
        result = verify_ms_chap_v1(challenge, response, password, username)
        assert isinstance(result, bool)

    def test_ms_chap_v1_invalid_lengths(self):
        """Test MS-CHAPv1 with invalid data lengths."""
        challenge = b'\x01\x02\x03\x04\x05\x06\x07\x08'
        password = "testpass"
        username = "testuser"

        # Too short response
        short_response = b'\x01\x02' + b'\x00' * 10
        assert verify_ms_chap_v1(challenge, short_response, password, username) == False

        # Wrong challenge length
        wrong_challenge = b'\x01\x02\x03\x04'
        valid_response = b'\x01\x02' + b'\x00' * 48
        assert verify_ms_chap_v1(wrong_challenge, valid_response, password, username) == False

    def test_ms_chap_v2_validation(self):
        """Test MS-CHAPv2 response validation."""
        challenge = b'\x01' * 16  # 16-byte challenge for v2
        password = "testpass"
        username = "testuser"

        # Create a mock MS-CHAPv2 response
        peer_challenge = b'\x02' * 16
        reserved = b'\x00' * 8
        nt_response = b'\x03' * 24
        flags = b'\x00\x00'

        response = peer_challenge + reserved + nt_response + flags

        # This will fail because we're using mock data, but should not crash
        result = verify_ms_chap_v2(challenge, response, password, username)
        assert isinstance(result, bool)

    def test_ms_chap_v2_invalid_lengths(self):
        """Test MS-CHAPv2 with invalid data lengths."""
        challenge = b'\x01' * 16
        password = "testpass"
        username = "testuser"

        # Too short response
        short_response = b'\x01' * 20
        assert verify_ms_chap_v2(challenge, short_response, password, username) == False

        # Wrong challenge length
        wrong_challenge = b'\x01' * 8
        valid_response = b'\x01' * 50
        assert verify_ms_chap_v2(wrong_challenge, valid_response, password, username) == False

    def test_verify_ms_chap_auto_detect(self):
        """Test auto-detection of MS-CHAP version."""
        password = "testpass"
        username = "testuser"

        # Test v1 detection (8-byte challenge)
        v1_challenge = b'\x01' * 8
        v1_response = b'\x01' * 50
        result = verify_ms_chap(v1_challenge, v1_response, password, username)
        assert isinstance(result, bool)

        # Test v2 detection (16-byte challenge)
        v2_challenge = b'\x01' * 16
        v2_response = b'\x01' * 50
        result = verify_ms_chap(v2_challenge, v2_response, password, username)
        assert isinstance(result, bool)

    def test_extract_ms_chap_attrs_success(self):
        """Test successful extraction of MS-CHAP attributes."""
        # Create mock VSA with MS-CHAP challenge and response
        challenge_vsa = (
            b'\x00\x00\x01\x37' +  # Vendor ID 311 (Microsoft)
            b'\x0b' +               # Type 11 (MS-CHAP-Challenge)
            b'\x06' +               # Length 6 (2 type+len + 4 challenge data)
            b'\x01\x02\x03\x04'    # Challenge data
        )

        response_vsa = (
            b'\x00\x00\x01\x37' +  # Vendor ID 311 (Microsoft)
            b'\x01' +               # Type 1 (MS-CHAP-Response)
            b'\x06' +               # Length 6 (2 type+len + 4 response data for test)
            b'\x11' * 4             # Response data (shortened for test)
        )

        attributes = [
            (26, challenge_vsa),  # Vendor-Specific
            (26, response_vsa),   # Vendor-Specific
            (1, b"username"),     # User-Name
        ]

        challenge, response = extract_ms_chap_attrs(attributes)
        assert challenge == b'\x01\x02\x03\x04'
        assert response == b'\x11' * 4

    def test_extract_ms_chap_attrs_missing(self):
        """Test extraction when MS-CHAP attributes are missing."""
        # No MS-CHAP attributes
        attributes = [
            (1, b"username"),     # User-Name
            (2, b"password"),     # User-Password
        ]

        with pytest.raises(MSCHAPDataMissing):
            extract_ms_chap_attrs(attributes)

    def test_extract_ms_chap_attrs_malformed(self):
        """Test extraction with malformed VSA data."""
        # Too short VSA
        short_vsa = b'\x00\x00\x01\x37\x0b'  # Missing length and data

        attributes = [
            (26, short_vsa),
        ]

        with pytest.raises(MSCHAPDataMissing):
            extract_ms_chap_attrs(attributes)

    def test_generate_ms_chap_success(self):
        """Test MS-CHAP success message generation."""
        challenge = b'\x01' * 16
        response = b'\x02' * 50
        password = "testpass"
        username = "testuser"

        success_msg = generate_ms_chap_success(challenge, response, password, username)

        # Should return ASCII-encoded success string
        assert isinstance(success_msg, bytes)
        assert success_msg.startswith(b'S=')
        assert len(success_msg) > 10  # Should have meaningful content

    def test_empty_password(self):
        """Test handling of empty passwords."""
        empty_hash = nt_password_hash("")
        assert len(empty_hash) == 16

        # Empty password should produce deterministic hash
        assert nt_password_hash("") == empty_hash
