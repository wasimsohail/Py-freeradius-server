import pytest
from unittest.mock import Mock, patch, MagicMock

from pyfreeradius.server.ldap import (
    LDAPConfig, LDAPAuthenticator, LDAPServerType, LDAPAuthMethod,
    LDAPUser, create_active_directory_config, create_openldap_config
)


class TestLDAPConfig:
    """Test LDAP configuration."""

    def test_default_config(self):
        """Test default configuration values."""
        config = LDAPConfig()
        assert config.server == "localhost"
        assert config.port == 389
        assert config.use_ssl is False
        assert config.use_tls is False
        assert config.server_type == LDAPServerType.GENERIC
        assert config.base_dn == "dc=example,dc=com"
        assert config.username_attribute == "uid"

    def test_custom_config(self):
        """Test custom configuration."""
        config = LDAPConfig(
            server="ldap.example.com",
            port=636,
            use_ssl=True,
            server_type=LDAPServerType.ACTIVE_DIRECTORY,
            base_dn="dc=company,dc=com",
            bind_dn="cn=admin,dc=company,dc=com",
            bind_password="secret",
            username_attribute="sAMAccountName"
        )
        assert config.server == "ldap.example.com"
        assert config.port == 636
        assert config.use_ssl is True
        assert config.server_type == LDAPServerType.ACTIVE_DIRECTORY
        assert config.base_dn == "dc=company,dc=com"
        assert config.bind_dn == "cn=admin,dc=company,dc=com"
        assert config.username_attribute == "sAMAccountName"


class TestLDAPUser:
    """Test LDAP user data structure."""

    def test_user_creation(self):
        """Test creating LDAP user."""
        user = LDAPUser(
            dn="uid=testuser,ou=users,dc=example,dc=com",
            username="testuser",
            email="test@example.com",
            fullname="Test User"
        )
        assert user.dn == "uid=testuser,ou=users,dc=example,dc=com"
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.fullname == "Test User"
        assert user.groups == []
        assert user.attributes == {}

    def test_user_with_groups(self):
        """Test user with groups."""
        user = LDAPUser(
            dn="uid=testuser,ou=users,dc=example,dc=com",
            username="testuser",
            groups=["admin", "users"]
        )
        assert user.groups == ["admin", "users"]


@pytest.mark.skipif(True, reason="Requires ldap3 library")
class TestLDAPAuthenticator:
    """Test LDAP authenticator (requires ldap3)."""

    def setup_method(self):
        """Set up test configuration."""
        self.config = LDAPConfig(
            server="ldap.example.com",
            base_dn="dc=example,dc=com",
            bind_dn="cn=admin,dc=example,dc=com",
            bind_password="admin_pass"
        )
        self.authenticator = LDAPAuthenticator(self.config)

    def test_authenticate_user_success(self):
        """Test successful user authentication."""
        with patch('ldap3.Server') as mock_server, \
             patch('ldap3.Connection') as mock_connection:

            # Mock successful authentication
            mock_conn = Mock()
            mock_conn.bind.return_value = True
            mock_connection.return_value = mock_conn

            # Mock user DN lookup
            with patch.object(self.authenticator, '_get_user_dn', return_value="uid=testuser,ou=users,dc=example,dc=com"):
                result = self.authenticator.authenticate_user("testuser", "password")
                assert result is True

    def test_authenticate_user_failure(self):
        """Test failed user authentication."""
        with patch('ldap3.Server') as mock_server, \
             patch('ldap3.Connection') as mock_connection:

            # Mock failed authentication
            mock_conn = Mock()
            mock_conn.bind.return_value = False
            mock_conn.result = {"description": "Invalid credentials"}
            mock_connection.return_value = mock_conn

            # Mock user DN lookup
            with patch.object(self.authenticator, '_get_user_dn', return_value="uid=testuser,ou=users,dc=example,dc=com"):
                result = self.authenticator.authenticate_user("testuser", "wrong_password")
                assert result is False

    def test_authenticate_user_not_found(self):
        """Test authentication with non-existent user."""
        with patch.object(self.authenticator, '_get_user_dn', return_value=None):
            result = self.authenticator.authenticate_user("nonexistent", "password")
            assert result is False

    def test_get_user_info_success(self):
        """Test getting user information."""
        with patch.object(self.authenticator, '_get_connection') as mock_get_conn:
            mock_conn = Mock()
            mock_entry = Mock()
            mock_entry.entry_dn = "uid=testuser,ou=users,dc=example,dc=com"
            mock_conn.entries = [mock_entry]
            mock_get_conn.return_value = mock_conn

            # Mock attribute extraction
            with patch.object(self.authenticator, '_get_attribute_value') as mock_get_attr, \
                 patch.object(self.authenticator, '_extract_attributes', return_value={}), \
                 patch.object(self.authenticator, 'get_user_groups', return_value=["users"]):

                mock_get_attr.side_effect = lambda entry, attr: {
                    "uid": "testuser",
                    "mail": "test@example.com",
                    "cn": "Test User",
                    "telephoneNumber": "+1234567890"
                }.get(attr, "")

                user = self.authenticator.get_user_info("testuser")
                assert user is not None
                assert user.username == "testuser"
                assert user.email == "test@example.com"
                assert user.fullname == "Test User"
                assert user.phone == "+1234567890"
                assert user.groups == ["users"]

    def test_get_user_info_not_found(self):
        """Test getting info for non-existent user."""
        with patch.object(self.authenticator, '_get_connection') as mock_get_conn:
            mock_conn = Mock()
            mock_conn.entries = []
            mock_get_conn.return_value = mock_conn

            user = self.authenticator.get_user_info("nonexistent")
            assert user is None

    def test_get_user_groups(self):
        """Test getting user groups."""
        with patch.object(self.authenticator, '_get_connection') as mock_get_conn:
            mock_conn = Mock()

            # Mock group entries
            mock_entry1 = Mock()
            mock_entry2 = Mock()
            mock_conn.entries = [mock_entry1, mock_entry2]
            mock_get_conn.return_value = mock_conn

            with patch.object(self.authenticator, '_get_attribute_value') as mock_get_attr:
                mock_get_attr.side_effect = ["admin", "users"]

                groups = self.authenticator.get_user_groups("uid=testuser,ou=users,dc=example,dc=com")
                assert groups == ["admin", "users"]

    def test_test_connection_success(self):
        """Test connection test success."""
        with patch.object(self.authenticator, '_get_connection') as mock_get_conn:
            mock_conn = Mock()
            mock_conn.bound = True
            mock_get_conn.return_value = mock_conn

            result = self.authenticator.test_connection()
            assert result is True

    def test_test_connection_failure(self):
        """Test connection test failure."""
        with patch.object(self.authenticator, '_get_connection', return_value=None):
            result = self.authenticator.test_connection()
            assert result is False


class TestLDAPConfigHelpers:
    """Test LDAP configuration helper functions."""

    def test_create_active_directory_config(self):
        """Test Active Directory configuration creation."""
        config = create_active_directory_config(
            server="ad.company.com",
            domain="company.com",
            bind_user="admin",
            bind_password="secret",
            use_ssl=True
        )

        assert config.server == "ad.company.com"
        assert config.port == 636
        assert config.use_ssl is True
        assert config.server_type == LDAPServerType.ACTIVE_DIRECTORY
        assert config.base_dn == "dc=company,dc=com"
        assert config.bind_dn == "admin@company.com"
        assert config.bind_password == "secret"
        assert config.user_search_filter == "(sAMAccountName=%s)"
        assert config.username_attribute == "sAMAccountName"

    def test_create_openldap_config(self):
        """Test OpenLDAP configuration creation."""
        config = create_openldap_config(
            server="ldap.company.com",
            base_dn="dc=company,dc=com",
            bind_dn="cn=admin,dc=company,dc=com",
            bind_password="secret",
            use_tls=True
        )

        assert config.server == "ldap.company.com"
        assert config.port == 389
        assert config.use_tls is True
        assert config.server_type == LDAPServerType.OPENLDAP
        assert config.base_dn == "dc=company,dc=com"
        assert config.bind_dn == "cn=admin,dc=company,dc=com"
        assert config.bind_password == "secret"
        assert config.user_search_filter == "(uid=%s)"
        assert config.username_attribute == "uid"
        assert config.user_search_base == "ou=users,dc=company,dc=com"
        assert config.group_search_base == "ou=groups,dc=company,dc=com"


class TestLDAPAttributeExtraction:
    """Test LDAP attribute extraction methods."""

    def test_get_attribute_value_single(self):
        """Test getting single attribute value."""
        config = LDAPConfig()
        authenticator = LDAPAuthenticator(config)

        # Mock LDAP entry
        mock_entry = Mock()
        mock_attr = Mock()
        mock_attr.value = "test_value"
        setattr(mock_entry, "test_attr", mock_attr)

        value = authenticator._get_attribute_value(mock_entry, "test_attr")
        assert value == "test_value"

    def test_get_attribute_value_list(self):
        """Test getting attribute value from list."""
        config = LDAPConfig()
        authenticator = LDAPAuthenticator(config)

        # Mock LDAP entry with list value
        mock_entry = Mock()
        mock_attr = Mock()
        mock_attr.value = ["first_value", "second_value"]
        setattr(mock_entry, "test_attr", mock_attr)

        value = authenticator._get_attribute_value(mock_entry, "test_attr")
        assert value == "first_value"

    def test_get_attribute_value_missing(self):
        """Test getting missing attribute value."""
        config = LDAPConfig()
        authenticator = LDAPAuthenticator(config)

        mock_entry = Mock()
        # Mock hasattr to return False for missing attribute
        with patch('builtins.hasattr', return_value=False):
            value = authenticator._get_attribute_value(mock_entry, "missing_attr")
            assert value == ""

    def test_extract_attributes(self):
        """Test extracting all attributes."""
        config = LDAPConfig()
        authenticator = LDAPAuthenticator(config)

        # Mock LDAP entry
        mock_entry = Mock()
        mock_entry.entry_attributes = ["attr1", "attr2"]

        # Mock attributes
        mock_attr1 = Mock()
        mock_attr1.value = "value1"
        mock_attr2 = Mock()
        mock_attr2.value = ["value2a", "value2b"]

        setattr(mock_entry, "attr1", mock_attr1)
        setattr(mock_entry, "attr2", mock_attr2)

        attributes = authenticator._extract_attributes(mock_entry)
        assert attributes == {
            "attr1": ["value1"],
            "attr2": ["value2a", "value2b"]
        }
