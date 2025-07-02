import pytest
import tempfile
import os
from unittest.mock import Mock, patch

from pyfreeradius.server.sql import (
    SQLConfig, SQLAuthenticator, DatabaseType, PasswordType,
    create_sample_database, UserAttribute
)


class TestSQLAuthentication:
    """Test SQL authentication functionality."""

    def setup_method(self):
        """Set up test database."""
        self.db_file = tempfile.mktemp(suffix='.db')
        create_sample_database(self.db_file)

        self.config = SQLConfig(
            db_type=DatabaseType.SQLITE,
            database=self.db_file
        )
        self.authenticator = SQLAuthenticator(self.config)

    def teardown_method(self):
        """Clean up test database."""
        self.authenticator.close()
        if os.path.exists(self.db_file):
            os.unlink(self.db_file)

    def test_authenticate_valid_user(self):
        """Test authentication with valid credentials."""
        result = self.authenticator.authenticate_user("testuser", "testpass")
        assert result is True

    def test_authenticate_invalid_password(self):
        """Test authentication with invalid password."""
        result = self.authenticator.authenticate_user("testuser", "wrongpass")
        assert result is False

    def test_authenticate_nonexistent_user(self):
        """Test authentication with non-existent user."""
        result = self.authenticator.authenticate_user("nonexistent", "password")
        assert result is False

    def test_get_user_check_attributes(self):
        """Test retrieving user check attributes."""
        attrs = self.authenticator.get_user_check_attributes("testuser")
        assert len(attrs) == 1
        assert attrs[0].username == "testuser"
        assert attrs[0].attribute == "Cleartext-Password"
        assert attrs[0].value == "testpass"

    def test_get_user_reply_attributes(self):
        """Test retrieving user reply attributes."""
        attrs = self.authenticator.get_user_reply_attributes("testuser")
        assert len(attrs) == 1
        assert attrs[0].username == "testuser"
        assert attrs[0].attribute == "Reply-Message"
        assert attrs[0].value == "Hello from SQL!"

    def test_password_type_detection(self):
        """Test password type detection."""
        auth = self.authenticator

        assert auth._detect_password_type("plaintext") == PasswordType.CLEARTEXT
        assert auth._detect_password_type("{MD5}5d41402abc4b2a76b9719d911017c592") == PasswordType.MD5
        assert auth._detect_password_type("{SHA}aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d") == PasswordType.SHA1
        assert auth._detect_password_type("{SHA256}e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == PasswordType.SHA256
        assert auth._detect_password_type("$1$salt$hash") == PasswordType.CRYPT
        assert auth._detect_password_type("5d41402abc4b2a76b9719d911017c592") == PasswordType.NT_HASH

    def test_password_verification_cleartext(self):
        """Test cleartext password verification."""
        auth = self.authenticator
        assert auth._verify_password("test", "test", PasswordType.CLEARTEXT) is True
        assert auth._verify_password("test", "wrong", PasswordType.CLEARTEXT) is False

    def test_password_verification_md5(self):
        """Test MD5 password verification."""
        auth = self.authenticator
        # MD5 hash of "test"
        md5_hash = "{MD5}098f6bcd4621d373cade4e832627b4f6"
        assert auth._verify_password("test", md5_hash, PasswordType.MD5) is True
        assert auth._verify_password("wrong", md5_hash, PasswordType.MD5) is False

    def test_password_verification_sha1(self):
        """Test SHA1 password verification."""
        auth = self.authenticator
        # SHA1 hash of "test"
        sha1_hash = "{SHA}a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
        assert auth._verify_password("test", sha1_hash, PasswordType.SHA1) is True
        assert auth._verify_password("wrong", sha1_hash, PasswordType.SHA1) is False


class TestSQLConfig:
    """Test SQL configuration."""

    def test_default_config(self):
        """Test default configuration values."""
        config = SQLConfig(db_type=DatabaseType.SQLITE)
        assert config.db_type == DatabaseType.SQLITE
        assert config.host == "localhost"
        assert config.database == "radius"
        assert config.users_table == "radcheck"
        assert config.username_column == "username"

    def test_custom_config(self):
        """Test custom configuration."""
        config = SQLConfig(
            db_type=DatabaseType.POSTGRESQL,
            host="db.example.com",
            port=5432,
            database="custom_radius",
            username="radius_user",
            password="secret",
            users_table="custom_users"
        )
        assert config.db_type == DatabaseType.POSTGRESQL
        assert config.host == "db.example.com"
        assert config.port == 5432
        assert config.database == "custom_radius"
        assert config.username == "radius_user"
        assert config.password == "secret"
        assert config.users_table == "custom_users"


@pytest.mark.skipif(True, reason="Requires PostgreSQL setup")
class TestPostgreSQLBackend:
    """Test PostgreSQL backend (requires psycopg2)."""

    def test_postgresql_connection(self):
        """Test PostgreSQL connection."""
        config = SQLConfig(
            db_type=DatabaseType.POSTGRESQL,
            host="localhost",
            database="test_radius",
            username="test_user",
            password="test_pass"
        )

        with patch('psycopg2.connect') as mock_connect:
            mock_conn = Mock()
            mock_connect.return_value = mock_conn

            authenticator = SQLAuthenticator(config)
            # This would test the connection in a real scenario
            authenticator.close()


@pytest.mark.skipif(True, reason="Requires MySQL setup")
class TestMySQLBackend:
    """Test MySQL backend (requires PyMySQL)."""

    def test_mysql_connection(self):
        """Test MySQL connection."""
        config = SQLConfig(
            db_type=DatabaseType.MYSQL,
            host="localhost",
            database="test_radius",
            username="test_user",
            password="test_pass"
        )

        with patch('pymysql.connect') as mock_connect:
            mock_conn = Mock()
            mock_connect.return_value = mock_conn

            authenticator = SQLAuthenticator(config)
            # This would test the connection in a real scenario
            authenticator.close()


def test_create_sample_database():
    """Test sample database creation."""
    db_file = tempfile.mktemp(suffix='.db')

    try:
        create_sample_database(db_file)
        assert os.path.exists(db_file)

        # Verify database contents
        config = SQLConfig(db_type=DatabaseType.SQLITE, database=db_file)
        authenticator = SQLAuthenticator(config)

        # Test that sample users exist
        assert authenticator.authenticate_user("testuser", "testpass") is True
        assert authenticator.authenticate_user("alice", "secret123") is True

        authenticator.close()

    finally:
        if os.path.exists(db_file):
            os.unlink(db_file)
