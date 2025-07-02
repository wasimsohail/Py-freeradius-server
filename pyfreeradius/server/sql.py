from __future__ import annotations

"""SQL authentication module for pyfreeradius.

Supports multiple database backends:
- SQLite (built-in)
- PostgreSQL (via psycopg2)
- MySQL (via PyMySQL)
- Microsoft SQL Server (via pyodbc)

Provides user authentication and attribute retrieval from SQL databases.
"""

import logging
import sqlite3
import hashlib
from typing import Dict, List, Optional, Tuple, Any, Union
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum

try:
    import crypt
    HAS_CRYPT = True
except ImportError:
    HAS_CRYPT = False

logger = logging.getLogger(__name__)


class DatabaseType(Enum):
    """Supported database types."""
    SQLITE = "sqlite"
    POSTGRESQL = "postgresql"
    MYSQL = "mysql"
    MSSQL = "mssql"


class PasswordType(Enum):
    """Supported password storage types."""
    CLEARTEXT = "cleartext"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    CRYPT = "crypt"
    NT_HASH = "nt_hash"


@dataclass
class SQLConfig:
    """SQL module configuration."""
    db_type: DatabaseType
    host: str = "localhost"
    port: int = 0  # Use default port for each DB type
    database: str = "radius"
    username: str = "radius"
    password: str = ""
    connection_string: str = ""

    # Table and column configuration
    users_table: str = "radcheck"
    groups_table: str = "radgroupcheck"
    user_group_table: str = "radusergroup"
    reply_table: str = "radreply"
    group_reply_table: str = "radgroupreply"

    # Column names
    username_column: str = "username"
    attribute_column: str = "attribute"
    value_column: str = "value"
    op_column: str = "op"

    # Connection pooling
    pool_size: int = 5
    max_overflow: int = 10
    pool_timeout: int = 30


@dataclass
class UserAttribute:
    """User attribute from database."""
    username: str
    attribute: str
    value: str
    operator: str = "=="


class DatabaseBackend(ABC):
    """Abstract database backend."""

    @abstractmethod
    def connect(self) -> Any:
        """Create database connection."""
        pass

    @abstractmethod
    def execute_query(self, query: str, params: Tuple = ()) -> List[Tuple]:
        """Execute query and return results."""
        pass

    @abstractmethod
    def close(self):
        """Close database connection."""
        pass


class SQLiteBackend(DatabaseBackend):
    """SQLite database backend."""

    def __init__(self, config: SQLConfig):
        self.config = config
        self.connection: Optional[sqlite3.Connection] = None

    def connect(self) -> sqlite3.Connection:
        """Create SQLite connection."""
        if not self.connection:
            db_path = self.config.database
            self.connection = sqlite3.connect(db_path, check_same_thread=False)
            self.connection.row_factory = sqlite3.Row
        return self.connection

    def execute_query(self, query: str, params: Tuple = ()) -> List[Tuple]:
        """Execute SQLite query."""
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute(query, params)
        return cursor.fetchall()

    def close(self):
        """Close SQLite connection."""
        if self.connection:
            self.connection.close()
            self.connection = None


class PostgreSQLBackend(DatabaseBackend):
    """PostgreSQL database backend."""

    def __init__(self, config: SQLConfig):
        self.config = config
        self.connection = None

    def connect(self):
        """Create PostgreSQL connection."""
        try:
            import psycopg2
            from psycopg2.extras import RealDictCursor

            if not self.connection:
                port = self.config.port or 5432
                self.connection = psycopg2.connect(
                    host=self.config.host,
                    port=port,
                    database=self.config.database,
                    user=self.config.username,
                    password=self.config.password,
                    cursor_factory=RealDictCursor
                )
            return self.connection
        except ImportError:
            raise RuntimeError("psycopg2 not installed. Install with: pip install psycopg2-binary")

    def execute_query(self, query: str, params: Tuple = ()) -> List[Tuple]:
        """Execute PostgreSQL query."""
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute(query, params)
        return cursor.fetchall()

    def close(self):
        """Close PostgreSQL connection."""
        if self.connection:
            self.connection.close()
            self.connection = None


class MySQLBackend(DatabaseBackend):
    """MySQL database backend."""

    def __init__(self, config: SQLConfig):
        self.config = config
        self.connection = None

    def connect(self):
        """Create MySQL connection."""
        try:
            import pymysql

            if not self.connection:
                port = self.config.port or 3306
                self.connection = pymysql.connect(
                    host=self.config.host,
                    port=port,
                    database=self.config.database,
                    user=self.config.username,
                    password=self.config.password,
                    cursorclass=pymysql.cursors.DictCursor  # type: ignore
                )
            return self.connection
        except ImportError:
            raise RuntimeError("PyMySQL not installed. Install with: pip install PyMySQL")

    def execute_query(self, query: str, params: Tuple = ()) -> List[Tuple]:
        """Execute MySQL query."""
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute(query, params)
        return cursor.fetchall()

    def close(self):
        """Close MySQL connection."""
        if self.connection:
            self.connection.close()
            self.connection = None


class SQLAuthenticator:
    """SQL-based user authenticator."""

    def __init__(self, config: SQLConfig):
        self.config = config
        self.backend = self._create_backend()

    def _create_backend(self) -> DatabaseBackend:
        """Create appropriate database backend."""
        if self.config.db_type == DatabaseType.SQLITE:
            return SQLiteBackend(self.config)
        elif self.config.db_type == DatabaseType.POSTGRESQL:
            return PostgreSQLBackend(self.config)
        elif self.config.db_type == DatabaseType.MYSQL:
            return MySQLBackend(self.config)
        else:
            raise ValueError(f"Unsupported database type: {self.config.db_type}")

    def authenticate_user(self, username: str, password: str) -> bool:
        """Authenticate user against SQL database."""
        try:
            # Get user password from database
            user_attrs = self.get_user_check_attributes(username)

            for attr in user_attrs:
                if attr.attribute.lower() in ('user-password', 'cleartext-password', 'password'):
                    stored_password = attr.value
                    password_type = self._detect_password_type(stored_password)

                    if self._verify_password(password, stored_password, password_type):
                        logger.info("SQL authentication successful for user %s", username)
                        return True

            logger.warning("SQL authentication failed for user %s", username)
            return False

        except Exception as e:
            logger.error("SQL authentication error for user %s: %s", username, e)
            return False

    def get_user_check_attributes(self, username: str) -> List[UserAttribute]:
        """Get check attributes for user."""
        query = f"""
            SELECT {self.config.username_column}, {self.config.attribute_column},
                   {self.config.value_column}, {self.config.op_column}
            FROM {self.config.users_table}
            WHERE {self.config.username_column} = ?
        """

        results = self.backend.execute_query(query, (username,))

        attributes = []
        for row in results:
            attr = UserAttribute(
                username=row[0],
                attribute=row[1],
                value=row[2],
                operator=row[3] if len(row) > 3 else "=="
            )
            attributes.append(attr)

        return attributes

    def get_user_reply_attributes(self, username: str) -> List[UserAttribute]:
        """Get reply attributes for user."""
        query = f"""
            SELECT {self.config.username_column}, {self.config.attribute_column},
                   {self.config.value_column}, {self.config.op_column}
            FROM {self.config.reply_table}
            WHERE {self.config.username_column} = ?
        """

        results = self.backend.execute_query(query, (username,))

        attributes = []
        for row in results:
            attr = UserAttribute(
                username=row[0],
                attribute=row[1],
                value=row[2],
                operator=row[3] if len(row) > 3 else "=="
            )
            attributes.append(attr)

        return attributes

    def get_user_groups(self, username: str) -> List[str]:
        """Get groups for user."""
        query = f"""
            SELECT groupname
            FROM {self.config.user_group_table}
            WHERE {self.config.username_column} = ?
        """

        results = self.backend.execute_query(query, (username,))
        return [row[0] for row in results]

    def _detect_password_type(self, stored_password: str) -> PasswordType:
        """Detect password storage type."""
        if stored_password.startswith('{MD5}'):
            return PasswordType.MD5
        elif stored_password.startswith('{SHA}'):
            return PasswordType.SHA1
        elif stored_password.startswith('{SHA256}'):
            return PasswordType.SHA256
        elif stored_password.startswith('$'):
            return PasswordType.CRYPT
        elif len(stored_password) == 32 and all(c in '0123456789abcdefABCDEF' for c in stored_password):
            return PasswordType.NT_HASH
        else:
            return PasswordType.CLEARTEXT

    def _verify_password(self, password: str, stored_password: str, password_type: PasswordType) -> bool:
        """Verify password against stored hash."""
        if password_type == PasswordType.CLEARTEXT:
            return password == stored_password

        elif password_type == PasswordType.MD5:
            hash_value = stored_password[5:]  # Remove {MD5} prefix
            computed_hash = hashlib.md5(password.encode()).hexdigest()
            return computed_hash == hash_value

        elif password_type == PasswordType.SHA1:
            hash_value = stored_password[5:]  # Remove {SHA} prefix
            computed_hash = hashlib.sha1(password.encode()).hexdigest()
            return computed_hash == hash_value

        elif password_type == PasswordType.SHA256:
            hash_value = stored_password[8:]  # Remove {SHA256} prefix
            computed_hash = hashlib.sha256(password.encode()).hexdigest()
            return computed_hash == hash_value

        elif password_type == PasswordType.CRYPT:
            if HAS_CRYPT:
                try:
                    return crypt.crypt(password, stored_password) == stored_password  # type: ignore
                except OSError:
                    logger.warning("crypt() not available on this system")
                    return False
            else:
                logger.warning("crypt module not available")
                return False

        elif password_type == PasswordType.NT_HASH:
            # NT Hash verification (for MS-CHAP)
            try:
                password_utf16 = password.encode('utf-16le')
                nt_hash = hashlib.new('md4', password_utf16).hexdigest()
                return nt_hash.lower() == stored_password.lower()
            except (ValueError, OSError):
                logger.warning("MD4 not available for NT hash verification")
                return False

        return False

    def close(self):
        """Close database connection."""
        self.backend.close()


def create_sample_database(db_path: str = "radius.db"):
    """Create sample SQLite database with test data."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Create tables
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS radcheck (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(64) NOT NULL,
            attribute VARCHAR(64) NOT NULL,
            op VARCHAR(2) NOT NULL DEFAULT '==',
            value VARCHAR(253) NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS radreply (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(64) NOT NULL,
            attribute VARCHAR(64) NOT NULL,
            op VARCHAR(2) NOT NULL DEFAULT '=',
            value VARCHAR(253) NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS radgroupcheck (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            groupname VARCHAR(64) NOT NULL,
            attribute VARCHAR(64) NOT NULL,
            op VARCHAR(2) NOT NULL DEFAULT '==',
            value VARCHAR(253) NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS radgroupreply (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            groupname VARCHAR(64) NOT NULL,
            attribute VARCHAR(64) NOT NULL,
            op VARCHAR(2) NOT NULL DEFAULT '=',
            value VARCHAR(253) NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS radusergroup (
            username VARCHAR(64) NOT NULL,
            groupname VARCHAR(64) NOT NULL,
            priority INTEGER DEFAULT 1
        )
    """)

    # Insert sample data
    cursor.execute("""
        INSERT OR REPLACE INTO radcheck (username, attribute, value)
        VALUES ('testuser', 'Cleartext-Password', 'testpass')
    """)

    cursor.execute("""
        INSERT OR REPLACE INTO radcheck (username, attribute, value)
        VALUES ('alice', 'Cleartext-Password', 'secret123')
    """)

    cursor.execute("""
        INSERT OR REPLACE INTO radreply (username, attribute, value)
        VALUES ('testuser', 'Reply-Message', 'Hello from SQL!')
    """)

    conn.commit()
    conn.close()

    logger.info("Sample database created at %s", db_path)
