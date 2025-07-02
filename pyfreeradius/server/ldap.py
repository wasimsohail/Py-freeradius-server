from __future__ import annotations

"""LDAP authentication module for pyfreeradius.

Supports LDAP authentication against various directory servers:
- Microsoft Active Directory
- OpenLDAP
- 389 Directory Server
- Oracle Directory Server
- IBM Tivoli Directory Server

Provides user authentication, attribute retrieval, and group membership.
"""

import logging
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class LDAPServerType(Enum):
    """Supported LDAP server types."""
    GENERIC = "generic"
    ACTIVE_DIRECTORY = "ad"
    OPENLDAP = "openldap"
    DIRECTORY_389 = "389ds"
    ORACLE_DS = "oracle"
    IBM_TIVOLI = "tivoli"


class LDAPAuthMethod(Enum):
    """LDAP authentication methods."""
    SIMPLE = "simple"
    SASL_PLAIN = "sasl_plain"
    SASL_GSSAPI = "sasl_gssapi"
    SASL_DIGEST_MD5 = "sasl_digest_md5"


@dataclass
class LDAPConfig:
    """LDAP module configuration."""
    # Server connection
    server: str = "localhost"
    port: int = 389
    use_ssl: bool = False
    use_tls: bool = False
    ca_cert_file: str = ""
    cert_file: str = ""
    key_file: str = ""

    # Authentication
    bind_dn: str = ""
    bind_password: str = ""
    auth_method: LDAPAuthMethod = LDAPAuthMethod.SIMPLE
    server_type: LDAPServerType = LDAPServerType.GENERIC

    # Search configuration
    base_dn: str = "dc=example,dc=com"
    user_search_base: str = ""
    user_search_filter: str = "(uid=%s)"
    user_dn_template: str = ""  # e.g., "uid=%s,ou=users,dc=example,dc=com"

    # Group configuration
    group_search_base: str = ""
    group_search_filter: str = "(member=%s)"
    group_attribute: str = "cn"

    # Attribute mapping
    username_attribute: str = "uid"
    email_attribute: str = "mail"
    fullname_attribute: str = "cn"
    phone_attribute: str = "telephoneNumber"

    # Connection options
    timeout: int = 10
    network_timeout: int = 10
    timelimit: int = 30
    sizelimit: int = 1000

    # Connection pooling
    pool_size: int = 5
    pool_lifetime: int = 300
    pool_keepalive: bool = True


@dataclass
class LDAPUser:
    """LDAP user information."""
    dn: str
    username: str
    email: str = ""
    fullname: str = ""
    phone: str = ""
    groups: Optional[List[str]] = None
    attributes: Optional[Dict[str, List[str]]] = None

    def __post_init__(self):
        if self.groups is None:
            self.groups = []
        if self.attributes is None:
            self.attributes = {}


class LDAPAuthenticator:
    """LDAP-based user authenticator."""

    def __init__(self, config: LDAPConfig):
        self.config = config
        self._connection = None

    def authenticate_user(self, username: str, password: str) -> bool:
        """Authenticate user against LDAP server."""
        try:
            # Import ldap3 library
            try:
                import ldap3
                from ldap3 import Server, Connection, ALL, SIMPLE, ANONYMOUS
                from ldap3.core.exceptions import LDAPException
            except ImportError:
                raise RuntimeError("ldap3 not installed. Install with: pip install ldap3")

            # Get user DN
            user_dn = self._get_user_dn(username)
            if not user_dn:
                logger.warning("LDAP user not found: %s", username)
                return False

            # Create server object
            server = self._create_server()

            # Attempt to bind with user credentials
            try:
                conn = Connection(server, user=user_dn, password=password, authentication=SIMPLE)
                if conn.bind():
                    logger.info("LDAP authentication successful for user %s", username)
                    conn.unbind()
                    return True
                else:
                    logger.warning("LDAP authentication failed for user %s: %s", username, conn.result)
                    return False
            except LDAPException as e:
                logger.error("LDAP authentication error for user %s: %s", username, e)
                return False

        except Exception as e:
            logger.error("LDAP authentication error for user %s: %s", username, e)
            return False

    def get_user_info(self, username: str) -> Optional[LDAPUser]:
        """Get user information from LDAP."""
        try:
            import ldap3
            from ldap3 import Server, Connection, ALL, SIMPLE, SUBTREE
            from ldap3.core.exceptions import LDAPException

            # Create connection
            conn = self._get_connection()
            if not conn:
                return None

            # Search for user
            search_base = self.config.user_search_base or self.config.base_dn
            search_filter = self.config.user_search_filter % username

            attributes = [
                self.config.username_attribute,
                self.config.email_attribute,
                self.config.fullname_attribute,
                self.config.phone_attribute,
                'objectClass'
            ]

            conn.search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=attributes
            )

            if not conn.entries:
                logger.warning("LDAP user not found: %s", username)
                return None

            entry = conn.entries[0]

            # Extract user information
            user = LDAPUser(
                dn=entry.entry_dn,
                username=self._get_attribute_value(entry, self.config.username_attribute),
                email=self._get_attribute_value(entry, self.config.email_attribute),
                fullname=self._get_attribute_value(entry, self.config.fullname_attribute),
                phone=self._get_attribute_value(entry, self.config.phone_attribute),
                attributes=self._extract_attributes(entry)
            )

            # Get user groups
            user.groups = self.get_user_groups(user.dn)

            return user

        except Exception as e:
            logger.error("Error getting LDAP user info for %s: %s", username, e)
            return None

    def get_user_groups(self, user_dn: str) -> List[str]:
        """Get groups for user."""
        try:
            import ldap3
            from ldap3 import SUBTREE

            conn = self._get_connection()
            if not conn:
                return []

            groups = []

            if self.config.group_search_base:
                # Search for groups containing the user
                search_filter = self.config.group_search_filter % user_dn

                conn.search(
                    search_base=self.config.group_search_base,
                    search_filter=search_filter,
                    search_scope=SUBTREE,
                    attributes=[self.config.group_attribute]
                )

                for entry in conn.entries:
                    group_name = self._get_attribute_value(entry, self.config.group_attribute)
                    if group_name:
                        groups.append(group_name)

            return groups

        except Exception as e:
            logger.error("Error getting LDAP groups for %s: %s", user_dn, e)
            return []

    def test_connection(self) -> bool:
        """Test LDAP connection."""
        try:
            conn = self._get_connection()
            if conn and conn.bound:
                logger.info("LDAP connection test successful")
                return True
            else:
                logger.error("LDAP connection test failed")
                return False
        except Exception as e:
            logger.error("LDAP connection test error: %s", e)
            return False

    def _create_server(self):
        """Create LDAP server object."""
        import ldap3
        from ldap3 import Server, ALL, Tls

        # Configure TLS if needed
        tls = None
        if self.config.use_tls or self.config.use_ssl:
            tls_config = {}
            if self.config.ca_cert_file:
                tls_config['ca_certs_file'] = self.config.ca_cert_file
            if self.config.cert_file:
                tls_config['local_certificate_file'] = self.config.cert_file
            if self.config.key_file:
                tls_config['local_private_key_file'] = self.config.key_file
            tls = Tls(**tls_config)

        # Create server
        server = Server(
            host=self.config.server,
            port=self.config.port,
            use_ssl=self.config.use_ssl,
            tls=tls,
            get_info=ALL,
            connect_timeout=self.config.network_timeout
        )

        return server

    def _get_connection(self):
        """Get LDAP connection."""
        if self._connection and self._connection.bound:
            return self._connection

        try:
            import ldap3
            from ldap3 import Connection, SIMPLE, ANONYMOUS

            server = self._create_server()

            if self.config.bind_dn:
                # Authenticated bind
                self._connection = Connection(
                    server,
                    user=self.config.bind_dn,
                    password=self.config.bind_password,
                    authentication=SIMPLE
                )
            else:
                # Anonymous bind
                self._connection = Connection(server, authentication=ANONYMOUS)

            if self._connection.bind():
                if self.config.use_tls and not self.config.use_ssl:
                    self._connection.start_tls()
                return self._connection
            else:
                logger.error("Failed to bind to LDAP server: %s", self._connection.result)
                return None

        except Exception as e:
            logger.error("Error creating LDAP connection: %s", e)
            return None

    def _get_user_dn(self, username: str) -> Optional[str]:
        """Get user DN by username."""
        # If DN template is provided, use it
        if self.config.user_dn_template:
            return self.config.user_dn_template % username

        # Otherwise, search for the user
        conn = self._get_connection()
        if not conn:
            return None

        try:
            import ldap3
            from ldap3 import SUBTREE

            search_base = self.config.user_search_base or self.config.base_dn
            search_filter = self.config.user_search_filter % username

            conn.search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=['dn']
            )

            if conn.entries:
                return conn.entries[0].entry_dn
            else:
                return None

        except Exception as e:
            logger.error("Error finding user DN for %s: %s", username, e)
            return None

    def _get_attribute_value(self, entry, attribute_name: str) -> str:
        """Get single attribute value from LDAP entry."""
        try:
            if hasattr(entry, attribute_name):
                attr = getattr(entry, attribute_name)
                if attr and attr.value:
                    if isinstance(attr.value, list):
                        return str(attr.value[0]) if attr.value else ""
                    else:
                        return str(attr.value)
            return ""
        except Exception:
            return ""

    def _extract_attributes(self, entry) -> Dict[str, List[str]]:
        """Extract all attributes from LDAP entry."""
        attributes = {}
        try:
            for attr_name in entry.entry_attributes:
                attr = getattr(entry, attr_name)
                if attr:
                    if isinstance(attr.value, list):
                        attributes[attr_name] = [str(v) for v in attr.value]
                    else:
                        attributes[attr_name] = [str(attr.value)]
        except Exception as e:
            logger.error("Error extracting LDAP attributes: %s", e)

        return attributes

    def close(self):
        """Close LDAP connection."""
        if self._connection:
            try:
                self._connection.unbind()
            except Exception:
                pass
            self._connection = None


def create_active_directory_config(
    server: str,
    domain: str,
    bind_user: str = "",
    bind_password: str = "",
    use_ssl: bool = True
) -> LDAPConfig:
    """Create LDAP config for Active Directory."""

    # Convert domain to DN format
    domain_parts = domain.split('.')
    base_dn = ','.join([f'dc={part}' for part in domain_parts])

    return LDAPConfig(
        server=server,
        port=636 if use_ssl else 389,
        use_ssl=use_ssl,
        server_type=LDAPServerType.ACTIVE_DIRECTORY,
        bind_dn=f"{bind_user}@{domain}" if bind_user else "",
        bind_password=bind_password,
        base_dn=base_dn,
        user_search_base=f"cn=Users,{base_dn}",
        user_search_filter="(sAMAccountName=%s)",
        group_search_base=f"cn=Users,{base_dn}",
        group_search_filter="(member=%s)",
        username_attribute="sAMAccountName",
        email_attribute="mail",
        fullname_attribute="displayName",
        phone_attribute="telephoneNumber"
    )


def create_openldap_config(
    server: str,
    base_dn: str,
    bind_dn: str = "",
    bind_password: str = "",
    use_tls: bool = True
) -> LDAPConfig:
    """Create LDAP config for OpenLDAP."""

    return LDAPConfig(
        server=server,
        port=389,
        use_tls=use_tls,
        server_type=LDAPServerType.OPENLDAP,
        bind_dn=bind_dn,
        bind_password=bind_password,
        base_dn=base_dn,
        user_search_base=f"ou=users,{base_dn}",
        user_search_filter="(uid=%s)",
        group_search_base=f"ou=groups,{base_dn}",
        group_search_filter="(memberUid=%s)",
        username_attribute="uid",
        email_attribute="mail",
        fullname_attribute="cn",
        phone_attribute="telephoneNumber"
    )
