from __future__ import annotations

"""Minimal parser for FreeRADIUS `clients.conf` compatible with pyfreeradius.

We only support extracting IP(/mask) or IPv6(/mask) and the *secret* field.
"""

import ipaddress
import pathlib
import re
from dataclasses import dataclass
from typing import Dict, List, Tuple

__all__ = [
    "Client",
    "Config",
]


@dataclass(slots=True)
class Client:
    name: str
    network: ipaddress._BaseNetwork  # type: ignore
    secret: str

    def matches(self, ip: str) -> bool:
        return ipaddress.ip_address(ip) in self.network


class Config:
    """Holds runtime configuration (clients, users, etc.)."""

    def __init__(self) -> None:
        self.clients: List[Client] = []
        # Simple test store – mapping username -> cleartext password
        self.users: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # Loading helpers
    # ------------------------------------------------------------------

    @classmethod
    def load(cls, clients_conf: pathlib.Path | str, users_file: pathlib.Path | str | None = None) -> "Config":
        conf = cls()
        conf._parse_clients_conf(pathlib.Path(clients_conf))
        if users_file is not None:
            conf._parse_users_file(pathlib.Path(users_file))
        return conf

    # ------------------------------------------------------------------
    # Private parsing helpers
    # ------------------------------------------------------------------

    _CLIENT_RE = re.compile(r"^client\s+(\S+)\s*\{", re.IGNORECASE)
    _KV_RE = re.compile(r"^(\S+)\s*=\s*(.+)$")

    def _parse_clients_conf(self, path: pathlib.Path) -> None:
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except FileNotFoundError:
            raise FileNotFoundError(f"clients.conf not found: {path}")

        in_block = False
        current_name = ""
        current_attrs: Dict[str, str] = {}

        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if not in_block:
                m = self._CLIENT_RE.match(line)
                if m:
                    current_name = m.group(1)
                    in_block = True
                    current_attrs = {}
                continue

            # We are inside a client block
            if line == "}" or line.startswith("}"):
                # finalize
                ip_line = current_attrs.get("ipaddr") or current_attrs.get("ipv6addr")
                secret = current_attrs.get("secret")
                if ip_line and secret:
                    # ip_line may include /mask
                    network = ipaddress.ip_network(ip_line, strict=False)
                    self.clients.append(Client(current_name, network, secret))
                in_block = False
                continue

            # key=value lines
            m = self._KV_RE.match(line)
            if m:
                key, value = m.group(1).lower(), m.group(2).strip().strip('"')
                current_attrs[key] = value

    def _parse_users_file(self, path: pathlib.Path) -> None:
        if not path.exists():
            return
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # simplistic: <username> Cleartext-Password := "<pass>"
            parts = line.split()
            if len(parts) >= 3 and parts[1].lower() == "cleartext-password":
                username = parts[0]
                # remainder after := or = may be value string
                rest = " ".join(parts[2:]).lstrip(":= ").strip()
                if rest.startswith('"') and rest.endswith('"'):
                    rest = rest[1:-1]
                self.users[username] = rest

    # ------------------------------------------------------------------
    # Lookup helpers
    # ------------------------------------------------------------------

    def find_secret_for_ip(self, ip: str) -> str | None:
        for client in self.clients:
            if client.matches(ip):
                return client.secret
        return None

    def check_user_password(self, username: str, password: str) -> bool:
        expected = self.users.get(username)
        if expected is None:
            # accept if no user db; alternatively, reject – we choose reject
            return False
        return expected == password
