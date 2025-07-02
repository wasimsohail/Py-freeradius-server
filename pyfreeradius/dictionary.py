from __future__ import annotations

"""Dictionary loader for pyfreeradius.

Supports a minimal subset of the FreeRADIUS dictionary syntax adequate for
packet encoding/decoding in milestone-1.

Supported directives (case-insensitive):

ATTRIBUTE <name> <code> <type> [vendor]
VALUE     <attr_name> <value_name> <number>  (ignored for now)
INCLUDE   <path>                              (relative to current file)

Lines starting with `#` are comments.  Blank lines are ignored.
"""

import pathlib
from dataclasses import dataclass
from typing import Dict, Optional

__all__ = [
    "AttributeDef",
    "Dictionary",
]


@dataclass(slots=True)
class AttributeDef:
    name: str
    code: int
    type: str  # string, integer, ipaddr, octets, etc.

    def __post_init__(self) -> None:
        self.name = self.name.strip()
        if isinstance(self.code, str):
            self.code = int(self.code)
        self.type = self.type.lower().strip()


class Dictionary:
    """In-memory representation of one or more dictionary files."""

    def __init__(self) -> None:
        self._by_name: Dict[str, AttributeDef] = {}
        self._by_code: Dict[int, AttributeDef] = {}

    # ---------------------------------------------------------------------
    # Public API
    # ---------------------------------------------------------------------

    def add_attribute(self, attr: AttributeDef) -> None:
        if attr.name in self._by_name or attr.code in self._by_code:
            # Ignore duplicates (FreeRADIUS does same when re-including)
            return
        self._by_name[attr.name] = attr
        self._by_code[attr.code] = attr

    def by_name(self, name: str) -> Optional[AttributeDef]:
        return self._by_name.get(name)

    def by_code(self, code: int) -> Optional[AttributeDef]:
        return self._by_code.get(code)

    # ------------------------------------------------------------------
    # Loading helpers
    # ------------------------------------------------------------------

    def load(self, path: pathlib.Path) -> None:
        """Load *path* and any nested includes into this Dictionary."""
        path = path.expanduser().resolve()
        self._load_file(path, path.parent)

    # ------------------------------------------------------------------
    # Internal implementation
    # ------------------------------------------------------------------

    def _load_file(self, file_path: pathlib.Path, base_dir: pathlib.Path) -> None:
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except FileNotFoundError:
            raise FileNotFoundError(f"Dictionary file not found: {file_path}") from None

        for line in content:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            tokens = line.split()
            directive = tokens[0].upper()
            args = tokens[1:]

            if directive == "ATTRIBUTE":
                if len(args) < 3:
                    continue  # malformed
                name, code, typ = args[:3]
                self.add_attribute(AttributeDef(name, int(code), typ))

            elif directive == "INCLUDE":
                include_path = base_dir / args[0]
                self._load_file(include_path.resolve(), include_path.parent)

            # VALUE and other lines ignored for milestone-1

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    def __contains__(self, item: str | int) -> bool:  # type: ignore[override]
        if isinstance(item, str):
            return item in self._by_name
        return item in self._by_code

    def __getitem__(self, item: str | int) -> AttributeDef:  # type: ignore[override]
        if isinstance(item, str):
            return self._by_name[item]
        return self._by_code[item]
