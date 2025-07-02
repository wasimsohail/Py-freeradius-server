#!/usr/bin/env python3
"""version.py - Generate FreeRADIUS version strings.

This script is a Python rewrite of the `version.sh` helper shipped with the
FreeRADIUS source tree.  It behaves (near-)identically, supporting the same
CLI, environment variables and output so that it can be used as a drop-in
replacement in build pipelines.

Most of the logic is a direct translation from POSIX shell to Python, with
small additions to improve readability and robustness.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import subprocess
import sys
from typing import List

# ---------------------------------------------------------------------------
# Constants & defaults – copied from version.sh
# ---------------------------------------------------------------------------

ROOT_DIR = pathlib.Path(__file__).resolve().parent

VERSION_FILE = ROOT_DIR / "VERSION"
COMMIT_FILE = ROOT_DIR / "VERSION_COMMIT"
COMMIT_DEPTH_FILE = ROOT_DIR / "VERSION_COMMIT_DEPTH"
RELEASE_FILE = ROOT_DIR / "RELEASE"

# Hard-coded fall-backs when VERSION is missing
DEFAULT_MAJOR = "4"
DEFAULT_MINOR = "0"
DEFAULT_INCRM = ""
DEFAULT_PRERELEASE = ""

# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------


def _in_repo() -> bool:
    """Return *True* when we are executed inside a Git repository."""
    try:
        subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=ROOT_DIR,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        return True
    except subprocess.CalledProcessError:
        return False


def _git(*args: str, capture: bool = True) -> str | None:
    """Run *git* with *args*.  When *capture* is *True* the stdout is
    returned stripped or *None* if the command fails.
    """
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=ROOT_DIR,
            text=True,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        return result.stdout.strip() if capture else ""
    except subprocess.CalledProcessError:
        return None


# ---------------------------------------------------------------------------
#   Version component helpers
# ---------------------------------------------------------------------------


def _read_version_parts() -> tuple[str, str, str, str]:
    """Return **(major, minor, incrm, prerelease)** from VERSION file or
    defaults when unavailable.
    """
    if VERSION_FILE.exists():
        raw = VERSION_FILE.read_text(encoding="utf-8").strip()
        # Split `4.0.0~beta0` into version and prerelease
        if "~" in raw:
            version_part, prerelease = raw.split("~", 1)
        else:
            version_part, prerelease = raw, ""
        ver_bits = (version_part.split(".") + ["", ""])[:3]  # pad to length 3
        major, minor, incrm = ver_bits
        return major, minor, incrm, prerelease
    # Fallbacks
    return DEFAULT_MAJOR, DEFAULT_MINOR, DEFAULT_INCRM, DEFAULT_PRERELEASE


def _component_major() -> str:
    return _read_version_parts()[0]


def _component_minor() -> str:
    return _read_version_parts()[1]


def _component_incrm() -> str:
    return _read_version_parts()[2]


def _component_prerelease() -> str:
    return _read_version_parts()[3]


def _component_commit() -> str:
    if COMMIT_FILE.exists():
        return COMMIT_FILE.read_text(encoding="utf-8").strip()

    if _in_repo():
        value = _git("rev-parse", "--short=8", "HEAD")
        if value:
            return value
    return ""


def _component_commit_depth() -> str:
    if COMMIT_DEPTH_FILE.exists():
        return COMMIT_DEPTH_FILE.read_text(encoding="utf-8").strip()

    if _in_repo():
        describe = _git("describe", "--tags", "--match", "branch_*", "--match", "release_*")
        if describe and "-" in describe:
            # Expected output: <tag>-<depth>-g<hash>
            depth = describe.split("-", 2)[1]
            return depth
    return ""


def _component_is_release() -> str:
    # Environment variable overrides everything.
    env_release = os.getenv("RELEASE")
    if env_release is not None:
        return env_release

    if RELEASE_FILE.exists():
        return "1"

    if _in_repo():
        # Check if current commit has a release_* tag and working tree clean
        if _git("describe", "--exact-match", "--match", "release_*") is not None:
            # Ensure git status is clean (no changes)
            status = _git("status", "--porcelain")
            return "1" if status == "" else "0"
        return "0"

    return "0"


_COMPONENT_HANDLERS = {
    "major": _component_major,
    "minor": _component_minor,
    "incrm": _component_incrm,
    "prerelease": _component_prerelease,
    "commit": _component_commit,
    "commit_depth": _component_commit_depth,
    "is_release": _component_is_release,
}


# ---------------------------------------------------------------------------
#   Main CLI handling
# ---------------------------------------------------------------------------


def parse_args(argv: List[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="version.py",
        add_help=False,
        description="Create a FreeRADIUS version string from one or more components.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "components",
        nargs="*",
        help=(
            "Sequence of components to output.  Each element may be one of:\n"
            "  major       – Major version component (from VERSION).\n"
            "  minor       – Minor version component.\n"
            "  incrm       – Incremental version component.\n"
            "  prerelease  – Pre-release component.\n"
            "  commit      – Short commit hash (8 chars).\n"
            "  commit_depth – Distance from last tag.\n"
            "  is_release  – 1 if current commit is a release tag, else 0.\n"
            "  *           – Any other string that will be echoed verbatim."
        ),
    )
    parser.add_argument("-h", action="store_true", dest="helpflag", help="Show this help message and exit.")
    parser.add_argument("-c", action="store_true", dest="clean", help="Remove *VERSION_* temporary files and exit.")
    parser.add_argument(
        "-d",
        action="store_true",
        dest="dump",
        help="Write commit, commit_depth, is_release to VERSION_* files and exit.",
    )

    ns, remaining = parser.parse_known_args(argv)

    # Replicate getopt: allow options preceding components only; if -h was used
    # we emulate the original behaviour where it ignores unknown stuff.
    if ns.helpflag:
        parser.print_help(sys.stdout)
        sys.exit(0)

    # Manually append remaining tokens (argparse stops at first positional)
    ns.components.extend(remaining)
    return ns


def _clean_tmp_files() -> None:
    for path in (COMMIT_FILE, COMMIT_DEPTH_FILE, RELEASE_FILE):
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def _dump_tmp_files() -> None:
    commit_val = _component_commit()
    COMMIT_FILE.write_text(commit_val + "\n", encoding="utf-8")

    depth_val = _component_commit_depth()
    COMMIT_DEPTH_FILE.write_text(depth_val + "\n", encoding="utf-8")

    if _component_is_release() == "1":
        RELEASE_FILE.touch(exist_ok=True)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: List[str] | None = None) -> None:
    args = parse_args(argv)

    if args.clean:
        _clean_tmp_files()
        sys.exit(0)

    if args.dump:
        _dump_tmp_files()
        sys.exit(0)

    if not args.components:
        # Behaviour of original script: if no components passed output nothing
        # and exit (printing newline).
        print()
        return

    out_parts: List[str] = []
    for comp in args.components:
        handler = _COMPONENT_HANDLERS.get(comp)
        if handler is not None:
            out_parts.append(handler())
        else:
            # Unknown component is echoed verbatim.
            out_parts.append(comp)

    # Print concatenated without separators, followed by newline.
    sys.stdout.write("".join(out_parts) + "\n")


if __name__ == "__main__":
    main()
