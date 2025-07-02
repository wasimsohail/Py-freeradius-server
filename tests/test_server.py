import asyncio
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import time

import pytest

from pyfreeradius.server.main import RadiusDatagramProtocol, build_response_packet
from pyfreeradius.server.config import Config
from pyfreeradius.dictionary import Dictionary, AttributeDef
from pyfreeradius.packet import Packet, Code


RADCLIENT_PATH = shutil.which("radclient")

pytestmark = pytest.mark.skipif(RADCLIENT_PATH is None, reason="radclient binary not available")


@pytest.fixture(scope="module")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
async def running_server(tmp_path, event_loop):
    # Prepare dictionary with necessary attrs
    dictionary = Dictionary()
    dictionary.add_attribute(AttributeDef("User-Name", 1, "string"))
    dictionary.add_attribute(AttributeDef("User-Password", 2, "string"))
    dictionary.add_attribute(AttributeDef("Reply-Message", 18, "string"))

    # Config: allow 127.0.0.1 with secret testing123, user alice/password
    clients_conf = tmp_path / "clients.conf"
    clients_conf.write_text(
        """
client localhost {
    ipaddr = 127.0.0.1
    secret = testing123
}
""",
        encoding="utf-8",
    )
    users_file = tmp_path / "users"
    users_file.write_text("alice Cleartext-Password := \"password\"\n", encoding="utf-8")

    config = Config.load(clients_conf, users_file)

    # Find free UDP port
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    _, port = sock.getsockname()
    sock.close()

    listen = event_loop.create_datagram_endpoint(
        lambda: RadiusDatagramProtocol(config, dictionary),
        local_addr=("127.0.0.1", port),
    )
    transport, protocol = await listen
    try:
        yield port
    finally:
        transport.close()


def test_radclient_auth(running_server):
    port = running_server
    req = "User-Name = \"alice\"\nUser-Password = \"password\"\n"
    req_path = pathlib.Path("/tmp/radius_request.txt")
    req_path.write_text(req, encoding="utf-8")
    cmd = [RADCLIENT_PATH, f"127.0.0.1:{port}", "auth", "testing123", "-f", str(req_path)]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    # radclient returns exit code 0 on Access-Accept, 1 on Access-Reject
    assert result.returncode == 0, f"radclient failed: {result.stderr}"
    assert "Access-Accept" in result.stdout
