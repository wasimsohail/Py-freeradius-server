import pytest

from pyfreeradius.dictionary import Dictionary, AttributeDef
from pyfreeradius.packet import Packet, Code


@pytest.fixture
def dictionary() -> Dictionary:
    d = Dictionary()
    # Minimal set of attributes needed for the test
    d.add_attribute(AttributeDef("User-Name", 1, "string"))
    d.add_attribute(AttributeDef("NAS-IP-Address", 4, "ipaddr"))
    d.add_attribute(AttributeDef("Reply-Message", 18, "string"))
    return d


def test_encode_decode_roundtrip(dictionary: Dictionary):
    secret = b"testing123"
    pkt = Packet(Code.ACCESS_REQUEST, identifier=42)
    pkt.add("User-Name", "alice", dictionary=dictionary)
    pkt.add("NAS-IP-Address", "192.0.2.1", dictionary=dictionary)

    raw = pkt.encode(secret=secret, dictionary=dictionary)

    decoded = Packet.decode(raw, secret=secret, dictionary=dictionary)

    # Verify header fields
    assert decoded.code == Code.ACCESS_REQUEST
    assert decoded.identifier == 42
    # Verify attributes as dict mapping code->value list
    attrs = {code: value for code, value in decoded.attributes}
    assert attrs[1] == "alice"
    assert attrs[4] == "192.0.2.1"


def test_unicode_string(dictionary: Dictionary):
    secret = b"s3cret"
    pkt = Packet(Code.ACCESS_REQUEST, identifier=5)
    pkt.add("User-Name", "δοκιμή", dictionary=dictionary)  # Greek word 'test'
    data = pkt.encode(secret=secret, dictionary=dictionary)
    dec = Packet.decode(data, secret=secret, dictionary=dictionary)
    assert dec.attributes[0][1] == "δοκιμή"
