from __future__ import annotations

import ssl
from typing import Tuple, Optional


class EAPTLSHandshake:
    """Runs a server-side TLS handshake over memory BIO objects.

    The object is completely I/O agnostic: the caller feeds it raw data from
    the peer using :py:meth:`recv` and retrieves bytes to send using
    :py:meth:`pending_out`.  When the handshake completes successfully
    :py:meth:`handshake_done` returns *True*.
    """

    def __init__(self, certfile: str, keyfile: str, cafile: Optional[str] = None):
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
        if cafile:
            ctx.load_verify_locations(cafile=cafile)
            ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.options |= ssl.OP_NO_COMPRESSION
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        ctx.set_ciphers("HIGH:!aNULL:@STRENGTH")

        self._in = ssl.MemoryBIO()
        self._out = ssl.MemoryBIO()
        self._sslobj = ctx.wrap_bio(self._in, self._out, server_side=True)
        self._handshake_done = False

    # -------------------------------------------------------
    # Public API
    # -------------------------------------------------------

    def recv(self, data: bytes) -> None:
        """Feed *data* received from the peer to the TLS engine."""
        self._in.write(data)
        if not self._handshake_done:
            try:
                self._sslobj.do_handshake()
                self._handshake_done = True
            except ssl.SSLWantReadError:
                pass
            except ssl.SSLError as ex:
                raise

    def pending_out(self) -> bytes:
        """Return any bytes waiting to be sent to the peer."""
        return self._out.read()

    def handshake_done(self) -> bool:
        return self._handshake_done

    # Future: methods to export MSK / cipher suite etc.
