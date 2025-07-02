#!/usr/bin/env python3

"""
Basic RADIUS Server Example

This example demonstrates how to set up and run a simple RADIUS server
using PyFreeRADIUS.

Usage:
    python3 examples/basic_server.py

Test with radclient:
    echo "User-Name=testuser,User-Password=testpass123" | radclient -x localhost:1812 auth testing123
"""

import asyncio
import logging
import sys
import os

# Add the parent directory to the path so we can import pyfreeradius
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from pyfreeradius.server.simple_server import create_simple_server
from pyfreeradius.packet import Code


async def main():
    """Run the basic RADIUS server."""
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    print("🚀 Starting PyFreeRADIUS Basic Server")
    print("=" * 50)

    # Configure clients (IP -> shared secret)
    clients = {
        "127.0.0.1": b"testing123",      # localhost
        "10.0.0.0/8": b"internal_net",   # Internal network
        "192.168.0.0/16": b"private_net" # Private network
    }

    try:
        # Create and start server
        server = await create_simple_server(
            bind_address="0.0.0.0",
            bind_port=1812,
            clients=clients
        )

        print(f"✅ RADIUS server started on port 1812")
        print(f"📡 Configured clients:")
        for ip, secret in clients.items():
            print(f"   • {ip} (secret: {secret.decode()})")

        print("\n🧪 Test with radclient:")
        print('   echo "User-Name=testuser,User-Password=testpass123" | \\')
        print('   radclient -x localhost:1812 auth testing123')

        print("\n📊 Server Statistics:")
        print("   Press Ctrl+C to stop and show final stats")

        # Keep server running and show periodic stats
        try:
            while True:
                await asyncio.sleep(10)
                stats = server.get_stats()
                if stats['packets_received'] > 0:
                    print(f"\n📈 Stats: {stats['packets_received']} packets received, "
                          f"{stats['access_accepts']} accepts, {stats['access_rejects']} rejects")

        except KeyboardInterrupt:
            print("\n\n⏹️  Shutting down server...")

        # Show final statistics
        final_stats = server.get_stats()
        print("\n📊 Final Statistics:")
        print(f"   • Packets received: {final_stats['packets_received']}")
        print(f"   • Packets sent: {final_stats['packets_sent']}")
        print(f"   • Access accepts: {final_stats['access_accepts']}")
        print(f"   • Access rejects: {final_stats['access_rejects']}")
        print(f"   • Errors: {final_stats['errors']}")
        print(f"   • Uptime: {final_stats['uptime_seconds']:.1f} seconds")
        print(f"   • Packets/sec: {final_stats['packets_per_second']:.2f}")

        # Stop server
        await server.stop()
        print("✅ Server stopped gracefully")

    except Exception as e:
        print(f"❌ Error starting server: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
