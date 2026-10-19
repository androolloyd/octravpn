#!/usr/bin/env python3
"""Expose the node's loopback-only Circle gateway to a local Docker port.

The host publishes this port on 127.0.0.1 only. A relay-side HTTPS proxy may
reach it through an authenticated SSH reverse tunnel; the node still validates
the octra.to Host and limits reads to the configured onboarding Circle.
"""

import asyncio


async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while chunk := await asyncio.wait_for(reader.read(65536), timeout=30):
            writer.write(chunk)
            await writer.drain()
    except (asyncio.TimeoutError, ConnectionError, OSError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass


async def handle(client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> None:
    try:
        gateway_reader, gateway_writer = await asyncio.open_connection("127.0.0.1", 20805)
    except OSError:
        client_writer.close()
        await client_writer.wait_closed()
        return
    await asyncio.gather(
        pipe(client_reader, gateway_writer),
        pipe(gateway_reader, client_writer),
    )


async def main() -> None:
    server = await asyncio.start_server(handle, "0.0.0.0", 20806, limit=65536)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
