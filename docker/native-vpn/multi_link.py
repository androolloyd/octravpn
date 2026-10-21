"""Bounded opaque TCP fixture links; the native protocol remains end-to-end."""
import asyncio
import json
import signal
import ssl
import sys


async def serve(mapping):
    slots = asyncio.Semaphore(32)
    active = set()
    servers = []

    async def bridge(reader, writer, target):
        # Refuse before creating tasks/backends when the bounded link is full.
        if slots.locked():
            writer.close(); await writer.wait_closed(); return
        async with slots:
            task = asyncio.current_task(); active.add(task)
            other = None
            try:
                upstream, other = await asyncio.wait_for(asyncio.open_connection(*target), 10)
                async def copy(source, destination):
                    while True:
                        data = await asyncio.wait_for(source.read(65_536), 180)
                        if not data: return
                        destination.write(data); await asyncio.wait_for(destination.drain(), 10)
                tasks = [asyncio.create_task(copy(reader, other)), asyncio.create_task(copy(upstream, writer))]
                try:
                    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                    for completed in done: completed.result()
                finally:
                    for work in tasks: work.cancel()
                    await asyncio.gather(*tasks, return_exceptions=True)
            except (OSError, TimeoutError, asyncio.IncompleteReadError):
                pass
            finally:
                writer.close()
                if other: other.close()
                active.discard(task)
                await asyncio.gather(writer.wait_closed(), *( [other.wait_closed()] if other else []), return_exceptions=True)
    for row in mapping:
        target = tuple(row['target'])
        context = None
        if 'tls' in row:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(row['tls']['certificate'], row['tls']['private_key'])
        async def accept(reader, writer, target=target, row=row):
            if 'tls' in row:
                print(json.dumps({'tls_peer': writer.get_extra_info('peername')[0], 'listen': row['listen']}), flush=True)
            elif row.get('observe_peer'):
                print(json.dumps({'tcp_peer': writer.get_extra_info('peername')[0], 'listen': row['listen']}), flush=True)
            await bridge(reader, writer, target)
        servers.append(await asyncio.start_server(accept, *row['listen'], limit=65_536, ssl=context,
            **({'ssl_handshake_timeout': 10} if context else {})))
    print(json.dumps({'ready': True, 'links': len(servers)}), flush=True)
    stopped = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in [signal.SIGTERM, signal.SIGINT]: loop.add_signal_handler(sig, stopped.set)
    await stopped.wait()
    for server in servers: server.close()
    await asyncio.gather(*(server.wait_closed() for server in servers))
    for task in list(active): task.cancel()
    await asyncio.gather(*active, return_exceptions=True)


if __name__ == '__main__': asyncio.run(serve(json.load(open(sys.argv[1]))))
