"""
Example 03 — Async card detection with asyncio
===============================================
Demonstrates ``wait_for_card_async``, which runs the blocking serial I/O
in a thread-pool so the event loop stays free for concurrent tasks.

This pattern is useful when embedding mifarepy inside FastAPI, Django
async views, or any asyncio-based service.

Usage:
    python 03_async_wait.py [port]
"""

import asyncio
import sys
from mifarepy import MifareReader
from mifarepy.protocol import GNetPlusError

PORT    = sys.argv[1] if len(sys.argv) > 1 else '/dev/ttyUSB0'
TIMEOUT = 20.0


async def ticker() -> None:
    """Print a heartbeat every second to show the loop is not blocked."""
    for i in range(1, 100):
        await asyncio.sleep(1)
        print(f'  … event loop alive ({i}s)')


async def card_waiter(reader: MifareReader) -> str:
    try:
        uid = await reader.wait_for_card_async(timeout=TIMEOUT)
        return uid
    except GNetPlusError as exc:
        return f'Reader error: {exc}'


async def main() -> None:
    with MifareReader(port=PORT) as reader:
        print(f'Waiting for card on {PORT} (async, timeout={TIMEOUT}s) …')

        # Run card detection and the ticker concurrently.
        ticker_task = asyncio.create_task(ticker())

        try:
            uid = await asyncio.wait_for(
                card_waiter(reader),
                timeout=TIMEOUT + 2,
            )
            ticker_task.cancel()
            print(f'\nCard detected! UID = {uid}')
        except asyncio.TimeoutError:
            ticker_task.cancel()
            print('\nNo card detected within the timeout.')


asyncio.run(main())
