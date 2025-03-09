#!/usr/bin/env python3

import stem
import socket
import hashlib
import asyncio
import aiohttp

from email.parser import HeaderParser
from urllib.parse import urlparse
from contextlib import asynccontextmanager
from random import random
from datetime import datetime, timedelta
from pathlib import Path

from multidict import CIMultiDictProxy
from tqdm.asyncio import tqdm
from stem.control import Controller
from aiohttp_socks import ProxyConnector
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type, wait_fixed

CHUNK_SIZE = 1024 * 1024  # 1 MB chunks
MAX_CONNECTIONS = 8  # Number of concurrent workers
MAX_CHUNK_RETRIES = 3  # Retries per chunk (connection errors)
SOCKET_FAILURE_THRESHOLD = 5  # Failures before renewing a port
TIMEOUT = 10  # Request timeout in seconds
TOR_CONTROL_PORT = 9055
TOR_PASSWORD = ""  # Set if needed
TOR_COMMON_CONTROL_PORTS = [9050, 9150, 9051, 8118]

# Use tqdm for printing to preserve the progress bar
print = tqdm.write

# Debug-mode flags
DEBUG_MAX_PROXIES = 2  # None
DEBUG_DO_USE_DUMMY_DATA = True
DEBUG_CONNECTION_FAILURE_RATE = 0
CHUNK_SIZE = CHUNK_SIZE


# --- Custom Exception ---
class WorkerError(Exception):
    pass


class NoMoreProxies(Exception):
    pass


class DownloadDone(Exception):
    pass


@asynccontextmanager
async def get_queue_item(queue: asyncio.Queue):
    """Context manager to get an item from the queue and mark it as done."""
    item = await queue.get()

    try:
        yield item
    finally:
        queue.task_done()


def find_tor_control_port():
    """Finds an active Tor Control Port by checking known ports."""
    for port in TOR_COMMON_CONTROL_PORTS:
        try:
            with Controller.from_port(port=port) as controller:
                controller.authenticate(chroot_path="")
                return port
        except stem.connection.IncorrectSocketType:
            continue  # Not a Control Port, try next
        except (socket.error, stem.SocketError):
            continue  # Port not in use, try next
        except stem.connection.AuthenticationFailure:
            return port


def get_tor_proxies():
    """Retrieves the active Control and SOCKS ports from a running Tor instance."""

    if tor_control_port := find_tor_control_port():
        with Controller.from_port(port=tor_control_port) as controller:
            controller.authenticate(chroot_path="")

            # Get the active Control Port(s)
            control_addresses = controller.get_info("net/listeners/control")
            control_addresses = [addr.strip('"') for addr in control_addresses.split()]

            # Get the active SOCKS Ports
            proxy_addresses = controller.get_info("net/listeners/socks")
            proxy_addresses = [addr.strip('"') for addr in proxy_addresses.split()]

        if DEBUG_MAX_PROXIES:
            proxy_addresses = proxy_addresses[0:DEBUG_MAX_PROXIES]

        return (control_addresses, proxy_addresses)


@retry(
    # stop=stop_after_attempt(3),
    wait=wait_exponential(min=timedelta(seconds=10), max=timedelta(hours=10)),
    retry=retry_if_exception_type(NoMoreProxies),
)
async def proxy_availability_monitor(good_proxies_queue: asyncio.Queue):
    print("Replenishing proxies and monitoring availability.")
    await asyncio.sleep(1)

    (_, available_proxies) = get_tor_proxies()

    # Populate the proxies pool redundantly
    for _ in range(MAX_CONNECTIONS):
        for proxy in available_proxies:
            await good_proxies_queue.put(proxy)

    while not good_proxies_queue.empty():
        print(f"Proxies report: {good_proxies_queue.qsize()} available.")
        await asyncio.sleep(10)

    raise NoMoreProxies("All proxies exhausted.")


async def progress_tracker(progress_queue: asyncio.Queue, file_size: int) -> None:
    with tqdm(
            total=file_size,
            unit="B",
            unit_scale=True,
            desc="Downloading",
            position=0,  # Ensures it sticks to the bottom
            leave=True,  # Keeps it visible after completion
    ) as pbar:
        while True:
            async with get_queue_item(progress_queue) as downloaded:
                if downloaded is None:
                    break

                pbar.update(downloaded)


@retry(
    stop=stop_after_attempt(MAX_CHUNK_RETRIES),
    wait=wait_exponential(min=timedelta(seconds=1), max=timedelta(minutes=1)),
    retry=retry_if_exception_type((aiohttp.ClientError, asyncio.TimeoutError)),
)
async def attempt_chunk(
        url: str,
        a: int,
        b: int,
        proxy: str,
) -> bytes:
    if DEBUG_CONNECTION_FAILURE_RATE and (random() < DEBUG_CONNECTION_FAILURE_RATE):
        raise aiohttp.ClientError("Simulating lack of connection")

    if DEBUG_DO_USE_DUMMY_DATA:
        # Do dummy I/O work and return dummy data
        await asyncio.sleep(1 + random())
        return b'0' * (b - a)

    if (a is None) or (b is None):
        raise ValueError("Chunk range not provided.")

    headers = {'Range': f"bytes={a}-{(b - 1)}"}
    connector = ProxyConnector.from_url(url=f"socks5://{proxy}")

    async with aiohttp.ClientSession(connector=connector) as local_session:
        async with local_session.get(url, headers=headers, timeout=TIMEOUT) as response:
            response.raise_for_status()
            return await response.read()


@retry(wait=wait_fixed(timedelta(seconds=5)))
async def worker(
        *,
        worker_id: int,
        chunk_queue: asyncio.PriorityQueue,
        good_proxies_queue: asyncio.Queue,
        progress_queue: asyncio.Queue,
        url: str,
        chunk_data: dict[int, bytes],
):
    print(f"Worker {worker_id}: Started.")
    await asyncio.sleep(random())

    while True:
        async with (
            get_queue_item(chunk_queue) as (priority, item),
            get_queue_item(good_proxies_queue) as proxy
        ):
            try:
                ((chunk_id, total_chunks), (a, b)) = item
                print(f"Worker {worker_id}: Chunk {chunk_id}/{total_chunks} processing [{a}-{b}]")

                # Record the chunk data (w/o intermediary storage)
                chunk_data[chunk_id] = await attempt_chunk(url, a, b, proxy)

                # Record the size of downloaded data for progress tracking
                await progress_queue.put(len(chunk_data[chunk_id]))
            except asyncio.CancelledError:
                print(f"Worker {worker_id}: Received cancellation signal.")

                # Re-schedule the chunk, just in case
                await chunk_queue.put((priority, item))

                # The proxy might still be good, so put it back
                await good_proxies_queue.put(proxy)

                break
            except Exception as ex:
                print(f"Worker {worker_id}: Chunk {chunk_id}/{total_chunks} failed on {proxy}: {ex}")

                # Increase priority to retry the same chunk sooner
                await chunk_queue.put((priority - 1, item))

                # Trigger worker backoff
                raise WorkerError(
                    f"Worker {worker_id}: Chunk {chunk_id}/{total_chunks} "
                    f"failure with proxy {proxy} "
                    f"(reason: {ex})"
                )

                # Don't put the proxy back into the good queue
                pass
            else:
                # Put the proxy back into the good queue
                await good_proxies_queue.put(proxy)


def parse_headers(headers: CIMultiDictProxy) -> dict:
    """Parse the headers and return the file size and filename."""

    # Parse file size from Content-Length header.
    content_length = headers.get("Content-Length")
    file_size = int(content_length) if content_length else None

    headers = HeaderParser().parsestr(f"X: {headers.get('Content-Disposition') or ''}")
    filename = headers.get_param("filename", header="X")

    print(f"File size from headers: {file_size}")
    print(f"Filename from headers: {filename}")

    return {'file_size': file_size, 'filename': filename, 'headers': headers}


@retry(
    wait=wait_exponential(min=timedelta(seconds=1), max=timedelta(hours=12)),
    retry=retry_if_exception_type((aiohttp.ClientError, asyncio.TimeoutError)),
)
async def get_headers(url: str) -> CIMultiDictProxy:
    """
    Fetch file metadata via an HTTP HEAD request.

    Returns a dictionary with:
      - "file_size": int or None, the Content-Length as an integer.
      - "filename": str, extracted from the Content-Disposition header using the email parser.
        If absent or parsing fails, the filename is derived from the URL path.
    """
    async with aiohttp.ClientSession() as session:
        async with session.head(url, allow_redirects=True) as response:
            response.raise_for_status()
            return response.headers


async def download_file(url: str) -> dict:
    chunk_data = {}

    good_proxies_queue = asyncio.Queue()
    progress_queue = asyncio.Queue()
    chunk_queue = asyncio.PriorityQueue()

    metadata = parse_headers(await get_headers(url))

    if (file_size := metadata['file_size']) is None:
        raise ValueError("Content-Length header not provided by server.")

    print(f"Downloading {url}")
    print(f"Reported file size: {file_size / (1024 * 1024):.2f} MB")

    chunk_ranges = [(i, min(i + CHUNK_SIZE, file_size)) for i in range(0, file_size, CHUNK_SIZE)]

    # Enqueue all chunks
    for (chunk_id, (start, end)) in enumerate(chunk_ranges):
        await chunk_queue.put((0, ((chunk_id, len(chunk_ranges)), (start, end))))

    try:
        async with asyncio.TaskGroup() as tg:
            progress_bar_task = tg.create_task(progress_tracker(progress_queue, file_size))
            proxy_monitor_task = tg.create_task(proxy_availability_monitor(good_proxies_queue))

            for i in range(MAX_CONNECTIONS):
                tg.create_task(worker(
                    worker_id=i,
                    chunk_queue=chunk_queue,
                    good_proxies_queue=good_proxies_queue,
                    progress_queue=progress_queue,
                    url=url,
                    chunk_data=chunk_data,
                ))

            await chunk_queue.join()

            proxy_monitor_task.cancel()

            # Let the progress tracker finish
            await progress_queue.put(None)
            await asyncio.wait_for(progress_bar_task, timeout=3)

            # Cancel any running tasks (to quit the context):
            raise DownloadDone()
    except* DownloadDone:
        print("Download completed.")

    except* NoMoreProxies as exg:
        print(f"Download failed: {list(exg.exceptions)}")

    except* asyncio.exceptions.CancelledError as exg:
        print(f"Download cancelled: {list(exg.exceptions)}")

    except* Exception as exg:
        print(f"Download error: {list(exg.exceptions)}")

    if set(chunk_data.keys()) == set(range(len(chunk_ranges))):
        if file_size == sum(len(chunk_data[i]) for i in chunk_data):
            return {'chunk_data': chunk_data, **metadata}


def main(url: str):
    # Download the file
    data = asyncio.run(download_file(url))

    # These are the chunked downloaded bytes
    if (chunk_data := data.get('chunk_data')) is None:
        print("Download failed; sorry.")
        exit(1)

    # Get the filename from the metadata
    filename = Path(data.get('filename') or Path(urlparse(url).path).name or "downloaded_file").resolve()

    # Compute md5 and sha256 checksums:
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()

    for i in range(len(chunk_data)):
        md5.update(chunk_data[i])
        sha256.update(chunk_data[i])

    print(f"MD5: {md5.hexdigest()}")
    print(f"SHA256: {sha256.hexdigest()}")

    with filename.open(mode='wb') as fd:
        for i in range(len(chunk_data)):
            fd.write(chunk_data[i])

    print(f"File saved as {filename}")

    with open(f"{filename}-readme.txt", 'w') as fd:
        fd.write(f"MD5: {md5.hexdigest()}\n")
        fd.write(f"SHA256: {sha256.hexdigest()}\n")
        fd.write(f"URL: {url}\n")
        fd.write(f"Chunk size: {CHUNK_SIZE}\n")
        fd.write(f"Max connections: {MAX_CONNECTIONS}\n")
        fd.write(f"Date/time: {datetime.now():%Y-%m-%d %H:%M:%S}\n")


if __name__ == "__main__":
    url = "https://download.pytorch.org/whl/cpu/torchaudio-0.10.0%2Bcpu-cp36-cp36m-linux_x86_64.whl#sha256=2c2374eff0bcad2e8e3ae12ec6f3abde416c7cbcc1cdaf58b0c0be32ae2ee4a2"
    # url = "https://download.pytorch.org/whl/nightly/rocm6.3/torch-2.7.0.dev20250307%2Brocm6.3-cp312-cp312-manylinux_2_28_x86_64.whl"
    # url = "https://kernel.ubuntu.com/mainline/v6.13.6/amd64/linux-modules-6.13.6-061306-generic_6.13.6-061306.202503071839_amd64.deb"

    main(url)
