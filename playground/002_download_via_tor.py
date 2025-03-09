#!/usr/bin/env python3
import argparse

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

DEFAULT_CHUNK_SIZE_BYTES = 1024 * 1024  # 1 MB chunks (default)
DEFAULT_MAX_CONNECTIONS = 8  # Number of concurrent workers
MAX_CHUNK_RETRIES = 3  # Retries per chunk (connection errors)
SOCKET_FAILURE_THRESHOLD = 5  # Failures before renewing a port
TIMEOUT = 10  # Request timeout in seconds
TOR_CONTROL_PORT = 9055
TOR_PASSWORD = ""  # Set if needed
TOR_COMMON_CONTROL_PORTS = [9050, 9150, 9051, 8118]

# Use tqdm for printing to preserve the progress bar
print = tqdm.write

# Debug-mode flags
DEBUG_MAX_PROXIES = None
DEBUG_DO_USE_DUMMY_DATA = False
DEBUG_CONNECTION_FAILURE_RATE = 0
DEFAULT_CHUNK_SIZE_BYTES = DEFAULT_CHUNK_SIZE_BYTES


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


async def test_tor_connectivity():
    """
    Tests Tor connectivity for each SOCKS proxy by sending an HTTP GET request
    to http://httpbin.org/ip using a SOCKS5 proxy connector.
    """

    if not (proxies_result := get_tor_proxies()):
        print("No Tor proxies found.")
        return

    (_, proxy_addresses) = proxies_result
    test_url = "http://httpbin.org/ip"

    async def test_proxy(proxy: str):
        try:
            (host, port) = proxy.split(":")
            connector = ProxyConnector.from_url(f"socks5://{host}:{port}")
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(test_url, timeout=10) as response:
                    response.raise_for_status()
                    data = await response.json()
                    print(f"Tor connectivity successful on {proxy}: {data}")
        except Exception as e:
            print(f"Tor connectivity failed on {proxy}: {e}")

    await asyncio.gather(*(test_proxy(proxy) for proxy in proxy_addresses))


@retry(
    # stop=stop_after_attempt(3),
    wait=wait_exponential(min=timedelta(seconds=10), max=timedelta(hours=10)),
    retry=retry_if_exception_type(NoMoreProxies),
)
async def proxy_availability_monitor(good_proxies_queue: asyncio.Queue, max_connections: int):
    print("Replenishing proxies and monitoring availability.")
    await asyncio.sleep(1)

    (_, available_proxies) = get_tor_proxies()

    # Populate the proxies pool redundantly
    for _ in range(max_connections):
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


async def download_file(url: str, chunk_size_bytes: int, max_connections: int) -> dict:
    chunk_data = {}

    good_proxies_queue = asyncio.Queue()
    progress_queue = asyncio.Queue()
    chunk_queue = asyncio.PriorityQueue()

    metadata = parse_headers(await get_headers(url))

    if (file_size := metadata['file_size']) is None:
        raise ValueError("Content-Length header not provided by server.")

    print(f"Downloading {url}")
    print(f"Reported file size: {file_size / (1024 * 1024):.2f} MB")

    chunk_ranges = [(i, min(i + chunk_size_bytes, file_size)) for i in range(0, file_size, chunk_size_bytes)]

    # Enqueue all chunks
    for (chunk_id, (start, end)) in enumerate(chunk_ranges):
        await chunk_queue.put((0, ((chunk_id, len(chunk_ranges)), (start, end))))

    try:
        async with asyncio.TaskGroup() as tg:
            progress_bar_task = tg.create_task(progress_tracker(progress_queue, file_size))
            proxy_monitor_task = tg.create_task(proxy_availability_monitor(good_proxies_queue, max_connections))

            for i in range(max_connections):
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


def parse_args() -> argparse.Namespace:
    """Parses command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Download a file asynchronously with chunked storage. Must fit in memory."
    )
    parser.add_argument("url", help="The URL of the file to download.")
    parser.add_argument(
        "-o", "--output",
        help="Output filename [default: derived from server or URL]",
        type=Path
    )
    parser.add_argument(
        "-c", "--chunk-size",
        type=float,
        default=DEFAULT_CHUNK_SIZE_BYTES / (2 ** 20),
        help=f"Chunk size in MB [default: {DEFAULT_CHUNK_SIZE_BYTES / (2 ** 20):,} MB]"
    )
    parser.add_argument(
        "-m", "--max-connections",
        type=int,
        default=DEFAULT_MAX_CONNECTIONS,
        help=f"Max simultaneous connections [default: {DEFAULT_MAX_CONNECTIONS}]"
    )
    return parser.parse_args()


def validate_args(url: str, chunk_size: int, max_connections: int, output_dest: Path | None) -> None:
    """Performs sanity checks on the provided arguments."""
    # Check URL scheme.
    parsed_url = urlparse(url)
    if parsed_url.scheme not in ("http", "https"):
        raise ValueError("URL must start with 'http://' or 'https://'.")

    # Check that chunk size is positive.
    if chunk_size <= 0:
        raise ValueError("Chunk size must be a positive number.")

    # Check that max connections is positive.
    if max_connections <= 0:
        raise ValueError("Max connections must be a positive integer.")

    # Ensure the output file's parent directory exists (if output is provided).
    if output_dest:
        if output_dest.is_dir():
            pass
        else:
            if not output_dest.parent.exists():
                raise ValueError(f"Output directory '{output_dest.parent}' does not exist.")


def main():
    args = parse_args()

    url = args.url

    # If output destination is provided, resolve it; otherwise, output remains None (to be handled later).
    # This may be a directory or a file.
    output_dest = args.output.resolve() if args.output else None

    # Convert chunk size from MB to bytes.
    chunk_size_bytes = int(args.chunk_size * (2 ** 20))
    max_connections = args.max_connections

    # Perform sanity checks.
    validate_args(url, chunk_size_bytes, max_connections, output_dest)

    print(f"URL: {url}")
    print(f"Output: {output_dest or 'Not specified'}")
    print(f"Chunk Size (bytes): {chunk_size_bytes}")
    print(f"Max Connections: {max_connections}")

    # Test Tor connectivity
    asyncio.run(test_tor_connectivity())

    # DOWNLOAD THE FILE
    data = asyncio.run(download_file(url=url, chunk_size_bytes=chunk_size_bytes, max_connections=max_connections))

    # These are the chunked downloaded bytes
    if (chunk_data := data.get('chunk_data')) is None:
        print("Download failed; sorry.")
        exit(1)

    # Get the default filename from the metadata
    default_filename = data.get('filename') or \
                       Path(urlparse(url).path).name or \
                       f"downloaded_file_{datetime.now():%Y%m%d_%H%M%S}"

    if output_dest:
        if output_dest.is_dir():
            output_file = output_dest / default_filename
        else:
            output_file = output_dest
    else:
        output_file = Path(default_filename).resolve()

    # Compute md5 and sha256 checksums:
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()

    for i in range(len(chunk_data)):
        md5.update(chunk_data[i])
        sha256.update(chunk_data[i])

    print(f"MD5: {md5.hexdigest()}")
    print(f"SHA256: {sha256.hexdigest()}")

    with output_file.open(mode='wb') as fd:
        for i in range(len(chunk_data)):
            fd.write(chunk_data[i])

    print(f"File saved as {output_file}")

    with open(f"{output_file}-readme.txt", 'w') as fd:
        fd.write(f"MD5: {md5.hexdigest()}\n")
        fd.write(f"SHA256: {sha256.hexdigest()}\n")
        fd.write(f"URL: {url}\n")
        fd.write(f"Chunk size: {chunk_size_bytes}\n")
        fd.write(f"Max connections: {max_connections}\n")
        fd.write(f"Date/time: {datetime.now():%Y-%m-%d %H:%M:%S}\n")


if __name__ == "__main__":
    # url = "https://download.pytorch.org/whl/cpu/torchaudio-0.10.0%2Bcpu-cp36-cp36m-linux_x86_64.whl#sha256=2c2374eff0bcad2e8e3ae12ec6f3abde416c7cbcc1cdaf58b0c0be32ae2ee4a2"
    # url = "https://download.pytorch.org/whl/nightly/rocm6.3/torch-2.7.0.dev20250307%2Brocm6.3-cp312-cp312-manylinux_2_28_x86_64.whl"
    # url = "https://kernel.ubuntu.com/mainline/v6.13.6/amd64/linux-modules-6.13.6-061306-generic_6.13.6-061306.202503071839_amd64.deb"

    main()
