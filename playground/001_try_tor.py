#!/usr/bin/env python3

import stem
import socket
import requests

from stem.control import Controller

TOR_COMMON_CONTROL_PORTS = [9050, 9150, 9051, 8118]


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


def get_tor_ports():
    """Retrieves the active Control and SOCKS ports from a running Tor instance."""
    tor_control_port = find_tor_control_port()
    if tor_control_port is None:
        return None

    with Controller.from_port(port=tor_control_port) as controller:
        controller.authenticate(chroot_path="")

        # Get the active Control Port(s)
        control_addresses = controller.get_info("net/listeners/control")
        control_addresses = [addr.strip('"') for addr in control_addresses.split()]

        # Get the active SOCKS Ports
        proxy_addresses = controller.get_info("net/listeners/socks")
        proxy_addresses = [addr.strip('"') for addr in proxy_addresses.split()]

        return (control_addresses, proxy_addresses)


def check_tor_connectivity(proxy_address):
    (host, port) = proxy_address.rsplit(":", 1)  # Extract IP and port correctly

    proxies = {
        "http": f"socks5h://{host}:{port}",
        "https": f"socks5h://{host}:{port}",
    }

    try:
        response = requests.get("http://httpbin.org/ip", proxies=proxies, timeout=10)
        response.raise_for_status()
        print(f"Tor connectivity successful on {proxy_address}. Your IP via Tor:")
        print(response.json())
    except Exception as e:
        print(f"Failed to connect via Tor on {proxy_address}:")
        print(e)


if __name__ == "__main__":
    (control_addresses, proxy_addresses) = get_tor_ports()

    print(f"Control Ports: {control_addresses}")
    print(f"SOCKS Ports: {proxy_addresses}")

    for proxy in proxy_addresses:
        check_tor_connectivity(proxy_address=proxy)
