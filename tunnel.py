"""
    tunnel.pyjam.as
    ~~~~~~~~~~~~~~~

    tunnel.pyjam.as provides an SSL-terminated, ephemeral HTTP tunnel to a
    machine on your local network without any custom software on your machine
    thanks to Wireguard.

    Copyright (C) 2022 Carl Bordum Hansen
"""


# TODO: can we use IPv6?
import atexit
import os
import random
import subprocess
import sys
import textwrap
from ipaddress import IPv4Address, IPv4Network
from types import TracebackType
from typing import Optional, Type

from flask import Flask, Response

import requests


SLUG_ALPHABET: str = "123456789abcdefghijkmnopqrstuvwxyz"

HOSTNAME = os.getenv("TUNNEL_HOSTNAME", "tunnel.pyjam.as")
CADDY_HOSTNAME = os.getenv("TUNNEL_CADDY_HOSTNAME", "localhost")
WG_NAME = os.getenv("TUNNEL_WG_INTERFACE_NAME", HOSTNAME)
if len(WG_NAME) > 15:
    print(
        f'Wireguard interface name "{WG_NAME}" is too long (>15 chars). Overwrite by setting TUNNEL_WG_INTERFACE_NAME',
        sys.stderr,
    )
    sys.exit(1)

WG_NETWORK = IPv4Network(os.getenv("TUNNEL_WG_NETWORK", "10.101.0.0/16"))
WG_PORT = int(os.getenv("TUNNEL_WG_PORT", "54321"))


def _gen_private_wg_key() -> str:
    """Generate a Wireguard private key."""
    p = subprocess.run(["wg", "genkey"], stdout=subprocess.PIPE)
    if p.returncode != 0:
        raise ChildProcessError("Failed to generate wireguard key")
    return p.stdout.decode().strip()


def _gen_public_wg_key(private_key: str) -> str:
    """Generate a public Wireguard key from a private key."""
    p = subprocess.Popen(
        ["wg", "pubkey"], stdout=subprocess.PIPE, stdin=subprocess.PIPE
    )
    out, _ = p.communicate(input=private_key.encode())
    return out.decode().strip()


class Client:
    def __init__(self, vpn_ip: IPv4Address, port: int, hostname: str, slug: str):
        self.ip = vpn_ip
        self.port = port
        self.hostname = hostname
        self.slug = slug
        self.private_key = _gen_private_wg_key()
        self.public_key = _gen_public_wg_key(self.private_key)
        self._update_route_rules()

    def config(
        self,
        server_hostname: str,
        server_ip: IPv4Address,
        server_wg_port: int,
        server_wg_public_key: str,
    ) -> str:
        return textwrap.dedent(
            f"""
            [Interface]
            Address = {self.ip}/32
            PrivateKey = {self.private_key}
            PostUp = printf 'You can now access http://0.0.0.0:{self.port} on https://{self.slug}.{self.hostname}/ ✨\\n'

            [Peer]
            PublicKey = {server_wg_public_key}
            AllowedIPs = {server_ip}/32
            Endpoint = {server_hostname}:{server_wg_port}
            PersistentKeepalive = 21
        """
        )

    @property
    def server_side_config(self) -> str:
        return textwrap.dedent(
            f"""
            [Peer]
            PublicKey = {self.public_key}
            AllowedIPs = {self.ip}/32
            """
        )

    @property
    def ip_route_cmd(self) -> list[str]:
        return ["ip", "route", "add", f"{self.ip}/32", "dev", "tunnel"]

    def _update_route_rules(self) -> None:
        """Update routing/firewall rules."""
        p = subprocess.run(self.ip_route_cmd)
        if p.returncode != 0:
            raise ChildProcessError(f"Failed to update routing rules for {self.ip}")


class WireguardServerInterface:
    def __init__(self, name: str, network: IPv4Network, port: int):
        self.name = name
        self.network = network
        self.port = port

        self.peers: list[Client] = []
        self.private_key = _gen_private_wg_key()
        self.public_key = _gen_public_wg_key(self.private_key)
        self._file_handle = open(self.full_path, "w+")
        self.hosts = network.hosts()
        self.ip = self.next_ip()

        self.write()
        self._up()
        atexit.register(self._down)

    @property
    def full_path(self) -> str:
        return f"/etc/wireguard/{self.name}.conf"

    def next_ip(self) -> IPv4Address:
        """Return the next ip in the Wireguard network."""
        return next(self.hosts)

    def add_peer(self, peer: Client) -> None:
        self.peers.append(peer)

    def _up(self) -> None:
        """Start the servers Wireguard interface."""
        p = subprocess.run(["wg-quick", "up", self.name])
        if p.returncode != 0:
            raise ChildProcessError("Failed to `up` interface")

    def _down(self) -> None:
        """Stop the servers Wireguard interface."""
        p = subprocess.run(["wg-quick", "down", self.name])
        if p.returncode != 0:
            raise ChildProcessError("Failed to `down` interface")

    def _generate_config(self) -> str:
        peer_configs = [peer.server_side_config for peer in self.peers]

        return (
            textwrap.dedent(
                f"""
                [Interface]
                Address = {self.ip}/32
                ListenPort = {self.port}
                PrivateKey = {self.private_key}
                """
            )
            + "\n".join(peer_configs)
        )

    def write(self) -> None:
        """Write Wireguard server configuration to disk."""
        self._file_handle.seek(0)
        self._file_handle.write(self._generate_config())
        self._file_handle.flush()

    def reload_interface(self) -> None:
        p = subprocess.run(
            f"/bin/bash -c 'wg addconf {self.name} <(wg-quick strip {self.name})'",
            shell=True,
        )
        if p.returncode != 0:
            raise ChildProcessError("Failed to reload interface")

    def __enter__(self) -> None:
        pass

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        self.write()
        self.reload_interface()


def init_reverse_proxy(caddy_hostname: str) -> None:
    """Initialise Caddy."""
    payload = {
        "apps": {"http": {"servers": {"srv0": {"listen": [":80"], "routes": []}}}}
    }
    r = requests.post(
        f"http://{caddy_hostname}:2019/load",
        json=payload,
    )
    r.raise_for_status()


def update_reverse_proxy(
    server_hostname: str, caddy_hostname: str, client: Client
) -> None:
    """Update Caddy to act as a reverse proxy for *client*."""
    payload = {
        "handle": [
            {
                "handler": "subroute",
                "routes": [
                    {
                        "handle": [
                            {
                                "handler": "reverse_proxy",
                                "upstreams": [{"dial": f"{client.ip}:{client.port}"}],
                            }
                        ]
                    }
                ],
            }
        ],
        "match": [{"host": [f"{client.slug}.{server_hostname}"]}],
        "terminal": True,
    }
    r = requests.post(
        f"http://{caddy_hostname}:2019/config/apps/http/servers/srv0/routes/",
        json=payload,
    )
    r.raise_for_status()


def make_slug(alphabet: str = SLUG_ALPHABET, length: int = 6) -> str:
    """Generate a slug usable as a subdomain and interface name."""
    return "".join(random.choices(alphabet, k=length))


wg = WireguardServerInterface(WG_NAME, WG_NETWORK, WG_PORT)
app = Flask(__name__)


@app.before_first_request
def init() -> None:
    init_reverse_proxy(CADDY_HOSTNAME)


@app.route("/")
def index() -> Response:
    return app.send_static_file("index.html")


@app.route("/<int:port>")
def new_tunnel(port: int) -> str:
    """Create a new tunnel.

    *port* is the port that the client wants requests forwarded to.
    """
    slug = make_slug()

    client = Client(wg.next_ip(), port, HOSTNAME, slug)

    with wg:
        wg.add_peer(client)

    update_reverse_proxy(HOSTNAME, CADDY_HOSTNAME, client)

    return client.config(HOSTNAME, wg.ip, wg.port, wg.public_key)
