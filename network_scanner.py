#!/usr/bin/env python3

import argparse
import concurrent.futures
import ipaddress
import json
import socket
import subprocess
import sys
from typing import Dict, List, Optional, Sequence, Set, Tuple


def run_command(command_args: Sequence[str]) -> Tuple[int, str, str]:
    """Run a system command and return (returncode, stdout, stderr)."""
    try:
        completed = subprocess.run(
            list(command_args),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            text=True,
        )
        return completed.returncode, completed.stdout.strip(), completed.stderr.strip()
    except FileNotFoundError as exc:
        return 127, "", str(exc)


def detect_default_interface() -> Optional[str]:
    """Detect the default network interface using `ip route`.

    Returns the interface name or None if it cannot be determined.
    """
    code, out, _ = run_command(["ip", "-o", "route", "show", "default"])
    if code != 0 or not out:
        return None
    # Example: "default via 192.168.1.1 dev wlan0 proto dhcp metric 600"
    parts = out.split()
    if "dev" in parts:
        try:
            dev_index = parts.index("dev")
            return parts[dev_index + 1]
        except (ValueError, IndexError):
            return None
    return None


def detect_interface_network(interface_name: str) -> Optional[ipaddress.IPv4Network]:
    """Detect the IPv4 network for the provided interface using `ip addr`.

    Returns the IPv4Network or None.
    """
    code, out, _ = run_command(["ip", "-o", "-4", "addr", "show", "dev", interface_name])
    if code != 0 or not out:
        return None
    # Example line: "2: wlan0    inet 192.168.1.42/24 brd 192.168.1.255 scope global dynamic wlan0"
    for line in out.splitlines():
        fields = line.split()
        if "inet" in fields:
            try:
                inet_index = fields.index("inet")
                cidr = fields[inet_index + 1]
                try:
                    iface_network = ipaddress.ip_interface(cidr).network
                    return ipaddress.IPv4Network(str(iface_network), strict=False)
                except ValueError:
                    continue
            except (ValueError, IndexError):
                continue
    return None


def autodetect_network() -> Optional[ipaddress.IPv4Network]:
    """Try to autodetect the primary IPv4 network.

    This uses the default interface and its assigned address.
    """
    interface_name = detect_default_interface()
    if not interface_name:
        return None
    return detect_interface_network(interface_name)


def ping_host_once(ip_address: str, timeout_seconds: float) -> bool:
    """Ping a host once using the system `ping` command.

    Returns True if the host responds, False otherwise.
    """
    # Linux ping: -n no DNS, -c 1 count, -W timeout in seconds
    timeout_arg = str(max(1, int(round(timeout_seconds))))
    code, _, _ = run_command(["ping", "-n", "-c", "1", "-W", timeout_arg, ip_address])
    return code == 0


def collect_arp_entries() -> Dict[str, str]:
    """Collect ARP table entries via `ip neigh`.

    Returns a mapping of ip -> mac for entries that have a known link-layer address.
    """
    code, out, _ = run_command(["ip", "neigh", "show"])
    if code != 0 or not out:
        return {}
    ip_to_mac: Dict[str, str] = {}
    # Example: "192.168.1.1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
    for line in out.splitlines():
        fields = line.split()
        if len(fields) < 5:
            continue
        ip = fields[0]
        mac = None
        if "lladdr" in fields:
            try:
                mac = fields[fields.index("lladdr") + 1]
            except (ValueError, IndexError):
                mac = None
        if mac and mac != "00:00:00:00:00:00":
            ip_to_mac[ip] = mac
    return ip_to_mac


def reverse_dns_lookup(ip_address: str) -> Optional[str]:
    """Attempt reverse DNS lookup for the given IP address."""
    try:
        host, _, _ = socket.gethostbyaddr(ip_address)
        return host
    except Exception:
        return None


def scan_network_with_ping(network: ipaddress.IPv4Network, timeout_seconds: float, max_workers: int) -> Set[str]:
    """Perform a ping sweep across the network, returning responding IP strings."""
    responding_ips: Set[str] = set()
    ip_strings: List[str] = [str(host) for host in network.hosts()]
    if not ip_strings:
        return responding_ips

    def task(ip: str) -> Tuple[str, bool]:
        return ip, ping_host_once(ip, timeout_seconds)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        for ip, alive in executor.map(task, ip_strings, chunksize=32):
            if alive:
                responding_ips.add(ip)
    return responding_ips


def format_as_table(rows: List[Tuple[str, Optional[str], Optional[str]]]) -> str:
    """Format the results as an aligned text table."""
    headers = ("IP Address", "MAC Address", "Hostname")
    str_rows: List[Tuple[str, str, str]] = []
    for ip, mac, host in rows:
        str_rows.append((ip, mac or "", host or ""))
    col_widths = [
        max(len(headers[0]), *(len(r[0]) for r in str_rows)) if str_rows else len(headers[0]),
        max(len(headers[1]), *(len(r[1]) for r in str_rows)) if str_rows else len(headers[1]),
        max(len(headers[2]), *(len(r[2]) for r in str_rows)) if str_rows else len(headers[2]),
    ]
    lines: List[str] = []
    header_line = f"{headers[0]:<{col_widths[0]}}  {headers[1]:<{col_widths[1]}}  {headers[2]:<{col_widths[2]}}"
    sep_line = f"{'-' * col_widths[0]}  {'-' * col_widths[1]}  {'-' * col_widths[2]}"
    lines.append(header_line)
    lines.append(sep_line)
    for r in str_rows:
        lines.append(f"{r[0]:<{col_widths[0]}}  {r[1]:<{col_widths[1]}}  {r[2]:<{col_widths[2]}}")
    return "\n".join(lines)


def format_as_csv(rows: List[Tuple[str, Optional[str], Optional[str]]]) -> str:
    output_lines: List[str] = ["ip,mac,hostname"]
    for ip, mac, host in rows:
        ip_s = ip
        mac_s = mac or ""
        host_s = host or ""
        # naive escaping for commas and quotes
        def esc(val: str) -> str:
            if "," in val or '"' in val or "\n" in val:
                return '"' + val.replace('"', '""') + '"'
            return val
        output_lines.append(
            ",".join([esc(ip_s), esc(mac_s), esc(host_s)])
        )
    return "\n".join(output_lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Escanea la red local para listar dispositivos (ping + ARP).",
    )
    parser.add_argument(
        "--cidr",
        help="Red a escanear en formato CIDR, p.ej. 192.168.1.0/24. Si no se especifica, se detecta automáticamente.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=128,
        help="Número de hilos para el ping (por defecto: 128)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.8,
        help="Tiempo de espera por ping en segundos (por defecto: 0.8)",
    )
    parser.add_argument(
        "--no-dns",
        action="store_true",
        help="No intentar resolución inversa de nombres (más rápido)",
    )
    parser.add_argument(
        "--include-arp",
        action="store_true",
        help="Incluir IPs conocidas por la tabla ARP aunque no respondan al ping",
    )
    parser.add_argument(
        "--format",
        choices=["table", "json", "csv"],
        default="table",
        help="Formato de salida (por defecto: table)",
    )

    args = parser.parse_args(argv)

    network: Optional[ipaddress.IPv4Network]
    if args.cidr:
        try:
            network = ipaddress.IPv4Network(args.cidr, strict=False)
        except Exception:
            print("Error: CIDR inválido. Ejemplo: 192.168.1.0/24", file=sys.stderr)
            return 2
    else:
        network = autodetect_network()
        if not network:
            print("No se pudo detectar la red automáticamente. Especifique --cidr.", file=sys.stderr)
            return 2

    responding_ips = scan_network_with_ping(network, args.timeout, args.workers)
    arp_map = collect_arp_entries() if args.include_arp else {}

    all_ips: Set[str] = set(responding_ips)
    if args.include_arp:
        all_ips.update(ip for ip in arp_map.keys() if ip in network)

    rows: List[Tuple[str, Optional[str], Optional[str]]] = []
    for ip in sorted(all_ips, key=lambda s: tuple(int(x) for x in s.split('.'))):
        mac = arp_map.get(ip)
        hostname: Optional[str] = None
        if not args.no_dns:
            hostname = reverse_dns_lookup(ip)
        rows.append((ip, mac, hostname))

    if args.format == "json":
        output = []
        for ip, mac, host in rows:
            output.append({"ip": ip, "mac": mac, "hostname": host})
        print(json.dumps(output, indent=2, ensure_ascii=False))
    elif args.format == "csv":
        print(format_as_csv(rows))
    else:
        print(format_as_table(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

