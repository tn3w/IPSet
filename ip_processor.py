#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import re
import csv
import socket
import zipfile
import urllib.request
from io import StringIO, BytesIO
from typing import Dict, List, Set, Tuple
from concurrent.futures import ThreadPoolExecutor
from netaddr import IPAddress
import dns.resolver

OUTPUT_FILE = "ipset.json"
LOOKUP_FILE = "iplookup.json"

DATASETS = {
    "Tor-Exit-Nodes": "https://onionoo.torproject.org/details?flag=exit",
    "NordVPN-Servers": "https://api.nordvpn.com/v1/servers?limit=10000",
    "ProtonVPN-Servers": (
        "https://raw.githubusercontent.com/tn3w/ProtonVPN-IPs/refs/heads/master/protonvpn_ips.json",
    ),
    "ExpressVPN-Servers": (
        "https://raw.githubusercontent.com/sudesh0sudesh/ExpressVPN-IPs"
        "/refs/heads/main/express_ips.csv",
    ),
    "Surfshark-Servers": (
        "https://raw.githubusercontent.com/sudesh0sudesh/surfshark-IPs"
        "/refs/heads/main/surfshark_ips.csv",
    ),
    "Surfshark-Hostnames": "https://surfshark.com/api/v1/server/configurations",
    "Private-Internet-Access-Servers": "https://serverlist.piaservers.net/vpninfo/servers/v6",
    "CyberGhost-Servers": (
        "https://gist.githubusercontent.com/Windows81/17e75698d4fe349bcfb71d1c1ca537d4"
        "/raw/88713feecd901acaa03b3805b7ac1ab19ada73b2/.txt",
    ),
    "TunnelBear-Servers": (
        "https://raw.githubusercontent.com/tn3w/TunnelBear-IPs"
        "/refs/heads/master/tunnelbear_ips.json",
    ),
    "Mullvad": "https://api.mullvad.net/www/relays/all",
    "Firehol-Proxies": "https://iplists.firehol.org/files/firehol_proxies.netset",
    "Awesome-Lists-Proxies": (
        "https://raw.githubusercontent.com/mthcht/awesome-lists/refs/heads/main"
        "/Lists/PROXY/ALL_PROXY_Lists.csv",
    ),
    "StopForumSpam": "http://www.stopforumspam.com/downloads/listed_ip_90.zip",
}


def download_file(url: str, source_name: str) -> bytes:
    """
    Download a file from a URL and return its content as bytes.
    """
    try:
        print(f"Downloading {source_name} from {url}...")
        response = urllib.request.urlopen(url)
        content = response.read()
        print(f"Downloaded {source_name}")
        return content
    except Exception as e:
        print(f"Error downloading {source_name}: {e}")
        return b""


def extract_ipv4(addr: str) -> str:
    """Extract IPv4 address from a string that may include a port."""
    parts = addr.split(":")
    return parts[0]


def extract_ipv6(addr: str) -> str:
    """
    Extract IPv6 address from a string that may include brackets and port.
    Returns the address in its full expanded form using netaddr.
    """
    if addr.startswith("["):
        end_bracket = addr.find("]")
        if end_bracket != -1:
            addr = addr[1:end_bracket]
    else:
        parts = addr.split(":")
        if len(parts) > 2 and parts[-2].isdigit() and parts[-1].isdigit():
            addr = ":".join(parts[:-1])

    try:
        return str(IPAddress(addr, version=6))
    except Exception:
        return addr


def resolve_hostname(hostname: str) -> Tuple[str, List[str]]:
    """
    Resolve a hostname to IP addresses using both socket and DNS lookups.
    """
    ips = set()

    try:
        info = socket.getaddrinfo(hostname, None, socket.AF_INET)
        for _, _, _, _, addr in info:
            ips.add(addr[0])

        info = socket.getaddrinfo(hostname, None, socket.AF_INET6)
        for _, _, _, _, addr in info:
            ips.add(str(IPAddress(addr[0], version=6)))
    except Exception as e:
        print(f"Socket error resolving {hostname}: {e}")

    try:
        answers = dns.resolver.resolve(hostname, "A")
        for rdata in answers:
            ips.add(str(rdata))
    except Exception as e:
        print(f"DNS error resolving A records for {hostname}: {e}")

    try:
        answers = dns.resolver.resolve(hostname, "AAAA")
        for rdata in answers:
            ips.add(str(IPAddress(str(rdata), version=6)))
    except Exception as e:
        print(f"DNS error resolving AAAA records for {hostname}: {e}")

    return hostname, list(ips)


def process_tor_exit_nodes(data: bytes) -> List[str]:
    """Process Tor exit node data and return list of IPs."""
    try:
        data = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        print(f"Error loading Tor exit node data: {e}")
        return []

    tor_nodes: Set[str] = set()

    if "relays" not in data:
        print("No 'relays' found in the Tor exit node data")
        return []

    for relay in data["relays"]:
        for field in ["exit_addresses", "or_addresses"]:
            for addr in relay.get(field, []):
                if ":" in addr and addr.count(":") > 1 or addr.startswith("["):
                    ipv6 = extract_ipv6(addr)
                    if ipv6:
                        tor_nodes.add(ipv6)
                else:
                    ipv4 = extract_ipv4(addr)
                    if ipv4:
                        tor_nodes.add(ipv4)

    return list(tor_nodes)


def process_nordvpn_servers(data: bytes) -> List[str]:
    """Process NordVPN server data and return list of IPs."""
    try:
        data = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        print(f"Error loading NordVPN server data: {e}")
        return []

    station_ips: Set[str] = set()

    for server in data:
        if "station" in server and server["station"]:
            station_ips.add(server["station"])

        if "ipv6_station" in server and server["ipv6_station"]:
            try:
                ipv6 = str(IPAddress(server["ipv6_station"], version=6))
                station_ips.add(ipv6)
            except Exception:
                if server["ipv6_station"]:
                    station_ips.add(server["ipv6_station"])

    return list(station_ips)


def process_sudesh0sudesh_servers(data: bytes) -> List[str]:
    """Process ExpressVPN or Surfshark server data and return list of IPs."""
    try:
        ip_addresses: List[str] = []
        csv_data = StringIO(data.decode("utf-8"))

        csv_reader = csv.reader(csv_data)
        next(csv_reader, None)
        for row in csv_reader:
            if row and len(row) > 0:
                ip_addresses.append(row[0])

        return ip_addresses
    except (UnicodeDecodeError, csv.Error) as e:
        print(f"Error processing server data: {e}")
        return []


def process_protonvpn_tunnelbear_servers(data: bytes) -> List[str]:
    """Process ProtonVPN or TunnelBear server data and return list of IPs."""
    try:
        data = json.loads(data.decode("utf-8"))
        return data
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        print(f"Error loading server data: {e}")
        return []


def extract_surfshark_remote_addresses(configs: Dict[str, str]) -> Set[str]:
    """Extract all unique remote addresses from OpenVPN configuration files."""
    remote_addresses: Set[str] = set()

    for _, content in configs.items():
        matches = re.findall(r"remote\s+([^\s]+)\s+\d+", content)
        if matches:
            remote_addresses.update(matches)

    return remote_addresses


def process_surfshark_hostnames(url: str) -> List[str]:
    """Download Surfshark configuration and extract IPs from hostnames."""
    try:
        response = urllib.request.urlopen(url)
        zip_data = BytesIO(response.read())

        configs: Dict[str, str] = {}
        with zipfile.ZipFile(zip_data) as zip_file:
            for filename in zip_file.namelist():
                if filename.endswith(".ovpn"):
                    with zip_file.open(filename) as file:
                        content = file.read().decode("utf-8", errors="replace")
                        configs[filename] = content

        if not configs:
            print("Error processing Surfshark configurations")
            return []

        remote_addresses = extract_surfshark_remote_addresses(configs)

        all_ips: Set[str] = set()
        with ThreadPoolExecutor(max_workers=20) as executor:
            results = list(executor.map(resolve_hostname, remote_addresses))

        for _, ips in sorted(results):
            if not ips:
                continue
            all_ips.update(ips)

        return list(all_ips)
    except Exception as e:
        print(f"Error processing Surfshark data: {e}")
        return []


def process_pia_servers(data: bytes) -> List[str]:
    """Process PIA server data and return list of IPs."""
    try:
        content = data.decode("utf-8")
        last_bracket_index = content.rfind("}")
        if last_bracket_index != -1:
            valid_json = content[: last_bracket_index + 1]
            data = json.loads(valid_json)
        else:
            print("No valid JSON structure found in PIA data")
            return []

        ip_addresses: Set[str] = set()

        if "regions" in data:
            for region in data["regions"]:
                if "servers" in region:
                    for _, servers in region["servers"].items():
                        for server in servers:
                            if "ip" in server:
                                if ":" in server["ip"]:
                                    try:
                                        ipv6 = str(IPAddress(server["ip"], version=6))
                                        ip_addresses.add(ipv6)
                                    except Exception:
                                        ip_addresses.add(server["ip"])
                                else:
                                    ip_addresses.add(server["ip"])

        return list(ip_addresses)
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        print(f"Error processing PIA server data: {e}")
        return []


def process_cyberghost_servers(data: bytes) -> List[str]:
    """Process Cyberghost server data and return list of IPs."""
    try:
        ip_addresses: Set[str] = set()
        content = data.decode("utf-8").splitlines()

        for line in content:
            if not line.strip():
                continue

            parts = line.strip().split()
            if parts:
                ip = parts[0].strip()

                if ":" in ip and ip.count(":") > 1:
                    try:
                        ip = str(IPAddress(ip, version=6))
                    except Exception:
                        pass

                ip_addresses.add(ip)

        return list(ip_addresses)
    except UnicodeDecodeError as e:
        print(f"Error processing Cyberghost server data: {e}")
        return []


def process_mullvad_servers(data: bytes) -> List[str]:
    """Process Mullvad server data and return list of IPs."""
    try:
        data = json.loads(data.decode("utf-8"))

        ip_addresses: Set[str] = set()

        for server in data:
            if "ipv4_addr_in" in server and server["ipv4_addr_in"]:
                ip_addresses.add(server["ipv4_addr_in"])

            if "ipv6_addr_in" in server and server["ipv6_addr_in"]:
                try:
                    ipv6 = str(IPAddress(server["ipv6_addr_in"], version=6))
                    ip_addresses.add(ipv6)
                except Exception:
                    if server["ipv6_addr_in"]:
                        ip_addresses.add(server["ipv6_addr_in"])

        return list(ip_addresses)
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        print(f"Error processing Mullvad server data: {e}")
        return []


def process_firehol_proxies(data: bytes) -> List[str]:
    """Process FireHOL proxies database and return list of IPs."""
    try:
        ip_addresses: List[str] = []
        content = data.decode("utf-8").splitlines()

        for line in content:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if "/" not in line:
                ip_addresses.append(line)

        return ip_addresses
    except UnicodeDecodeError as e:
        print(f"Error processing FireHOL proxies database: {e}")
        return []


def process_awesome_lists_proxies(data: bytes) -> List[str]:
    """Process Awesome Lists proxies data and return list of IPs."""
    try:
        ip_addresses: Set[str] = set()
        csv_data = StringIO(data.decode("utf-8"))

        csv_reader = csv.reader(csv_data)
        for row in csv_reader:
            if not row:
                continue

            potential_ip = row[0].strip()
            if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", potential_ip):
                ip_addresses.add(potential_ip)

        return list(ip_addresses)
    except (UnicodeDecodeError, csv.Error) as e:
        print(f"Error processing Awesome Lists proxies database: {e}")
        return []


def process_stopforumspam(data: bytes) -> List[str]:
    """Process StopForumSpam IP list from zip file and return list of IPs."""
    try:
        ip_addresses: Set[str] = set()
        zip_data = BytesIO(data)

        with zipfile.ZipFile(zip_data) as zip_file:
            with zip_file.open("listed_ip_90.txt") as file:
                for line in file:
                    ip = line.decode("utf-8").strip()
                    if ip:
                        ip_addresses.add(ip)

        print(f"Extracted {len(ip_addresses)} IPs from StopForumSpam list")
        return list(ip_addresses)
    except Exception as e:
        print(f"Error processing StopForumSpam data: {e}")
        return []


def sort_ip_addresses(ip_addresses: List[str]) -> List[str]:
    """
    Sort IP addresses with IPv4 first, then IPv6.
    All IPv6 addresses should be in their long form.
    """
    ipv4_addresses = []
    ipv6_addresses = []

    for ip in ip_addresses:
        if ":" in ip:
            try:
                ipv6 = str(IPAddress(ip, version=6))
                ipv6_addresses.append(ipv6)
            except Exception:
                ipv6_addresses.append(ip)
        else:
            ipv4_addresses.append(ip)

    ipv4_addresses.sort()
    ipv6_addresses.sort()

    return ipv4_addresses + ipv6_addresses


def ensure_directory_exists(directory: str) -> None:
    """Create directory if it doesn't exist."""
    if not os.path.exists(directory):
        os.makedirs(directory)
        print(f"Created directory: {directory}")


def process_dataset(source_name: str, data: bytes) -> List[str]:
    """Process a dataset based on source name and return list of IPs."""
    print(f"Processing {source_name}...")

    processors = {
        "Tor-Exit-Nodes": process_tor_exit_nodes,
        "NordVPN-Servers": process_nordvpn_servers,
        "ExpressVPN-Servers": process_sudesh0sudesh_servers,
        "Surfshark-Servers": process_sudesh0sudesh_servers,
        "ProtonVPN-Servers": process_protonvpn_tunnelbear_servers,
        "TunnelBear-Servers": process_protonvpn_tunnelbear_servers,
        "Surfshark-Hostnames": lambda _: process_surfshark_hostnames(
            DATASETS["Surfshark-Hostnames"]
        ),
        "Private-Internet-Access-Servers": process_pia_servers,
        "CyberGhost-Servers": process_cyberghost_servers,
        "Mullvad": process_mullvad_servers,
        "Firehol-Proxies": process_firehol_proxies,
        "Awesome-Lists-Proxies": process_awesome_lists_proxies,
        "StopForumSpam": process_stopforumspam,
    }

    if source_name in processors:
        return processors[source_name](data)

    print(f"Unknown dataset source: {source_name}")
    return []


def create_ip_lookup_file(group_to_ips: Dict[str, List[str]]) -> None:
    """
    Create a more efficient lookup structure where keys are IPs and values are lists of groups.
    This makes it easy to determine which groups an IP belongs to.
    """
    print("Creating IP lookup file...")
    ip_to_groups: Dict[str, List[str]] = {}

    for group, ips in group_to_ips.items():
        for ip in ips:
            if ip not in ip_to_groups:
                ip_to_groups[ip] = []
            ip_to_groups[ip].append(group)

    with open(LOOKUP_FILE, "w", encoding="utf-8") as json_file:
        json.dump(ip_to_groups, json_file)

    print(f"Successfully created {LOOKUP_FILE} with {len(ip_to_groups)} unique IPs")


def main():
    """Main function to process all datasets and create the ipset.json file."""
    result_dict = {}

    for source_name, url in DATASETS.items():
        data = download_file(url, source_name)

        ip_list = process_dataset(source_name, data)

        sorted_ip_list = sort_ip_addresses(ip_list)

        key = source_name.replace("-", "")
        result_dict[key] = sorted_ip_list

        print(f"Processed {len(sorted_ip_list)} IPs for {source_name}")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as json_file:
        json.dump(result_dict, json_file)

    print(f"Successfully created {OUTPUT_FILE}")
    create_ip_lookup_file(result_dict)


if __name__ == "__main__":
    main()
