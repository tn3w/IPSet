#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import concurrent.futures
import csv
import json
import os
import re
import socket
import urllib.error
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO, StringIO
from typing import Dict, Final, List, Set, Tuple
import time

from netaddr import IPAddress, IPNetwork, ipv6_compact
import dns.resolver

OUTPUT_FILE: Final[str] = "ipset.json"
LOOKUP_FILE: Final[str] = "iplookup.json"
IP_LIST_FILE: Final[str] = "iplist.json"
IP_LIST_TXT_FILE: Final[str] = "iplist.txt"
DATACENTER_ASNS_FILE: Final[str] = "datacenter_asns.json"

IP_LIST_TXT_HEADER: Final[str] = """#
# iplist.txt
# https://github.com/tn3w/IPSet/blob/master/iplist.txt
#
# This file contains a list of possible malicious IPs and CIDRs.
# This includes IPs from the following sources:
# - Tor-Exit-Nodes
# - VPN Providers (ExpressVPN, Surfshark, ProtonVPN, TunnelBear,
#                  Private-Internet-Access, CyberGhost, Mullvad)
# - Awesome Lists (Awesome-Proxies)
# - StopForumSpam
# - Firehol-Level1 (CIDRs)
# - Firehol-Proxies
# - Datacenter (CIDRs)
#
"""

DATASETS: Final[Dict[str, str]] = {
    "Tor-Exit-Nodes": "https://onionoo.torproject.org/details",
    "NordVPN": "https://api.nordvpn.com/v1/servers?limit=10000",
    "ProtonVPN": (
        "https://raw.githubusercontent.com/tn3w/ProtonVPN-IPs/"
        "refs/heads/master/protonvpn_ips.json"
    ),
    "ExpressVPN": (
        "https://raw.githubusercontent.com/sudesh0sudesh/ExpressVPN-IPs/"
        "refs/heads/main/express_ips.csv"
    ),
    "Surfshark-Servers": (
        "https://raw.githubusercontent.com/sudesh0sudesh/surfshark-IPs/"
        "refs/heads/main/surfshark_ips.csv"
    ),
    "Surfshark-Hostnames": "https://surfshark.com/api/v1/server/configurations",
    "Private-Internet-Access": "https://serverlist.piaservers.net/vpninfo/servers/v6",
    "CyberGhost": (
        "https://gist.githubusercontent.com/Windows81/17e75698d4fe349bcfb71d1c1ca537d4/"
        "raw/88713feecd901acaa03b3805b7ac1ab19ada73b2/.txt"
    ),
    "TunnelBear": (
        "https://raw.githubusercontent.com/tn3w/TunnelBear-IPs/"
        "refs/heads/master/tunnelbear_ips.json"
    ),
    "Mullvad": "https://api.mullvad.net/www/relays/all",
    "Firehol-Proxies": "https://iplists.firehol.org/files/firehol_proxies.netset",
    "Firehol-Level1": "https://iplists.firehol.org/files/firehol_level1.netset",
    "Awesome-Proxies": (
        "https://raw.githubusercontent.com/mthcht/awesome-lists/"
        "refs/heads/main/Lists/PROXY/ALL_PROXY_Lists.csv"
    ),
    "StopForumSpam": "http://www.stopforumspam.com/downloads/listed_ip_90.zip",
    "Datacenter": (
        "https://raw.githubusercontent.com/brianhama/bad-asn-list/"
        "refs/heads/master/bad-asn-list.csv"
    ),
}

TOR_EXIT_NODE_ASNS: Final[List[str]] = [
    "60729",
    "53667",
    "4224",
    "208323",
    "198093",
    "401401",
    "210731",
    "61125",
    "214503",
    "215125",
    "214094",
    "205100",
    "57860",
    "8283",
    "215659",
    "197648",
    "44925",
    "198985",
    "214996",
    "210083",
    "49770",
    "197422",
    "205235",
    "30893",
]


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
    Returns the address in its compressed form using netaddr.
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
        ip = IPAddress(addr, version=6)
        return str(ip)
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
    """Process FireHOL database and return list of IPs."""
    try:
        ip_addresses: List[str] = []
        content = data.decode("utf-8").splitlines()

        for line in content:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if "/" in line:
                try:
                    network = IPNetwork(line)
                    for ip in network:
                        ip_addresses.append(str(ip))
                except Exception as e:
                    print(f"Error processing FireHOL proxies database: {e}")
            else:
                ip_addresses.append(line)

        return ip_addresses
    except UnicodeDecodeError as e:
        print(f"Error processing FireHOL proxies database: {e}")
        return []


def process_firehol_level1(data: bytes) -> List[str]:
    """Process FireHOL database and return list of IPs."""
    try:
        ip_addresses: List[str] = []
        content = data.decode("utf-8").splitlines()

        for line in content:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

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


def get_ip_ranges_by_asn(asn: str) -> List[str]:
    """Retrieve IP ranges for a given ASN using RIPEstat API with retry logic"""
    asn_num = asn.replace("AS", "").strip()
    url = (
        f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn_num}"
    )

    for attempt in range(1, 4):
        try:
            with urllib.request.urlopen(url, timeout=20) as response:
                data = json.loads(response.read().decode("utf-8"))
                return (
                    [prefix["prefix"] for prefix in data["data"]["prefixes"]]
                    if data["status"] == "ok"
                    else []
                )
        except Exception as e:
            print(f"Error retrieving AS{asn_num} (attempt {attempt}/3): {e}")
            if attempt < 3:
                time.sleep(1)

    print(f"Failed to retrieve ranges for AS{asn_num} after 3 attempts")
    return []


def get_ip_ranges_by_asn_list(asns_list: List[str]) -> List[str]:
    """Get IP ranges for a list of ASNs."""
    cidrs = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_to_asn = {
            executor.submit(get_ip_ranges_by_asn, asn): asn for asn in asns_list
        }

        for i, future in enumerate(concurrent.futures.as_completed(future_to_asn), 1):
            asn = future_to_asn[future]
            try:
                ranges = future.result()
                cidrs.extend(ranges)

                if i % 10 == 0 or i == len(asns_list):
                    print(
                        f"Progress: {i}/{len(asns_list)} ASNs"
                        f" processed ({i/len(asns_list)*100:.1f}%)"
                    )
            except Exception as e:
                print(f"Error processing AS{asn}: {e}")

    print(f"Retrieved {len(cidrs)} IP ranges for {len(asns_list)} ASNs")

    return cidrs


def process_data_center_asns(data: bytes) -> Tuple[List[str], List[str]]:
    """
    Process Data Center ASNs database and return both list of ASNs and their IP ranges.

    Args:
        data: The downloaded CSV file content as bytes

    Returns:
        Tuple of (list of ASN strings, list of CIDR ranges)
    """
    try:
        asns: Set[str] = set()
        csv_data = StringIO(data.decode("utf-8"))

        csv_reader = csv.reader(csv_data)
        next(csv_reader, None)
        for row in csv_reader:
            if row and len(row) > 0:
                asn = row[0].strip()
                asns.add(asn)

        asns_list = list(asns)
        print(f"Retrieving IP ranges for {len(asns_list)} ASNs...")
        cidrs = get_ip_ranges_by_asn_list(asns_list)
    except (UnicodeDecodeError, csv.Error) as e:
        print(f"Error processing data center ASNs database: {e}")
        return [], []

    return list(asns), cidrs


def minify_ipv6_addresses(ip_addresses: List[str]) -> List[str]:
    """
    Minify IPv6 addresses to their compressed format.
    Handles both individual IPs and CIDR notation for IPv4 and IPv6.
    """
    result = []
    for ip in ip_addresses:
        try:
            if "/" in ip:
                ip_part, prefix = ip.split("/", 1)
                if ":" in ip_part:
                    compressed_ip = str(IPAddress(ip_part).format(dialect=ipv6_compact))
                    result.append(f"{compressed_ip}/{prefix}")
                else:
                    result.append(ip)
            else:
                if ":" in ip:
                    result.append(str(IPAddress(ip).format(dialect=ipv6_compact)))
                else:
                    result.append(ip)
        except Exception as e:
            print(f"Error processing IP {ip}: {e}")
            result.append(ip)
    return result


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
        "NordVPN": process_nordvpn_servers,
        "ExpressVPN": process_sudesh0sudesh_servers,
        "Surfshark-Servers": process_sudesh0sudesh_servers,
        "ProtonVPN": process_protonvpn_tunnelbear_servers,
        "TunnelBear": process_protonvpn_tunnelbear_servers,
        "Surfshark-Hostnames": lambda _: process_surfshark_hostnames(
            DATASETS["Surfshark-Hostnames"]
        ),
        "Private-Internet-Access": process_pia_servers,
        "CyberGhost": process_cyberghost_servers,
        "Mullvad": process_mullvad_servers,
        "Firehol-Proxies": process_firehol_proxies,
        "Firehol-Level1": process_firehol_level1,
        "Awesome-Proxies": process_awesome_lists_proxies,
        "StopForumSpam": process_stopforumspam,
    }

    if source_name in processors:
        return processors[source_name](data)

    print(f"Unknown dataset source: {source_name}")
    return []


def is_in_any_network(ip_chunk, networks):
    """
    Check if any of the networks contain the IP.
    """
    result = []
    networks = [IPNetwork(n) for n in networks]
    for ip in ip_chunk:
        if not any(IPAddress(ip) in network for network in networks):
            result.append(ip)
    return result


def create_flat_ip_list(group_to_ips: Dict[str, List[str]]) -> None:
    """
    Create a flat list of all unique IPs from all sources.
    IPv6 addresses are in compressed format.
    """
    print("Creating flat IP list...")
    unique_ips = set()

    for group, ips in group_to_ips.items():
        if group in ["FireholLevel1", "Datacenter"]:
            continue
        unique_ips.update(ips)

    unique_ips.update(group_to_ips["FireholLevel1"])

    print("Minifying IPv6 addresses...")
    sorted_ips = minify_ipv6_addresses(list(unique_ips))

    with open(IP_LIST_FILE, "w", encoding="utf-8") as json_file:
        json.dump(sorted_ips, json_file)

    with open(IP_LIST_TXT_FILE, "w", encoding="utf-8") as txt_file:
        txt_file.write(IP_LIST_TXT_HEADER)
        txt_file.write("\n".join(sorted_ips))

    print(f"Successfully created {IP_LIST_FILE} with {len(sorted_ips)} unique IPs")


def create_ip_lookup_file(group_to_ips: Dict[str, List[str]]) -> None:
    """
    Create a more efficient lookup structure where keys are IPs and values are lists of groups.
    Use this for an O(1) lookup when checking which groups an IP belongs to.
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
    surfshark_ips = set()

    for source_name, url in DATASETS.items():
        data = download_file(url, source_name)
        if source_name == "Datacenter":
            asns, cidrs = process_data_center_asns(data)
            with open(DATACENTER_ASNS_FILE, "w", encoding="utf-8") as json_file:
                json.dump(asns, json_file)
            result_dict["Datacenter"] = cidrs
            continue

        result = process_dataset(source_name, data)

        if source_name == "Tor-Exit-Nodes":
            result.extend(get_ip_ranges_by_asn_list(TOR_EXIT_NODE_ASNS))

        if source_name in ["Surfshark-Servers", "Surfshark-Hostnames"]:
            surfshark_ips.update(result)
            continue

        key = source_name.replace("-", "")
        result_dict[key] = minify_ipv6_addresses(result)
        print(f"Processed {len(result)} IPs for {source_name}")

    sorted_surfshark_ips = minify_ipv6_addresses(list(surfshark_ips))
    result_dict["Surfshark"] = sorted_surfshark_ips
    print(f"Processed {len(sorted_surfshark_ips)} IPs for Surfshark (combined)")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as json_file:
        json.dump(result_dict, json_file)

    print(f"Successfully created {OUTPUT_FILE}")

    create_flat_ip_list(result_dict)
    create_ip_lookup_file(result_dict)


if __name__ == "__main__":
    main()
