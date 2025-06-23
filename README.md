# IPSet

A comprehensive IP address categorization and lookup tool that collects addresses from VPN providers, Tor exit nodes, datacenter ASNs, and known proxy lists. Built for security researchers and network administrators who need to quickly identify and categorize IP addresses.

**Key Features:**
- ✅ Fast IP categorization and lookup
- ✅ Sources from 7+ VPN providers
- ✅ Includes Tor exit nodes
- ✅ Datacenter/hosting ASN identification 
- ✅ Multiple optimized output formats
- ✅ Support for both IPv4 and IPv6

## JSON Files

This repository generates and uses five JSON files:

1. **ipset.json**: The primary dataset containing mappings from group names to lists of IP addresses and CIDR ranges. Groups include:
   - Tor exit nodes
   - VPN providers (ExpressVPN, Surfshark, ProtonVPN, TunnelBear, Private-Internet-Access, CyberGhost, Mullvad)
   - Awesome-Proxies list
   - StopForumSpam
   - Firehol-Level1 (CIDRs)
   - Firehol-Proxies
   - Datacenter (CIDRs)

2. **iplookup.json**: An inverse mapping of the data in `ipset.json` for faster O(1) lookups.

3. **iplist.json**: A flat list of all IP addresses without any group information.

4. **iplist.txt**: A text file version of the flat list for easy integration with other tools.

5. **datacenter_asns.json**: A list of Autonomous System Numbers (ASNs) associated with datacenters and hosting providers.

## Usage

### Installing and Running

Install the dependencies:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Run the following command to generate the JSON files:

```bash
python main.py
```

### Creating the Optimized Lookup Structure

The `iplookup.json` file is automatically created when running `main.py`. This creates an inverse mapping of the data in `ipset.json` for faster O(1) lookups.

```python
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
```

### Searching for IP Group Membership

You can use the following functions to check which groups an IP belongs to:

```python
import json
from typing import List
from netaddr import IPAddress, IPNetwork

def search_ip_in_ipset(ip: str, ipset_file: str = "ipset.json") -> List[str]:
    """
    Search for an IP address in the ipset.json file and return all groups it belongs to.
    This is slower as it has to iterate through all groups and their IP lists.
    Supports both direct IP matches and CIDR range matches.

    Args:
        ip: The IP address to search for
        ipset_file: Path to the ipset.json file

    Returns:
        List of group names that contain the IP address
    """
    try:
        with open(ipset_file, "r", encoding="utf-8") as f:
            group_to_ips = json.load(f)

        ip_obj = IPAddress(ip)
        ip_version = ip_obj.version
        matching_groups = []
        for group, ips in group_to_ips.items():
            for ip_or_cidr in ips:
                if "/" in ip_or_cidr:
                    cidr = IPNetwork(ip_or_cidr)
                    if cidr.version != ip_version:
                        continue

                    ip_int = int(ip_obj)
                    net_int = int(cidr.network)
                    prefix_len = cidr.prefixlen

                    if ip_version == 4:
                        mask = ((1 << 32) - 1) ^ ((1 << (32 - prefix_len)) - 1)
                    else:
                        mask = ((1 << 128) - 1) ^ ((1 << (128 - prefix_len)) - 1)

                    if (ip_int & mask) != (net_int & mask):
                        continue

                    if ip_obj in cidr:
                        matching_groups.append(group)
                        break
                elif ip == ip_or_cidr:
                    matching_groups.append(group)
                    break

        return matching_groups
    except Exception as e:
        print(f"Error searching for IP in ipset.json: {e}")
        return []


def search_ip_in_lookup(ip: str, lookup_file: str = "iplookup.json") -> List[str]:
    """
    Search for an IP address in the iplookup.json file and return all groups it belongs to.
    This checks for direct IP matches and also if the IP is contained within any CIDR ranges.

    Args:
        ip: The IP address to search for
        lookup_file: Path to the iplookup.json file

    Returns:
        List of group names that contain the IP address
    """
    try:
        with open(lookup_file, "r", encoding="utf-8") as f:
            ip_to_groups = json.load(f)

        matching_groups = ip_to_groups.get(ip, [])

        ip_obj = IPAddress(ip)
        ip_version = ip_obj.version
        for ip_or_cidr, groups in ip_to_groups.items():
            if "/" in ip_or_cidr:
                cidr = IPNetwork(ip_or_cidr)
                if cidr.version != ip_version:
                    continue

                ip_int = int(ip_obj)
                net_int = int(cidr.network)
                prefix_len = cidr.prefixlen

                if ip_version == 4:
                    mask = ((1 << 32) - 1) ^ ((1 << (32 - prefix_len)) - 1)
                else:
                    mask = ((1 << 128) - 1) ^ ((1 << (128 - prefix_len)) - 1)

                if (ip_int & mask) != (net_int & mask):
                    continue

                if ip_obj in cidr:
                    for group in groups:
                        if group not in matching_groups:
                            matching_groups.append(group)

        return matching_groups
    except Exception as e:
        print(f"Error searching for IP in iplookup.json: {e}")
        return []
```

### Searching for IP Group Membership (Optimized)

This is a more optimized way to search for IP group membership. It uses a dictionary of IP addresses and their groups, and a dictionary of CIDR ranges and their groups. It loads the data into memory and then uses the dictionary to search for the IP address.

Output:
```
IP: 8.8.4.4
  Time taken: 0.06616806983947754 seconds
  Groups: ['Datacenter']

IP: 185.220.101.33
  Time taken: 0.06744527816772461 seconds
  Groups: ['TorExitNodes', 'StopForumSpam']

IP: 76.240.243.24
  Time taken: 0.06687688827514648 seconds
  Groups: None
```

Example:
```python
import json
import time
from typing import List, Dict, Tuple
from netaddr import IPAddress, IPNetwork


def load_ip_file(
    lookup_file: str = "ipset.json",
) -> Tuple[Dict[str, List[str]], Dict[IPNetwork, List[str]]]:
    """Load the lookup IP file into a dictionary."""
    try:
        with open(lookup_file, "r", encoding="utf-8") as f:
            data = json.load(f)

            ip_to_groups: Dict[str, List[str]] = {}
            cidrs_to_ips: Dict[IPNetwork, List[str]] = {}

            for group, ips in data.items():
                for ip in ips:
                    if "/" in ip:
                        ip_obj = IPNetwork(ip)
                        if ip_obj not in cidrs_to_ips:
                            cidrs_to_ips[ip_obj] = []
                        cidrs_to_ips[ip_obj].append(group)
                        continue

                    if ip not in ip_to_groups:
                        ip_to_groups[ip] = []
                    ip_to_groups[ip].append(group)

            return ip_to_groups, cidrs_to_ips
    except Exception as e:
        print(f"Error loading lookup IP file: {e}")
        return {}, {}


def search_ip_in_lookup(
    ip: str, ips: Dict[str, List[str]], cidrs: Dict[IPNetwork, List[str]]
) -> List[str]:
    """
    Search for an IP address in the iplookup.json file and return all groups it belongs to.
    This checks for direct IP matches and also if the IP is contained within any CIDR ranges.

    Args:
        ip: The IP address to search for
        ips: The dictionary of IP addresses and their groups

    Returns:
        List of group names that contain the IP address
    """
    try:
        matching_groups = ips.get(ip, [])

        ip_obj = IPAddress(ip)
        ip_version = ip_obj.version

        for cidr, groups in cidrs.items():
            if cidr.version != ip_version:
                continue

            ip_int = int(ip_obj)
            net_int = int(cidr.network)
            prefix_len = cidr.prefixlen

            if ip_version == 4:
                mask = ((1 << 32) - 1) ^ ((1 << (32 - prefix_len)) - 1)
            else:
                mask = ((1 << 128) - 1) ^ ((1 << (128 - prefix_len)) - 1)

            if (ip_int & mask) != (net_int & mask):
                continue

            if ip_obj in cidr:
                for group in groups:
                    if group not in matching_groups:
                        matching_groups.append(group)

        return matching_groups
    except Exception as e:
        print(f"Error searching for IP in iplookup.json: {e}")
        return []


if __name__ == "__main__":
    ips, cidrs = load_ip_file()
    for ip in [
        "8.8.4.4",  # Google DNS (datacenter)
        "185.220.101.33",  # Known Tor exit node
        "76.240.243.24",  # Typical residential IP
    ]:
        print(f"IP: {ip}")
        start_time = time.time()
        groups = search_ip_in_lookup(ip, ips, cidrs)
        end_time = time.time()
        print(f"  Time taken: {end_time - start_time} seconds")
        print(f"  Groups: {groups if groups else 'None'}\n")
```

### Working with Datacenter ASNs

> [!NOTE]
> This can be deprecated since the datacenter CIDRs are already in the `ipset.json` file.
> This is only useful if you want to check if an ASN belongs to a datacenter.
> For normal IP lookups, you should use the `ipset.json` or `iplookup.json` files.

The `datacenter_asns.json` file contains a list of ASNs (Autonomous System Numbers) associated with datacenter and hosting providers. You can use this list to identify traffic coming from non-residential sources.

Here's an example of how to efficiently check if an ASN belongs to a datacenter:

```python
import json

def load_datacenter_asns(asn_file: str = "datacenter_asns.json") -> set:
    """Load datacenter ASNs into a set for O(1) lookups."""
    try:
        with open(asn_file) as f:
            return set(json.load(f))
    except Exception as e:
        print(f"Error loading ASNs: {e}")
        return set()

def is_datacenter_asn(asn: str, asns: set = None) -> bool:
    """Check if ASN belongs to a datacenter."""
    if not asns:
        asns = load_datacenter_asns()
    return asn.replace("AS", "") in asns

if __name__ == "__main__":
    asns = load_datacenter_asns()
    for asn in ["AS16509", "AS14618"]:  # Amazon, Cloudflare
        print(f"{asn} is{' not' if not is_datacenter_asn(asn, asns) else ''} a datacenter ASN")
```

## License
Copyright 2025 TN3W

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.