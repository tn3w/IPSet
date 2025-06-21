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
from typing import List, Dict
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
        with open(ipset_file, 'r', encoding='utf-8') as f:
            group_to_ips = json.load(f)

        ip_obj = IPAddress(ip)
        matching_groups = []
        for group, ips in group_to_ips.items():
            for ip_or_cidr in ips:
                if '/' in ip_or_cidr:
                    if ip_obj in IPNetwork(ip_or_cidr):
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
        with open(lookup_file, 'r', encoding='utf-8') as f:
            ip_to_groups = json.load(f)
        
        matching_groups = ip_to_groups.get(ip, [])

        ip_obj = IPAddress(ip)
        for ip_or_cidr, groups in ip_to_groups.items():
            if '/' in ip_or_cidr:
                if ip_obj in IPNetwork(ip_or_cidr):
                    for group in groups:
                        if group not in matching_groups:
                            matching_groups.append(group)

        return matching_groups
    except Exception as e:
        print(f"Error searching for IP in iplookup.json: {e}")
        return []
```

Example:
```python
import json

def load_lookup_ip_file(lookup_file: str = "iplookup.json") -> Dict[str, List[str]]:
    """Load the lookup IP file into a dictionary."""
    try:
        with open(lookup_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading lookup IP file: {e}")


def search_ip_in_lookup(ip: str, ips: Dict[str, List[str]]) -> List[str]:
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
        for ip_or_cidr, groups in ips.items():
            if '/' in ip_or_cidr:
                if ip_obj in IPNetwork(ip_or_cidr):
                    for group in groups:
                        if group not in matching_groups:
                            matching_groups.append(group)

        return matching_groups
    except Exception as e:
        print(f"Error searching for IP in iplookup.json: {e}")
        return []


if __name__ == "__main__":
    ips = load_lookup_ip_file()
    for ip in [
        "1.1.1.1",         # Cloudflare DNS (datacenter)
        "185.220.101.33",  # Known Tor exit node
        "45.95.169.255",   # Typically a VPN IP
        "104.28.255.97",   # Cloudflare proxy
        "76.240.243.24",   # Typical residential IP
        "2a03:2880:f12f:83:face:b00c:0:25de"  # Facebook's IPv6 (datacenter)
    ]:
        print(f"IP: {ip}")
        groups = search_ip_in_lookup(ip)
        print(f"  Groups: {groups if groups else 'None'}\n")
```

### Working with Datacenter ASNs

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