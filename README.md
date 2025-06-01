# IPSet

A collection of tools to build and query IP address sets from various sources including VPN providers, Tor exit nodes, and known proxy servers.

## JSON Files

This repository generates and uses five JSON files:

1. **ipset.json**: The primary dataset containing mappings from group names to lists of IP addresses. Groups include VPN providers (NordVPN, ExpressVPN, etc.), Tor exit nodes, and known proxies.

2. **iplookup.json**: An optimized lookup structure where keys are IP addresses and values are lists of groups they belong to. This file enables faster lookups when checking which groups an IP belongs to.

3. **firehol_level1.json**: An list of IP cidr ranges from firehol level 1.

4. **countries_states_cities.json**: Geographic data including countries, regions, states, and cities. Used for geolocation features.

5. **zip_codes.json**: Maps city and state combinations to ZIP codes for location-based filtering.

6. **datacenter_asns.json**: A list of Autonomous System Numbers (ASNs) associated with datacenters and hosting providers, often used to identify traffic from non-residential sources.

## Usage

### Generating the Files

Run the following scripts to generate the JSON files:

```bash
# Generate ipset.json, iplookup.json, and datacenter_asns.json
python ip_processor.py

# Generate countries_states_cities.json and zip_codes.json
python geo_processor.py
```

### Creating the Optimized Lookup Structure

The `iplookup.json` file is automatically created when running `ip_processor.py`. This creates an inverse mapping of the data in `ipset.json` for faster lookups:

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

def search_ip_in_ipset(ip: str, ipset_file: str = "ipset.json") -> List[str]:
    """
    Search for an IP address in the ipset.json file and return all groups it belongs to.
    This is slower as it has to iterate through all groups and their IP lists.
    
    Args:
        ip: The IP address to search for
        ipset_file: Path to the ipset.json file
        
    Returns:
        List of group names that contain the IP address
    """
    try:
        with open(ipset_file, 'r', encoding='utf-8') as f:
            group_to_ips = json.load(f)
            
        matching_groups = []
        for group, ips in group_to_ips.items():
            if ip in ips:
                matching_groups.append(group)
                
        return matching_groups
    except Exception as e:
        print(f"Error searching for IP in ipset.json: {e}")
        return []

def search_ip_in_lookup(ip: str, lookup_file: str = "iplookup.json") -> List[str]:
    """
    Search for an IP address in the iplookup.json file and return all groups it belongs to.
    This is much faster as it uses direct dictionary lookup.
    
    Args:
        ip: The IP address to search for
        lookup_file: Path to the iplookup.json file
        
    Returns:
        List of group names that contain the IP address
    """
    try:
        with open(lookup_file, 'r', encoding='utf-8') as f:
            ip_to_groups = json.load(f)
            
        return ip_to_groups.get(ip, [])
    except Exception as e:
        print(f"Error searching for IP in iplookup.json: {e}")
        return []
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

# Example:
asns = load_datacenter_asns()
for asn in ["AS16509", "AS14618"]:  # Amazon, Cloudflare
    print(f"{asn} is{' not' if not is_datacenter_asn(asn, asns) else ''} a datacenter ASN")
```

This approach loads the ASNs into memory as a set, which provides O(1) lookup time complexity, making it extremely efficient for repeated lookups.

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