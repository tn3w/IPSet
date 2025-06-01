#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import csv
import unicodedata
import urllib.request
from io import StringIO
from typing import Dict, List, Any, Iterator, Optional

CONTINENT_NAME_TO_CODE = {
    "Africa": "AF",
    "Antarctica": "AN",
    "Asia": "AS",
    "Europe": "EU",
    "North America": "NA",
    "Oceania": "OC",
    "South America": "SA",
}

CONTINENT_NAME_TO_NORMALIZED_NAME = {
    "Northern America": "North America",
    "Southern Europe": "Europe",
    "Northern Europe": "Europe",
    "Western Europe": "Europe",
    "Eastern Europe": "Europe",
    "Central Europe": "Europe",
    "Southern Asia": "Asia",
    "Central Asia": "Asia",
    "South-Eastern Asia": "Asia",
    "Eastern Asia": "Asia",
    "Western Asia": "Asia",
    "Northern Africa": "Africa",
    "Eastern Africa": "Africa",
    "Western Africa": "Africa",
    "Southern Africa": "Africa",
    "Middle Africa": "Africa",
    "Australia and New Zealand": "Oceania",
    "Melanesia": "Oceania",
    "Micronesia": "Oceania",
    "Polynesia": "Oceania",
    "Caribbean": "North America",
    "Central America": "North America",
    "South America": "South America",
}

GEO_DATASETS = {
    "Countries-States-Cities": (
        "https://raw.githubusercontent.com/dr5hn/countries-states-cities-database/refs/heads/master/json/countries%2Bstates%2Bcities.json",
        "countries_states_cities.json",
    ),
    "Zip-Codes": (
        "https://raw.githubusercontent.com/wouterdebie/zip_codes_plus/refs/heads/main/data/zip_codes.csv",
        "zip_codes.json",
    ),
}


def get_normalized_continent_name(subregion: str) -> str:
    """
    Get normalized continent name from subregion.

    Args:
        subregion: The subregion name

    Returns:
        The normalized continent name
    """
    return CONTINENT_NAME_TO_NORMALIZED_NAME.get(subregion, subregion)


def download_data(url: str) -> Optional[bytes]:
    """
    Download data from URL and return it as bytes.

    Args:
        url: The URL to download from

    Returns:
        The downloaded data as bytes, or None if download failed
    """
    try:
        print(f"Downloading from {url}...")
        response = urllib.request.urlopen(url)
        content = response.read()
        print(f"Successfully downloaded data from {url}")
        return content
    except Exception as e:
        print(f"Error downloading data: {e}")
        return None


def process_countries_states_cities_data(data: bytes) -> Dict[str, Dict[str, Any]]:
    """
    Process the countries-states-cities data from bytes.

    Args:
        data: Raw JSON data as bytes

    Returns:
        Processed countries data dictionary
    """
    try:
        countries_data = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        print(f"Error loading country data: {e}")
        return {}

    result: Dict[str, Dict[str, Any]] = {}

    for country in countries_data:
        iso2 = country.get("iso2")
        if not iso2:
            continue

        region = country.get("region", "")
        subregion = country.get("subregion", "")

        if region and region in CONTINENT_NAME_TO_CODE:
            processed_region = region
        elif subregion in CONTINENT_NAME_TO_NORMALIZED_NAME:
            processed_region = get_normalized_continent_name(subregion)
        else:
            processed_region = region

        timezones = country.get("timezones", [])
        timezone: Dict[str, Any] = {}
        if timezones and len(timezones) > 0:
            first_timezone = timezones[0]
            timezone = {
                "name": first_timezone.get("zoneName", ""),
                "offset": first_timezone.get("gmtOffset", 0),
            }

        processed_states: List[Dict[str, Any]] = []
        for state in country.get("states", []):
            processed_cities: List[str] = []

            for city in state.get("cities", []):
                city_name = city.get("name", "")
                if city_name:
                    normalized_name = unicodedata.normalize("NFKD", city_name)
                    normalized_name = "".join(
                        [c for c in normalized_name if not unicodedata.combining(c)]
                    )
                    processed_cities.append(normalized_name)

            processed_states.append(
                {
                    "name": state.get("name", ""),
                    "state_code": state.get("state_code", ""),
                    "cities": processed_cities,
                }
            )

        result[iso2] = {
            "name": country.get("name", ""),
            "region": processed_region,
            "timezone": timezone,
            "states": processed_states,
        }

    return result


def process_zip_codes_data(data: bytes) -> Dict[str, str]:
    """
    Process ZIP codes CSV data from bytes and convert it to a more efficient format for lookups.

    Args:
        data: Raw CSV data as bytes

    Returns:
        Processed zip codes data dictionary
    """
    try:
        decoded_data = data.decode("utf-8")
        csv_data = StringIO(decoded_data)

        csv_reader: Iterator[List[str]] = csv.reader(csv_data)

        next(csv_reader, None)

        zip_codes_data: Dict[str, str] = {}

        for row in csv_reader:
            if len(row) < 4:
                continue

            zip_code = row[0].strip()
            city = row[2].strip()
            state = row[3].strip()

            if not city or not state:
                continue

            city_upper = city.upper()
            state_upper = state.upper()
            key = f"{city_upper}|{state_upper}"

            if key not in zip_codes_data or (len(zip_code) < len(zip_codes_data[key])):
                zip_codes_data[key] = zip_code

        return zip_codes_data
    except (UnicodeDecodeError, csv.Error) as e:
        print(f"Error processing ZIP codes data: {e}")
        return {}


def save_json_data(data: Dict, output_file: str) -> None:
    """
    Save data to a JSON file.

    Args:
        data: The data to save
        output_file: The path to save the data to
    """
    try:
        with open(output_file, "w", encoding="utf-8") as file:
            json.dump(data, file, ensure_ascii=False)
        print(f"Successfully saved data to {output_file}")
    except IOError as e:
        print(f"Error saving data to {output_file}: {e}")


def main():
    """Main function to download, process, and save all geo datasets."""
    for dataset_name, (url, output_file) in GEO_DATASETS.items():
        data = download_data(url)

        if data is None:
            print(f"Failed to download {dataset_name}, skipping processing")
            continue

        if dataset_name == "Countries-States-Cities":
            processed_data = process_countries_states_cities_data(data)
            if processed_data:
                save_json_data(processed_data, output_file)
                print(
                    f"Successfully processed countries-states-cities data to {output_file}"
                )
        elif dataset_name == "Zip-Codes":
            processed_data = process_zip_codes_data(data)
            if processed_data:
                save_json_data(processed_data, output_file)
                print(f"Successfully processed ZIP codes data to {output_file}")


if __name__ == "__main__":
    main()
