"""Write a small country database for PowerDNS's geoip backend.

Production uses DB-IP Lite (not in git, CC BY 4.0). The simulation only needs
country() and continent() to pick an edge (East Asia and Oceania go to
edge-asia, everyone else to edge-th), so this marks a few ranges per region,
in the same MaxMind DB format.

    python3 make_geo_mmdb.py <out.mmdb>
"""
import sys

from mmdb_writer import MMDBWriter
from netaddr import IPSet

RANGES = {
    # code: (continent, ranges). 1.46.0.0/15 is the Thai range the GeoDNS
    # README tests with.
    "TH": ("AS", ["1.46.0.0/15", "49.228.0.0/14", "45.154.26.0/24"]),
    "US": ("NA", ["8.8.8.0/24", "8.8.4.0/24"]),
    "HK": ("AS", ["57.158.25.0/24"]),
    "JP": ("AS", ["133.0.0.0/16"]),
    "AU": ("OC", ["1.128.0.0/16"]),
}

writer = MMDBWriter(ip_version=4, database_type="DBIP-Country-Lite")
for code, (continent, nets) in RANGES.items():
    writer.insert_network(IPSet(nets), {"country": {"iso_code": code},
                                        "continent": {"code": continent}})
writer.to_db_file(sys.argv[1])
