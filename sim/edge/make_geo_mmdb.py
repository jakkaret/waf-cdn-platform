"""Write a small country database for PowerDNS's geoip backend.

Production uses DB-IP Lite (not in git, CC BY 4.0). The simulation only needs
country() to tell Thai visitors from the rest, so this marks a few Thai and
US ranges, in the same MaxMind DB format.

    python3 make_geo_mmdb.py <out.mmdb>
"""
import sys

from mmdb_writer import MMDBWriter
from netaddr import IPSet

RANGES = {
    # 1.46.0.0/15 is the Thai range the GeoDNS README tests with.
    "TH": ["1.46.0.0/15", "49.228.0.0/14", "45.154.26.0/24"],
    "US": ["8.8.8.0/24", "8.8.4.0/24"],
    "HK": ["57.158.25.0/24"],
}

writer = MMDBWriter(ip_version=4, database_type="DBIP-Country-Lite")
for code, nets in RANGES.items():
    writer.insert_network(IPSet(nets), {"country": {"iso_code": code}})
writer.to_db_file(sys.argv[1])
