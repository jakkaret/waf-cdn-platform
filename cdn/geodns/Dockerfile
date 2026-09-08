FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Bundle a Thailand-only IP-range GeoIP table at build time, filtered from
# DB-IP's free Lite country database (CC-BY 4.0, https://db-ip.com) via
# https://github.com/sapics/ip-location-db. Filtering to TH-only keeps the
# bundled file small (~1,600 rows) since server.py only needs a binary
# TH / not-TH split for the 2-edge deployment this project actually has.
RUN python -c "\
import csv, urllib.request; \
url = 'https://raw.githubusercontent.com/sapics/ip-location-db/main/dbip-country/dbip-country-ipv4.csv'; \
data = urllib.request.urlopen(url, timeout=60).read().decode(); \
rows = [r for r in csv.reader(data.splitlines()) if len(r) == 3 and r[2] == 'TH']; \
open('/app/th_ranges.csv', 'w', newline='').writelines(f'{r[0]},{r[1]}\n' for r in rows); \
print(f'wrote {len(rows)} Thailand IP ranges')"

COPY server.py ./

EXPOSE 53/udp 53/tcp
CMD ["python", "server.py"]
