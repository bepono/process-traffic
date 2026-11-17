"""Offline IP -> country lookup from DB-IP's free "IP to Country Lite" CSV.

Data: data/dbip-country-lite.csv.gz (https://db-ip.com, CC BY 4.0).
Refresh it monthly with: python3 geo.py --update
"""
import array
import bisect
import gzip
import ipaddress
import os
import socket
import sys
import threading
import urllib.request
from datetime import date

HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(HERE, "data", "dbip-country-lite.csv.gz")


class CountryDB:
    """Compact range table: IPv4 keyed by 32-bit int, IPv6 by its upper 64 bits."""

    def __init__(self):
        self.ready = False
        self.v4s = array.array("I"); self.v4e = array.array("I"); self.v4c = bytearray()
        self.v6s = array.array("Q"); self.v6e = array.array("Q"); self.v6c = bytearray()

    def load(self, path=DB_PATH):
        with _load_lock:
            if self.ready or not os.path.exists(path):
                return
            self._load(path)

    def _load(self, path):
        pton, frm = socket.inet_pton, int.from_bytes
        A4, A6 = socket.AF_INET, socket.AF_INET6
        with gzip.open(path, "rt", encoding="ascii", errors="replace") as f:
            for line in f:
                try:
                    a, b, cc = line.rstrip("\n").split(",")
                except ValueError:
                    continue
                cc = cc.encode()[:2].ljust(2, b"?")
                if ":" in a:
                    self.v6s.append(frm(pton(A6, a)[:8], "big"))
                    self.v6e.append(frm(pton(A6, b)[:8], "big"))
                    self.v6c += cc
                else:
                    self.v4s.append(frm(pton(A4, a), "big"))
                    self.v4e.append(frm(pton(A4, b), "big"))
                    self.v4c += cc
        self.ready = True

    def lookup(self, ip: str):
        """Return ISO country code, 'LAN' for private/local addresses, or None."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if addr.version == 6 and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return "LAN"
        if not self.ready:
            return None
        if addr.version == 4:
            key, starts, ends, ccs = int(addr), self.v4s, self.v4e, self.v4c
        else:
            key, starts, ends, ccs = int(addr) >> 64, self.v6s, self.v6e, self.v6c
        i = bisect.bisect_right(starts, key) - 1
        if i < 0 or key > ends[i]:
            return None
        cc = ccs[2 * i:2 * i + 2].decode()
        return None if cc in ("ZZ", "??") else cc


class ASNDB:
    """IP -> (AS number, network owner) from DB-IP "IP to ASN Lite" (CC BY 4.0)."""
    PATH = os.path.join(HERE, "data", "dbip-asn-lite.csv.gz")

    def __init__(self):
        self.ready = False
        self.v4s = array.array("I"); self.v4e = array.array("I"); self.v4i = array.array("I")
        self.v6s = array.array("Q"); self.v6e = array.array("Q"); self.v6i = array.array("I")
        self.orgs: list[tuple[int, str]] = []
        self._lock = threading.Lock()

    def load(self):
        with self._lock:
            if self.ready or not os.path.exists(self.PATH):
                return
            import csv
            pton, frm = socket.inet_pton, int.from_bytes
            index: dict[tuple[int, str], int] = {}
            with gzip.open(self.PATH, "rt", encoding="utf-8", errors="replace", newline="") as f:
                for row in csv.reader(f):
                    if len(row) < 4:
                        continue
                    a, b, asn, org = row[0], row[1], row[2], row[3]
                    key = (int(asn or 0), org)
                    i = index.get(key)
                    if i is None:
                        i = index[key] = len(self.orgs)
                        self.orgs.append(key)
                    try:
                        if ":" in a:
                            self.v6s.append(frm(pton(socket.AF_INET6, a)[:8], "big"))
                            self.v6e.append(frm(pton(socket.AF_INET6, b)[:8], "big"))
                            self.v6i.append(i)
                        else:
                            self.v4s.append(frm(pton(socket.AF_INET, a), "big"))
                            self.v4e.append(frm(pton(socket.AF_INET, b), "big"))
                            self.v4i.append(i)
                    except OSError:
                        continue
            self.ready = True

    def lookup(self, ip: str):
        """{"asn": 399358, "org": "Anthropic, PBC"} or None."""
        if not self.ready:
            return None
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if addr.version == 6 and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return None
        if addr.version == 4:
            key, starts, ends, idx = int(addr), self.v4s, self.v4e, self.v4i
        else:
            key, starts, ends, idx = int(addr) >> 64, self.v6s, self.v6e, self.v6i
        i = bisect.bisect_right(starts, key) - 1
        if i < 0 or key > ends[i]:
            return None
        asn, org = self.orgs[idx[i]]
        return {"asn": asn, "org": org}


_load_lock = threading.Lock()
DB = CountryDB()
ASN = ASNDB()


def _load_all():
    DB.load()
    ASN.load()


threading.Thread(target=_load_all, daemon=True).start()  # a few seconds; lookups return None until done


def update():
    """Download this month's DB-IP country and ASN files (falls back to last month)."""
    today = date.today()
    months = [today.strftime("%Y-%m"),
              date(today.year - (today.month == 1), (today.month - 2) % 12 + 1, 1).strftime("%Y-%m")]
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    ok = True
    for kind, path in (("country", DB_PATH), ("asn", ASNDB.PATH)):
        for m in months:
            url = f"https://download.db-ip.com/free/dbip-{kind}-lite-{m}.csv.gz"
            try:
                tmp = path + ".part"
                urllib.request.urlretrieve(url, tmp)
                os.replace(tmp, path)
                print(f"Updated {kind} data ({m})")
                break
            except Exception as e:
                print(f"{url}: {e}")
        else:
            ok = False
    if not ok:
        sys.exit(1)


if __name__ == "__main__":
    if "--update" in sys.argv:
        update()
    else:
        DB.load(); ASN.load()
        for ip in sys.argv[1:]:
            print(ip, DB.lookup(ip), ASN.lookup(ip))
