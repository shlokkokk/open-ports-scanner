import os, json, requests

CACHE = "iana_cache.json"
URL   = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv"

def load():
    """Return {port: (name, desc)}. Download once, cache forever."""
    if os.path.exists(CACHE):
        return json.load(open(CACHE))
    print("[IANA] Downloading port list …")
    r = requests.get(URL, timeout=30)
    r.raise_for_status()
    data = {}
    for line in r.text.splitlines():
        parts = line.split(",")
        if len(parts) < 3:
            continue
        try:
            port = int(parts[1])
            name = parts[0] or f"Port-{port}"
            desc = parts[2] or "No description"
            data[port] = (name, desc)
        except ValueError:
            continue
    json.dump(data, open(CACHE, "w"))
    return data

# load on first import
IANA = load()