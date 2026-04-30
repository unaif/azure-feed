#!/usr/bin/env python3
"""
Azure IP Ranges feed parser.

Descarga el JSON semanal de Microsoft con los rangos IP de Azure por service tag,
lo sanitiza y produce ficheros limpios para EDL (Palo Alto) o External Threat Feed (FortiGate).

Uso:
    python3 scripts/parse.py

Salida en docs/:
    azure_ipv4.txt              # Todos los CIDRs IPv4 combinados
    azure_ipv6.txt              # Todos los CIDRs IPv6 combinados
    azure_frontdoor_ipv4.txt    # AzureFrontDoor.*
    azure_storage_ipv4.txt      # Storage.*
    azure_cdn_ipv4.txt          # AzureCDN.*
    azure_sql_ipv4.txt          # Sql.*
    meta.json                   # timestamp, changeNumber y conteos
"""
from __future__ import annotations

import ipaddress
import json
import pathlib
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

DOWNLOAD_PAGE = "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519"
OUT = pathlib.Path("docs")
USER_AGENT = "azure-feed-sync/1.0"
TIMEOUT = 60
RETRIES = 3
RETRY_BACKOFF = 5

MIN_IPV4_ENTRIES = 500

# Prefijos de service tag → nombre de fichero de salida
SERVICE_EXPORTS: dict[str, str] = {
    "frontdoor": "AzureFrontDoor",
    "storage": "Storage",
    "cdn": "AzureCDN",
    "sql": "Sql",
}


def fetch(url: str) -> bytes:
    last_err: Exception | None = None
    for attempt in range(1, RETRIES + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"HTTP {resp.status}")
                return resp.read()
        except (urllib.error.URLError, urllib.error.HTTPError, RuntimeError) as e:
            last_err = e
            if attempt < RETRIES:
                time.sleep(RETRY_BACKOFF * attempt)
    raise RuntimeError(f"Fetch falló tras {RETRIES} intentos: {last_err}")


def get_json_url() -> str:
    page = fetch(DOWNLOAD_PAGE).decode("utf-8", errors="ignore")
    match = re.search(
        r'https://download\.microsoft\.com/download/[^"\'>\s]+ServiceTags_Public_\d+\.json',
        page,
    )
    if not match:
        raise RuntimeError("No se encontró la URL del JSON en la página de descarga de Microsoft")
    return match.group(0)


def parse(data: dict) -> dict:
    all_ipv4: set[str] = set()
    all_ipv6: set[str] = set()
    by_service: dict[str, dict[str, set[str]]] = {}

    for entry in data.get("values", []):
        name: str = entry.get("name", "")
        prefixes: list[str] = entry.get("properties", {}).get("addressPrefixes", [])

        ipv4_set: set[str] = set()
        ipv6_set: set[str] = set()

        for prefix in prefixes:
            try:
                net = ipaddress.ip_network(prefix, strict=False)
                if isinstance(net, ipaddress.IPv4Network):
                    canonical = str(net)
                    ipv4_set.add(canonical)
                    all_ipv4.add(canonical)
                else:
                    canonical = str(net)
                    ipv6_set.add(canonical)
                    all_ipv6.add(canonical)
            except ValueError:
                pass

        if ipv4_set or ipv6_set:
            by_service[name] = {"ipv4": ipv4_set, "ipv6": ipv6_set}

    return {
        "all_ipv4": all_ipv4,
        "all_ipv6": all_ipv6,
        "by_service": by_service,
    }


def write_lines(path: pathlib.Path, items: set[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = "\n".join(sorted(items))
    if content:
        content += "\n"
    path.write_text(content, encoding="utf-8")


def main() -> int:
    print("Buscando URL del JSON de Azure...", file=sys.stderr)
    json_url = get_json_url()
    print(f"Descargando: {json_url}", file=sys.stderr)

    raw = fetch(json_url)
    data = json.loads(raw.decode("utf-8", errors="ignore"))

    change_number: int = data.get("changeNumber", 0)
    parsed = parse(data)

    if len(parsed["all_ipv4"]) < MIN_IPV4_ENTRIES:
        print(
            f"ERROR: solo {len(parsed['all_ipv4'])} entradas IPv4, esperadas ≥{MIN_IPV4_ENTRIES}",
            file=sys.stderr,
        )
        return 2

    write_lines(OUT / "azure_ipv4.txt", parsed["all_ipv4"])
    write_lines(OUT / "azure_ipv6.txt", parsed["all_ipv6"])

    by_service = parsed["by_service"]
    service_counts: dict[str, int] = {}
    for key, tag_prefix in SERVICE_EXPORTS.items():
        combined: set[str] = set()
        for svc_name, svc_data in by_service.items():
            if svc_name.startswith(tag_prefix):
                combined |= svc_data["ipv4"]
        if combined:
            write_lines(OUT / f"azure_{key}_ipv4.txt", combined)
            service_counts[key] = len(combined)

    meta = {
        "source": json_url,
        "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "change_number": change_number,
        "counts": {
            "ipv4_total": len(parsed["all_ipv4"]),
            "ipv6_total": len(parsed["all_ipv6"]),
            "service_tags": len(by_service),
            **{f"{k}_ipv4": v for k, v in service_counts.items()},
        },
    }
    (OUT / "meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")

    print(
        f"OK ipv4:{len(parsed['all_ipv4'])} "
        f"ipv6:{len(parsed['all_ipv6'])} "
        f"tags:{len(by_service)}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
