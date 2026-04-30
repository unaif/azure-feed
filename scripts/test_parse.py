#!/usr/bin/env python3
"""
Tests básicos del parser Azure. Ejecutar con:
    python3 scripts/test_parse.py

No requiere red ni dependencias externas.
"""
from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from parse import parse  # noqa: E402

SAMPLE_DATA: dict = {
    "changeNumber": 12345,
    "cloud": "Public",
    "values": [
        {
            "name": "AzureCloud",
            "id": "AzureCloud",
            "properties": {
                "changeNumber": 100,
                "addressPrefixes": [
                    "13.64.0.0/11",
                    "20.0.0.0/11",
                    "2603:1000::/25",
                ],
            },
        },
        {
            "name": "AzureFrontDoor.Frontend",
            "id": "AzureFrontDoor.Frontend",
            "properties": {
                "changeNumber": 50,
                "addressPrefixes": [
                    "13.107.246.0/24",
                    "204.79.197.0/24",
                ],
            },
        },
        {
            "name": "Storage.EastUS",
            "id": "Storage.EastUS",
            "properties": {
                "changeNumber": 20,
                "addressPrefixes": [
                    "52.239.184.0/23",
                    "2603:1020::/47",
                ],
            },
        },
        {
            "name": "Sql.WestEurope",
            "id": "Sql.WestEurope",
            "properties": {
                "changeNumber": 10,
                "addressPrefixes": [
                    "40.68.0.0/16",
                ],
            },
        },
        {
            "name": "EmptyService",
            "id": "EmptyService",
            "properties": {
                "changeNumber": 1,
                "addressPrefixes": [],
            },
        },
    ],
}


def run() -> None:
    r = parse(SAMPLE_DATA)

    # IPv4 combinado
    assert "13.64.0.0/11" in r["all_ipv4"], "CIDR AzureCloud no detectado"
    assert "20.0.0.0/11" in r["all_ipv4"], "CIDR AzureCloud 2 no detectado"
    assert "13.107.246.0/24" in r["all_ipv4"], "CIDR FrontDoor no detectado"
    assert "52.239.184.0/23" in r["all_ipv4"], "CIDR Storage no detectado"
    assert "40.68.0.0/16" in r["all_ipv4"], "CIDR Sql no detectado"

    # IPv6 combinado
    assert "2603:1000::/25" in r["all_ipv6"], "CIDR IPv6 AzureCloud no detectado"
    assert "2603:1020::/47" in r["all_ipv6"], "CIDR IPv6 Storage no detectado"

    # by_service indexado correctamente
    assert "AzureCloud" in r["by_service"], "servicio AzureCloud no indexado"
    assert "AzureFrontDoor.Frontend" in r["by_service"], "servicio FrontDoor no indexado"
    assert "Storage.EastUS" in r["by_service"], "servicio Storage no indexado"
    assert "EmptyService" not in r["by_service"], "servicio vacío no debería indexarse"

    # Datos por servicio
    fd = r["by_service"]["AzureFrontDoor.Frontend"]
    assert "13.107.246.0/24" in fd["ipv4"], "FrontDoor ipv4 mal clasificado"
    assert len(fd["ipv6"]) == 0, "FrontDoor no debería tener IPv6 en el sample"

    storage = r["by_service"]["Storage.EastUS"]
    assert "2603:1020::/47" in storage["ipv6"], "Storage IPv6 mal clasificado"

    print(
        f"OK | ipv4:{len(r['all_ipv4'])} "
        f"ipv6:{len(r['all_ipv6'])} "
        f"services:{len(r['by_service'])}"
    )


if __name__ == "__main__":
    run()
