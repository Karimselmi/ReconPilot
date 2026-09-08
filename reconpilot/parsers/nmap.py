import xml.etree.ElementTree as ET
from pathlib import Path


def parse_nmap(xml_file: Path) -> list[dict]:
    """
    Parse an Nmap XML file into structured Python dictionaries.
    """

    tree = ET.parse(xml_file)
    root = tree.getroot()

    results = []

    for host in root.findall("host"):

        address = host.find("address")

        if address is None:
            continue

        ip = address.get("addr")

        ports = []

        for port in host.findall("./ports/port"):

            state = port.find("state")
            service = port.find("service")

            port_data = {
                "port": int(port.get("portid")),
                "protocol": port.get("protocol"),
                "state": state.get("state") if state is not None else None,
                "service": (
                    service.get("name")
                    if service is not None
                    else None
                ),
                "product": (
                    service.get("product")
                    if service is not None
                    else None
                ),
                "version": (
                    service.get("version")
                    if service is not None
                    else None
                ),
            }

            ports.append(port_data)

        results.append(
            {
                "ip": ip,
                "ports": ports,
            }
        )

    return results
