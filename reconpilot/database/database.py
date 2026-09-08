import sqlite3
from datetime import datetime
from pathlib import Path


DATABASE_PATH = Path("results") / "reconpilot.db"


def get_connection() -> sqlite3.Connection:
    """Create a connection to the ReconPilot database."""

    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row

    return connection


def initialize_database() -> None:
    """Create the database tables if they do not exist."""

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            target_type TEXT NOT NULL,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            status TEXT NOT NULL
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            ip TEXT NOT NULL,
            UNIQUE(scan_id, ip),
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT,
            state TEXT,
            service TEXT,
            product TEXT,
            version TEXT,
            UNIQUE(host_id, port, protocol),
            FOREIGN KEY (host_id) REFERENCES hosts(id)
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS dns_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            target TEXT NOT NULL,
            record_type TEXT NOT NULL,
            value TEXT NOT NULL,
            UNIQUE(scan_id, record_type, value),
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS subdomains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            target TEXT NOT NULL,
            subdomain TEXT NOT NULL,
            address TEXT NOT NULL,
            UNIQUE(scan_id, subdomain, address),
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS http_services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            target TEXT NOT NULL,
            url TEXT NOT NULL,
            scheme TEXT,
            status_code INTEGER,
            title TEXT,
            server TEXT,
            location TEXT,
            response_time REAL,
            technologies TEXT,
            UNIQUE(scan_id, url),
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
        """
    )

    connection.commit()
    connection.close()


def create_scan(target: str, target_type: str) -> int:
    """Create a new reconnaissance scan."""

    connection = get_connection()
    cursor = connection.cursor()

    started_at = datetime.now().isoformat(timespec="seconds")

    cursor.execute(
        """
        INSERT INTO scans (
            target,
            target_type,
            started_at,
            status
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            target,
            target_type,
            started_at,
            "running",
        ),
    )

    scan_id = cursor.lastrowid

    connection.commit()
    connection.close()

    return scan_id


def complete_scan(
    scan_id: int,
    status: str = "completed",
) -> None:
    """Mark a scan as completed or failed."""

    connection = get_connection()
    cursor = connection.cursor()

    completed_at = datetime.now().isoformat(timespec="seconds")

    cursor.execute(
        """
        UPDATE scans
        SET completed_at = ?,
            status = ?
        WHERE id = ?
        """,
        (
            completed_at,
            status,
            scan_id,
        ),
    )

    connection.commit()
    connection.close()


def save_results(
    scan_id: int,
    results: list[dict],
) -> None:
    """Save parsed Nmap results for a scan."""

    connection = get_connection()
    cursor = connection.cursor()

    for host in results:
        cursor.execute(
            """
            INSERT OR IGNORE INTO hosts (
                scan_id,
                ip
            )
            VALUES (?, ?)
            """,
            (
                scan_id,
                host["ip"],
            ),
        )

        cursor.execute(
            """
            SELECT id
            FROM hosts
            WHERE scan_id = ?
            AND ip = ?
            """,
            (
                scan_id,
                host["ip"],
            ),
        )

        host_row = cursor.fetchone()

        if host_row is None:
            continue

        host_id = host_row["id"]

        for port in host["ports"]:
            cursor.execute(
                """
                INSERT OR REPLACE INTO ports (
                    host_id,
                    port,
                    protocol,
                    state,
                    service,
                    product,
                    version
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    host_id,
                    port["port"],
                    port["protocol"],
                    port["state"],
                    port["service"],
                    port["product"],
                    port["version"],
                ),
            )

    connection.commit()
    connection.close()


def save_dns_results(
    scan_id: int,
    target: str,
    results: dict[str, list[str]],
) -> None:
    """Save DNS results for a scan."""

    connection = get_connection()
    cursor = connection.cursor()

    for record_type, values in results.items():
        for value in values:
            cursor.execute(
                """
                INSERT OR IGNORE INTO dns_records (
                    scan_id,
                    target,
                    record_type,
                    value
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    scan_id,
                    target,
                    record_type,
                    value,
                ),
            )

    connection.commit()
    connection.close()


def save_subdomain_results(
    scan_id: int,
    target: str,
    results: list[dict],
) -> None:
    """Save discovered subdomains for a scan."""

    connection = get_connection()
    cursor = connection.cursor()

    for result in results:
        for address in result["addresses"]:
            cursor.execute(
                """
                INSERT OR IGNORE INTO subdomains (
                    scan_id,
                    target,
                    subdomain,
                    address
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    scan_id,
                    target,
                    result["subdomain"],
                    address,
                ),
            )

    connection.commit()
    connection.close()


def save_http_results(
    scan_id: int,
    target: str,
    results: list[dict],
) -> None:
    """Save HTTP reconnaissance results for a scan."""

    connection = get_connection()
    cursor = connection.cursor()

    for result in results:
        technologies = ", ".join(
            result.get("technologies", [])
        )

        cursor.execute(
            """
            INSERT OR REPLACE INTO http_services (
                scan_id,
                target,
                url,
                scheme,
                status_code,
                title,
                server,
                location,
                response_time,
                technologies
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                target,
                result["url"],
                result["scheme"],
                result["status_code"],
                result["title"],
                result["server"],
                result["location"],
                result["response_time"],
                technologies,
            ),
        )

    connection.commit()
    connection.close()


def get_results(
    target: str,
    scan_id: int | None = None,
) -> list[dict]:
    """Retrieve Nmap results for a target or specific scan."""

    connection = get_connection()
    cursor = connection.cursor()

    if scan_id is not None:
        cursor.execute(
            """
            SELECT
                h.ip,
                p.port,
                p.protocol,
                p.state,
                p.service,
                p.product,
                p.version
            FROM hosts h
            LEFT JOIN ports p
                ON h.id = p.host_id
            WHERE h.scan_id = ?
            ORDER BY h.ip, p.port
            """,
            (scan_id,),
        )
    else:
        cursor.execute(
            """
            SELECT
                h.ip,
                p.port,
                p.protocol,
                p.state,
                p.service,
                p.product,
                p.version
            FROM hosts h
            LEFT JOIN ports p
                ON h.id = p.host_id
            WHERE h.scan_id = (
                SELECT id
                FROM scans
                WHERE target = ?
                ORDER BY id DESC
                LIMIT 1
            )
            ORDER BY h.ip, p.port
            """,
            (target,),
        )

    rows = cursor.fetchall()
    connection.close()

    results = {}

    for row in rows:
        ip = row["ip"]

        if ip not in results:
            results[ip] = {
                "ip": ip,
                "ports": [],
            }

        if row["port"] is not None:
            results[ip]["ports"].append(
                {
                    "port": row["port"],
                    "protocol": row["protocol"],
                    "state": row["state"],
                    "service": row["service"],
                    "product": row["product"],
                    "version": row["version"],
                }
            )

    return list(results.values())


def get_full_results(
    target: str,
    scan_id: int | None = None,
) -> dict:
    """Retrieve all reconnaissance data for a target or scan."""

    connection = get_connection()
    cursor = connection.cursor()

    if scan_id is None:
        cursor.execute(
            """
            SELECT *
            FROM scans
            WHERE target = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (target,),
        )
    else:
        cursor.execute(
            """
            SELECT *
            FROM scans
            WHERE id = ?
            """,
            (scan_id,),
        )

    scan = cursor.fetchone()

    if scan is None:
        connection.close()

        return {
            "scan_id": None,
            "target": target,
            "target_type": "unknown",
            "status": None,
            "started_at": None,
            "completed_at": None,
            "nmap": [],
            "dns": {},
            "subdomains": [],
            "http": [],
        }

    actual_scan_id = scan["id"]

    # Nmap
    cursor.execute(
        """
        SELECT
            h.ip,
            p.port,
            p.protocol,
            p.state,
            p.service,
            p.product,
            p.version
        FROM hosts h
        LEFT JOIN ports p
            ON h.id = p.host_id
        WHERE h.scan_id = ?
        ORDER BY h.ip, p.port
        """,
        (actual_scan_id,),
    )

    hosts = {}

    for row in cursor.fetchall():
        ip = row["ip"]

        if ip not in hosts:
            hosts[ip] = {
                "ip": ip,
                "ports": [],
            }

        if row["port"] is not None:
            hosts[ip]["ports"].append(
                {
                    "port": row["port"],
                    "protocol": row["protocol"],
                    "state": row["state"],
                    "service": row["service"],
                    "product": row["product"],
                    "version": row["version"],
                }
            )

    # DNS
    cursor.execute(
        """
        SELECT record_type, value
        FROM dns_records
        WHERE scan_id = ?
        ORDER BY record_type, value
        """,
        (actual_scan_id,),
    )

    dns = {}

    for row in cursor.fetchall():
        dns.setdefault(
            row["record_type"],
            [],
        ).append(row["value"])

    # Subdomains
    cursor.execute(
        """
        SELECT subdomain, address
        FROM subdomains
        WHERE scan_id = ?
        ORDER BY subdomain, address
        """,
        (actual_scan_id,),
    )

    subdomains_map = {}

    for row in cursor.fetchall():
        subdomain = row["subdomain"]

        subdomains_map.setdefault(
            subdomain,
            [],
        ).append(row["address"])

    subdomains = [
        {
            "subdomain": subdomain,
            "addresses": addresses,
        }
        for subdomain, addresses in subdomains_map.items()
    ]

    # HTTP
    cursor.execute(
        """
        SELECT
            url,
            scheme,
            status_code,
            title,
            server,
            location,
            response_time,
            technologies
        FROM http_services
        WHERE scan_id = ?
        ORDER BY url
        """,
        (actual_scan_id,),
    )

    http = []

    for row in cursor.fetchall():
        technologies = []

        if row["technologies"]:
            technologies = [
                item.strip()
                for item in row["technologies"].split(",")
            ]

        http.append(
            {
                "url": row["url"],
                "scheme": row["scheme"],
                "status_code": row["status_code"],
                "title": row["title"],
                "server": row["server"],
                "location": row["location"],
                "response_time": row["response_time"],
                "technologies": technologies,
            }
        )

    connection.close()

    return {
        "scan_id": scan["id"],
        "target": scan["target"],
        "target_type": scan["target_type"],
        "status": scan["status"],
        "started_at": scan["started_at"],
        "completed_at": scan["completed_at"],
        "nmap": list(hosts.values()),
        "dns": dns,
        "subdomains": subdomains,
        "http": http,
    }


def get_scan(scan_id: int) -> dict | None:
    """Retrieve scan metadata."""

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT *
        FROM scans
        WHERE id = ?
        """,
        (scan_id,),
    )

    row = cursor.fetchone()
    connection.close()

    if row is None:
        return None

    return dict(row)


def get_scans() -> list[dict]:
    """Retrieve all scans."""

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            target,
            target_type,
            started_at,
            completed_at,
            status
        FROM scans
        ORDER BY id DESC
        """
    )

    rows = cursor.fetchall()
    connection.close()

    return [dict(row) for row in rows]
