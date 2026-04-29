#!/usr/bin/env python3
"""Ubuntu vulnerability discovery and patch agent (MVP)."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sqlite3
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import apt_pkg  # type: ignore
except Exception:  # pragma: no cover - runtime dependency
    apt_pkg = None

DEFAULT_CONFIG_PATH = "/etc/vuln-patch-agent/config.json"
DEFAULT_CONFIG = {
    "db_path": "/var/lib/vuln-patch-agent/vuln_patch.db",
    "audit_log": "/var/log/vuln-patch-agent/audit.log",
    "scan_output": "/var/log/vuln-patch-agent/latest_scan.json",
    "report_output": "/var/log/vuln-patch-agent/latest_report.json",
    "nvd_endpoint": "https://services.nvd.nist.gov/rest/json/cves/2.0",
    "results_per_page": 2000,
}


@dataclass
class VulnerabilityMatch:
    package: str
    installed_version: str
    cve_id: str
    cvss_score: float | None
    source_product: str
    reasoning: str


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_config(path: str | None) -> dict[str, Any]:
    config = dict(DEFAULT_CONFIG)
    if not path:
        path = DEFAULT_CONFIG_PATH

    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as handle:
            user_config = json.load(handle)
        config.update(user_config)

    return config


def ensure_parent_dir(path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)


def audit_log(log_file: str, event: str, details: dict[str, Any], level: str = "INFO") -> None:
    ensure_parent_dir(log_file)
    line = {
        "timestamp": utc_now(),
        "level": level,
        "event": event,
        "details": details,
    }
    with open(log_file, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(line, ensure_ascii=True) + "\n")


def get_connection(db_path: str) -> sqlite3.Connection:
    ensure_parent_dir(db_path)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path: str) -> None:
    with get_connection(db_path) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                cvss_score REAL,
                published_date TEXT,
                last_modified_date TEXT,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS affected_packages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT NOT NULL,
                product_name TEXT NOT NULL,
                version_start TEXT,
                version_start_inclusive INTEGER DEFAULT 1,
                version_end TEXT,
                version_end_inclusive INTEGER DEFAULT 1,
                source TEXT DEFAULT 'nvd',
                FOREIGN KEY(cve_id) REFERENCES vulnerabilities(cve_id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_affected_product ON affected_packages(product_name);
            CREATE INDEX IF NOT EXISTS idx_affected_cve ON affected_packages(cve_id);

            CREATE TABLE IF NOT EXISTS package_aliases (
                cpe_name TEXT PRIMARY KEY,
                dpkg_name TEXT NOT NULL,
                source TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sync_state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_at TEXT NOT NULL,
                vulnerable_findings INTEGER NOT NULL,
                vulnerable_packages INTEGER NOT NULL,
                output_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS patch_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_at TEXT NOT NULL,
                target_count INTEGER NOT NULL,
                success_count INTEGER NOT NULL,
                failed_count INTEGER NOT NULL,
                output_json TEXT NOT NULL
            );
            """
        )


def get_state(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute("SELECT value FROM sync_state WHERE key = ?", (key,)).fetchone()
    return row[0] if row else None


def set_state(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        """
        INSERT INTO sync_state(key, value, updated_at)
        VALUES(?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET
            value = excluded.value,
            updated_at = excluded.updated_at
        """,
        (key, value, utc_now()),
    )


def normalize_product_name(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def parse_cpe_product(criteria: str) -> str | None:
    # Example: cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*
    parts = criteria.split(":")
    if len(parts) < 6:
        return None
    raw_product = parts[4].strip()
    if not raw_product or raw_product in {"*", "-"}:
        return None
    return normalize_product_name(raw_product)


def extract_english_description(cve_payload: dict[str, Any]) -> str:
    descriptions = cve_payload.get("descriptions", [])
    for item in descriptions:
        if item.get("lang") == "en" and item.get("value"):
            return item["value"]
    if descriptions:
        return descriptions[0].get("value", "")
    return ""


def extract_cvss_score(cve_payload: dict[str, Any]) -> float | None:
    metrics = cve_payload.get("metrics", {})
    metric_keys = ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]
    for key in metric_keys:
        values = metrics.get(key, [])
        for item in values:
            data = item.get("cvssData") or {}
            score = data.get("baseScore")
            if score is not None:
                try:
                    return float(score)
                except (TypeError, ValueError):
                    continue
    return None


def walk_config_nodes(node: dict[str, Any], accumulator: list[dict[str, Any]]) -> None:
    for match in node.get("cpeMatch", []):
        if not match.get("vulnerable", False):
            continue
        product = parse_cpe_product(match.get("criteria", ""))
        if not product:
            continue
        accumulator.append(
            {
                "product_name": product,
                "version_start": match.get("versionStartIncluding") or match.get("versionStartExcluding"),
                "version_start_inclusive": 0 if match.get("versionStartExcluding") else 1,
                "version_end": match.get("versionEndIncluding") or match.get("versionEndExcluding"),
                "version_end_inclusive": 0 if match.get("versionEndExcluding") else 1,
                "source": "nvd",
            }
        )

    for child in node.get("children", []):
        walk_config_nodes(child, accumulator)


def extract_affected_products(cve_payload: dict[str, Any]) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for config in cve_payload.get("configurations", []):
        for node in config.get("nodes", []):
            walk_config_nodes(node, found)
    return found


def fetch_json(url: str, headers: dict[str, str] | None = None) -> dict[str, Any]:
    request = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(request, timeout=60) as response:
        payload = response.read().decode("utf-8")
    return json.loads(payload)


def sync_nvd_data(
    db_path: str,
    log_file: str,
    endpoint: str,
    api_key: str | None,
    since: str | None,
    results_per_page: int,
    max_pages: int | None,
) -> dict[str, Any]:
    init_db(db_path)
    total_vulns = 0
    total_affected = 0
    page_count = 0

    with get_connection(db_path) as conn:
        state_since = get_state(conn, "nvd_last_mod_start")
        if since:
            start_date = since
        elif state_since:
            start_date = state_since
        else:
            start_date = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=7)).replace(microsecond=0).isoformat().replace("+00:00", "Z")

        end_date = utc_now()
        start_index = 0

        headers: dict[str, str] = {}
        if api_key:
            headers["apiKey"] = api_key

        while True:
            query = {
                "resultsPerPage": results_per_page,
                "startIndex": start_index,
                "lastModStartDate": start_date,
                "lastModEndDate": end_date,
            }
            url = endpoint + "?" + urllib.parse.urlencode(query)

            try:
                data = fetch_json(url, headers=headers)
            except urllib.error.HTTPError as exc:
                body = exc.read().decode("utf-8", errors="replace")
                audit_log(log_file, "nvd_sync_failed", {"status": exc.code, "body": body}, level="ERROR")
                raise RuntimeError(f"NVD API error: HTTP {exc.code}") from exc
            except urllib.error.URLError as exc:
                audit_log(log_file, "nvd_sync_failed", {"reason": str(exc.reason)}, level="ERROR")
                raise RuntimeError(f"NVD API connection failed: {exc.reason}") from exc

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                break

            for item in vulns:
                cve = item.get("cve", {})
                cve_id = cve.get("id")
                if not cve_id:
                    continue

                description = extract_english_description(cve)
                cvss = extract_cvss_score(cve)
                published = cve.get("published")
                modified = cve.get("lastModified")

                conn.execute(
                    """
                    INSERT INTO vulnerabilities(cve_id, description, cvss_score, published_date, last_modified_date, updated_at)
                    VALUES(?, ?, ?, ?, ?, ?)
                    ON CONFLICT(cve_id) DO UPDATE SET
                        description = excluded.description,
                        cvss_score = excluded.cvss_score,
                        published_date = excluded.published_date,
                        last_modified_date = excluded.last_modified_date,
                        updated_at = excluded.updated_at
                    """,
                    (cve_id, description, cvss, published, modified, utc_now()),
                )

                conn.execute("DELETE FROM affected_packages WHERE cve_id = ?", (cve_id,))
                for affected in extract_affected_products(cve):
                    conn.execute(
                        """
                        INSERT INTO affected_packages(
                            cve_id, product_name, version_start, version_start_inclusive,
                            version_end, version_end_inclusive, source
                        )
                        VALUES(?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            cve_id,
                            affected["product_name"],
                            affected["version_start"],
                            affected["version_start_inclusive"],
                            affected["version_end"],
                            affected["version_end_inclusive"],
                            affected["source"],
                        ),
                    )
                    total_affected += 1

                total_vulns += 1

            conn.commit()
            page_count += 1

            total_results = int(data.get("totalResults", 0))
            start_index += len(vulns)
            if start_index >= total_results:
                break
            if max_pages and page_count >= max_pages:
                break

        set_state(conn, "nvd_last_mod_start", end_date)
        conn.commit()

    summary = {
        "started_from": start_date,
        "ended_at": end_date,
        "pages": page_count,
        "vulnerabilities_upserted": total_vulns,
        "affected_rows_upserted": total_affected,
    }
    audit_log(log_file, "nvd_sync_completed", summary)
    return summary


def import_oval_aliases(db_path: str, log_file: str, oval_path: str) -> dict[str, Any]:
    init_db(db_path)
    if not os.path.exists(oval_path):
        raise FileNotFoundError(f"OVAL file not found: {oval_path}")

    tree = ET.parse(oval_path)
    root = tree.getroot()

    found_aliases: dict[str, str] = {}
    pkg_regex = re.compile(r"\b([a-z0-9][a-z0-9+.-]+)\s+package\b", re.IGNORECASE)

    for elem in root.iter():
        tag = elem.tag.split("}")[-1].lower()
        if tag != "criterion":
            continue

        comment = (elem.attrib.get("comment") or "").strip()
        if not comment:
            continue

        match = pkg_regex.search(comment)
        if not match:
            continue

        dpkg_name = normalize_product_name(match.group(1))
        cpe_like = normalize_product_name(match.group(1).replace("-", "_"))

        found_aliases[cpe_like] = dpkg_name
        found_aliases[dpkg_name] = dpkg_name

    with get_connection(db_path) as conn:
        for cpe_name, dpkg_name in found_aliases.items():
            conn.execute(
                """
                INSERT INTO package_aliases(cpe_name, dpkg_name, source, updated_at)
                VALUES(?, ?, ?, ?)
                ON CONFLICT(cpe_name) DO UPDATE SET
                    dpkg_name = excluded.dpkg_name,
                    source = excluded.source,
                    updated_at = excluded.updated_at
                """,
                (cpe_name, dpkg_name, "oval", utc_now()),
            )
        conn.commit()

    summary = {
        "oval_file": oval_path,
        "aliases_upserted": len(found_aliases),
    }
    audit_log(log_file, "oval_import_completed", summary)
    return summary


class VersionComparator:
    def __init__(self) -> None:
        self.use_apt = apt_pkg is not None
        if self.use_apt:
            apt_pkg.init_system()  # type: ignore[attr-defined]

    def compare(self, left: str, right: str) -> int:
        if left == right:
            return 0

        if self.use_apt:
            result = apt_pkg.version_compare(left, right)  # type: ignore[union-attr]
            if result < 0:
                return -1
            if result > 0:
                return 1
            return 0

        lt = subprocess.run(
            ["dpkg", "--compare-versions", left, "lt", right],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if lt.returncode == 0:
            return -1

        gt = subprocess.run(
            ["dpkg", "--compare-versions", left, "gt", right],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if gt.returncode == 0:
            return 1

        return 0


def in_affected_range(
    comparator: VersionComparator,
    installed_version: str,
    start: str | None,
    start_inclusive: bool,
    end: str | None,
    end_inclusive: bool,
) -> bool:
    if start:
        cmp_start = comparator.compare(installed_version, start)
        if start_inclusive and cmp_start < 0:
            return False
        if not start_inclusive and cmp_start <= 0:
            return False

    if end:
        cmp_end = comparator.compare(installed_version, end)
        if end_inclusive and cmp_end > 0:
            return False
        if not end_inclusive and cmp_end >= 0:
            return False

    return True


def read_installed_packages() -> list[tuple[str, str]]:
    result = subprocess.run(
        ["dpkg-query", "-W", "-f=${Package}\t${Version}\n"],
        check=True,
        capture_output=True,
        text=True,
    )
    packages: list[tuple[str, str]] = []
    for line in result.stdout.splitlines():
        if not line.strip() or "\t" not in line:
            continue
        name, version = line.strip().split("\t", 1)
        packages.append((normalize_product_name(name), version.strip()))
    return packages


def scan_local_packages(db_path: str, log_file: str, output_file: str | None) -> dict[str, Any]:
    init_db(db_path)

    with get_connection(db_path) as conn:
        alias_rows = conn.execute("SELECT cpe_name, dpkg_name FROM package_aliases").fetchall()
        affected_rows = conn.execute(
            """
            SELECT a.cve_id, a.product_name, a.version_start, a.version_start_inclusive,
                   a.version_end, a.version_end_inclusive, v.cvss_score, v.description
            FROM affected_packages a
            JOIN vulnerabilities v ON v.cve_id = a.cve_id
            """
        ).fetchall()

    aliases_by_dpkg: dict[str, set[str]] = {}
    for row in alias_rows:
        cpe_name = normalize_product_name(row["cpe_name"])
        dpkg_name = normalize_product_name(row["dpkg_name"])
        aliases_by_dpkg.setdefault(dpkg_name, set()).add(cpe_name)

    affected_by_product: dict[str, list[sqlite3.Row]] = {}
    for row in affected_rows:
        product = normalize_product_name(row["product_name"])
        affected_by_product.setdefault(product, []).append(row)

    comparator = VersionComparator()
    findings: list[VulnerabilityMatch] = []
    installed = read_installed_packages()

    for pkg_name, pkg_version in installed:
        candidate_products = {pkg_name}
        candidate_products.update(aliases_by_dpkg.get(pkg_name, set()))

        for candidate in candidate_products:
            for row in affected_by_product.get(candidate, []):
                start = row["version_start"]
                end = row["version_end"]
                start_inclusive = bool(row["version_start_inclusive"])
                end_inclusive = bool(row["version_end_inclusive"])

                if not in_affected_range(comparator, pkg_version, start, start_inclusive, end, end_inclusive):
                    continue

                reason = (
                    f"product={row['product_name']}, installed={pkg_version}, "
                    f"range_start={start or '*'}({'inc' if start_inclusive else 'exc'}), "
                    f"range_end={end or '*'}({'inc' if end_inclusive else 'exc'})"
                )

                findings.append(
                    VulnerabilityMatch(
                        package=pkg_name,
                        installed_version=pkg_version,
                        cve_id=row["cve_id"],
                        cvss_score=row["cvss_score"],
                        source_product=row["product_name"],
                        reasoning=reason,
                    )
                )

    grouped: dict[str, dict[str, Any]] = {}
    for finding in findings:
        pkg_obj = grouped.setdefault(
            finding.package,
            {
                "package": finding.package,
                "installed_version": finding.installed_version,
                "vulnerabilities": [],
            },
        )
        pkg_obj["vulnerabilities"].append(
            {
                "cve_id": finding.cve_id,
                "cvss_score": finding.cvss_score,
                "source_product": finding.source_product,
                "reasoning": finding.reasoning,
            }
        )

    result = {
        "timestamp": utc_now(),
        "total_installed_packages": len(installed),
        "vulnerable_findings": len(findings),
        "vulnerable_packages": len(grouped),
        "packages": list(grouped.values()),
    }

    with get_connection(db_path) as conn:
        conn.execute(
            """
            INSERT INTO scan_history(run_at, vulnerable_findings, vulnerable_packages, output_json)
            VALUES(?, ?, ?, ?)
            """,
            (
                result["timestamp"],
                result["vulnerable_findings"],
                result["vulnerable_packages"],
                json.dumps(result, ensure_ascii=True),
            ),
        )
        conn.commit()

    if output_file:
        ensure_parent_dir(output_file)
        with open(output_file, "w", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2, ensure_ascii=True)
            handle.write("\n")

    audit_log(
        log_file,
        "scan_completed",
        {
            "total_installed_packages": result["total_installed_packages"],
            "vulnerable_findings": result["vulnerable_findings"],
            "vulnerable_packages": result["vulnerable_packages"],
        },
    )
    return result


def run_command(cmd: list[str]) -> tuple[int, str, str]:
    result = subprocess.run(cmd, check=False, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr


def patch_packages(
    db_path: str,
    log_file: str,
    scan_input_file: str | None,
    dry_run: bool,
    output_file: str | None,
) -> dict[str, Any]:
    if scan_input_file:
        with open(scan_input_file, "r", encoding="utf-8") as handle:
            scan_result = json.load(handle)
    else:
        scan_result = scan_local_packages(db_path, log_file, output_file=None)

    targets = sorted({pkg["package"] for pkg in scan_result.get("packages", [])})
    before_findings = int(scan_result.get("vulnerable_findings", 0))

    update_cmd = ["sudo", "/usr/bin/apt-get", "update"]
    upgrade_cmd = ["sudo", "/usr/bin/apt-get", "install", "--only-upgrade", "-y", *targets]

    command_results: dict[str, Any] = {
        "update": {"command": " ".join(update_cmd), "return_code": None},
        "upgrade": {"command": " ".join(upgrade_cmd), "return_code": None},
    }

    update_ok = True
    upgrade_ok = True

    if targets and not dry_run:
        rc, out, err = run_command(update_cmd)
        command_results["update"].update({"return_code": rc, "stdout": out[-4000:], "stderr": err[-4000:]})
        update_ok = rc == 0

        if update_ok:
            rc, out, err = run_command(upgrade_cmd)
            command_results["upgrade"].update({"return_code": rc, "stdout": out[-4000:], "stderr": err[-4000:]})
            upgrade_ok = rc == 0
        else:
            upgrade_ok = False

    after_scan = scan_local_packages(db_path, log_file, output_file=None)
    after_findings = int(after_scan.get("vulnerable_findings", 0))

    mitigated = max(before_findings - after_findings, 0)
    success_rate = 100.0 if before_findings == 0 else round((mitigated / before_findings) * 100, 2)

    summary = {
        "timestamp": utc_now(),
        "dry_run": dry_run,
        "targets": targets,
        "target_count": len(targets),
        "before_findings": before_findings,
        "after_findings": after_findings,
        "mitigated_findings": mitigated,
        "mitigation_success_rate": success_rate,
        "commands": command_results,
        "status": "success" if (dry_run or (update_ok and upgrade_ok)) else "failed",
    }

    if output_file:
        ensure_parent_dir(output_file)
        with open(output_file, "w", encoding="utf-8") as handle:
            json.dump(summary, handle, indent=2, ensure_ascii=True)
            handle.write("\n")

    with get_connection(db_path) as conn:
        conn.execute(
            """
            INSERT INTO patch_history(run_at, target_count, success_count, failed_count, output_json)
            VALUES(?, ?, ?, ?, ?)
            """,
            (
                summary["timestamp"],
                len(targets),
                len(targets) if summary["status"] == "success" else 0,
                0 if summary["status"] == "success" else len(targets),
                json.dumps(summary, ensure_ascii=True),
            ),
        )
        conn.commit()

    audit_log(
        log_file,
        "patch_completed",
        {
            "target_count": len(targets),
            "status": summary["status"],
            "mitigation_success_rate": success_rate,
        },
        level="ERROR" if summary["status"] == "failed" else "INFO",
    )

    return summary


def generate_report(db_path: str, log_file: str, output_file: str) -> dict[str, Any]:
    init_db(db_path)

    with get_connection(db_path) as conn:
        last_scan = conn.execute(
            "SELECT run_at, vulnerable_findings, vulnerable_packages, output_json FROM scan_history ORDER BY id DESC LIMIT 1"
        ).fetchone()
        last_patch = conn.execute(
            "SELECT run_at, target_count, success_count, failed_count, output_json FROM patch_history ORDER BY id DESC LIMIT 1"
        ).fetchone()

    report: dict[str, Any] = {
        "generated_at": utc_now(),
        "latest_scan": json.loads(last_scan["output_json"]) if last_scan else None,
        "latest_patch": json.loads(last_patch["output_json"]) if last_patch else None,
    }

    if last_patch:
        patch_json = json.loads(last_patch["output_json"])
        report["mitigation_success_rate"] = patch_json.get("mitigation_success_rate")
    else:
        report["mitigation_success_rate"] = None

    ensure_parent_dir(output_file)
    with open(output_file, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=True)
        handle.write("\n")

    audit_log(log_file, "report_generated", {"report_output": output_file})
    return report


def print_json(data: dict[str, Any]) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=True))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vuln-patch-agent",
        description="Ubuntu 22.04 Vulnerability Discovery & Patch Agent (MVP)",
    )
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH, help="Path to JSON config file")

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init-db", help="Initialize SQLite database")

    sync_parser = sub.add_parser("sync-nvd", help="Sync CVE data from NVD API 2.0")
    sync_parser.add_argument("--api-key", default=None, help="NVD API key")
    sync_parser.add_argument("--api-key-env", default="NVD_API_KEY", help="Environment variable name for NVD API key")
    sync_parser.add_argument("--since", default=None, help="Override incremental start date (ISO8601)")
    sync_parser.add_argument("--max-pages", type=int, default=None, help="Limit pages for controlled sync")

    oval_parser = sub.add_parser("import-oval", help="Import package aliases from Ubuntu OVAL XML")
    oval_parser.add_argument("--file", required=True, help="Path to Ubuntu OVAL XML file")

    scan_parser = sub.add_parser("scan", help="Scan installed packages against vulnerability DB")
    scan_parser.add_argument("--output", default=None, help="Output JSON path")

    patch_parser = sub.add_parser("patch", help="Patch vulnerable packages using selective sudo")
    patch_parser.add_argument("--scan-file", default=None, help="Use scan JSON instead of scanning live")
    patch_parser.add_argument("--dry-run", action="store_true", help="Do not execute apt commands")
    patch_parser.add_argument("--output", default=None, help="Output JSON path")

    run_parser = sub.add_parser("run", help="Run end-to-end pipeline")
    run_parser.add_argument("--api-key", default=None)
    run_parser.add_argument("--api-key-env", default="NVD_API_KEY")
    run_parser.add_argument("--since", default=None)
    run_parser.add_argument("--max-pages", type=int, default=None)
    run_parser.add_argument("--oval-file", default=None, help="Optional Ubuntu OVAL XML path")
    run_parser.add_argument("--patch", action="store_true", help="Execute patch step")
    run_parser.add_argument("--dry-run", action="store_true", help="Dry-run for patch step")
    run_parser.add_argument("--output", default=None, help="Pipeline output JSON path")

    report_parser = sub.add_parser("report", help="Generate latest mitigation report")
    report_parser.add_argument("--output", default=None, help="Output report path")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    config = load_config(args.config)
    db_path = config["db_path"]
    log_file = config["audit_log"]
    scan_output = config["scan_output"]
    report_output = config["report_output"]
    endpoint = config["nvd_endpoint"]
    results_per_page = int(config.get("results_per_page", 2000))

    try:
        if args.command == "init-db":
            init_db(db_path)
            output = {"status": "ok", "db_path": db_path}
            audit_log(log_file, "db_initialized", output)
            print_json(output)
            return 0

        if args.command == "sync-nvd":
            api_key = args.api_key or os.environ.get(args.api_key_env)
            output = sync_nvd_data(
                db_path=db_path,
                log_file=log_file,
                endpoint=endpoint,
                api_key=api_key,
                since=args.since,
                results_per_page=results_per_page,
                max_pages=args.max_pages,
            )
            print_json(output)
            return 0

        if args.command == "import-oval":
            output = import_oval_aliases(db_path=db_path, log_file=log_file, oval_path=args.file)
            print_json(output)
            return 0

        if args.command == "scan":
            output = scan_local_packages(db_path=db_path, log_file=log_file, output_file=args.output or scan_output)
            print_json(output)
            return 0

        if args.command == "patch":
            output = patch_packages(
                db_path=db_path,
                log_file=log_file,
                scan_input_file=args.scan_file,
                dry_run=args.dry_run,
                output_file=args.output,
            )
            print_json(output)
            return 0

        if args.command == "run":
            api_key = args.api_key or os.environ.get(args.api_key_env)
            pipeline: dict[str, Any] = {
                "timestamp": utc_now(),
                "steps": {},
            }
            pipeline["steps"]["sync_nvd"] = sync_nvd_data(
                db_path=db_path,
                log_file=log_file,
                endpoint=endpoint,
                api_key=api_key,
                since=args.since,
                results_per_page=results_per_page,
                max_pages=args.max_pages,
            )

            if args.oval_file:
                pipeline["steps"]["import_oval"] = import_oval_aliases(db_path, log_file, args.oval_file)

            pipeline["steps"]["scan"] = scan_local_packages(db_path, log_file, output_file=scan_output)

            if args.patch:
                pipeline["steps"]["patch"] = patch_packages(
                    db_path=db_path,
                    log_file=log_file,
                    scan_input_file=None,
                    dry_run=args.dry_run,
                    output_file=None,
                )

            if args.output:
                ensure_parent_dir(args.output)
                with open(args.output, "w", encoding="utf-8") as handle:
                    json.dump(pipeline, handle, indent=2, ensure_ascii=True)
                    handle.write("\n")

            print_json(pipeline)
            return 0

        if args.command == "report":
            output = generate_report(db_path=db_path, log_file=log_file, output_file=args.output or report_output)
            print_json(output)
            return 0

        parser.print_help()
        return 1

    except Exception as exc:  # pragma: no cover - top-level guard
        try:
            audit_log(log_file, "agent_error", {"error": str(exc)}, level="ERROR")
        except Exception:
            pass
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
