
import json
import requests

from pathlib import Path
from datetime import datetime, timezone
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# ==========================================
# PROJECT CONFIGURATION
# ==========================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATA_DIR = PROJECT_ROOT / "data"

OUTPUT_FILE = DATA_DIR / "vulnerabilities.json"

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


# ==========================================
# CREATE HTTP SESSION WITH AUTOMATIC RETRIES
# ==========================================

def create_session():

    retry_strategy = Retry(
        total=5,
        backoff_factor=2,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
        respect_retry_after_header=True
    )

    session = requests.Session()

    adapter = HTTPAdapter(max_retries=retry_strategy)

    session.mount("https://", adapter)

    return session


# ==========================================
# COLLECT VULNERABILITIES FROM NIST
# ==========================================

def collect_vulnerabilities():

    print("Connecting to NIST vulnerability database...")

    session = create_session()

    params = {
        "resultsPerPage": 20
    }

    response = session.get(
        NVD_API,
        params=params,
        timeout=30
    )

    response.raise_for_status()

    records = response.json().get("vulnerabilities", [])

    vulnerabilities = []

    print("Processing vulnerability records...")

    for record in records:

        cve = record.get("cve", {})

        # Extract vulnerability ID
        cve_id = cve.get("id")

        # Extract English description
        descriptions = cve.get("descriptions", [])

        description = next(
            (
                item["value"]
                for item in descriptions
                if item.get("lang") == "en"
            ),
            "No description available"
        )

        # Extract CVSS information
        metrics = cve.get("metrics", {})

        score = None
        severity = "Unknown"
        cvss_version = "Unavailable"

        # Check supported CVSS versions
        cvss_sources = [
            ("cvssMetricV40", "CVSS 4.0"),
            ("cvssMetricV31", "CVSS 3.1"),
            ("cvssMetricV30", "CVSS 3.0"),
            ("cvssMetricV2", "CVSS 2.0")
        ]

        for metric_key, version_name in cvss_sources:

            cvss_entries = metrics.get(metric_key, [])

            if cvss_entries:

                score_data = cvss_entries[0].get(
                    "cvssData", {}
                )

                score = score_data.get("baseScore")

                severity = (
                    score_data.get("baseSeverity")
                    or cvss_entries[0].get("baseSeverity")
                    or "Unknown"
                )

                cvss_version = version_name

                break

        # Store vulnerability information
        vulnerabilities.append({
            "id": cve_id,
            "description": description,
            "score": score,
            "severity": severity,
            "cvss_version": cvss_version,
            "published": cve.get("published")
        })

    return vulnerabilities


# ==========================================
# GENERATE JSON VULNERABILITY REPORT
# ==========================================

def generate_report():

    print("Starting vulnerability report generation...")

    DATA_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    vulnerabilities = collect_vulnerabilities()

    report = {
        "project": "Cyber Threat Intelligence",
        "last_updated": datetime.now(
            timezone.utc
        ).isoformat(),
        "total_vulnerabilities": len(vulnerabilities),
        "vulnerabilities": vulnerabilities
    }

    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            indent=4
        )

    print("----------------------------------")
    print("Vulnerability report generated!")
    print("Total records:", len(vulnerabilities))
    print("Output file:", OUTPUT_FILE)
    print("----------------------------------")


# ==========================================
# MAIN EXECUTION
# ==========================================

if __name__ == "__main__":

    try:
        generate_report()

    except requests.exceptions.RequestException as error:

        print("NIST API request failed:", error)
        raise

    except (ValueError, OSError) as error:

        print("Report generation failed:", error)
        raise
