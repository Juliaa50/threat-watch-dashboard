
import json
import requests

from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from datetime import datetime, timezone
from pathlib import Path


# Project directories
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
OUTPUT_FILE = DATA_DIR / "vulnerabilities.json"

# NIST National Vulnerability Database API
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def collect_vulnerabilities():

    # Configure automatic retries for temporary API failures
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

    params = {
        "resultsPerPage": 20
    }

    print("Connecting to NIST vulnerability database...")

    response = session.get(
        NVD_API,
        params=params,
        timeout=30
    )

    response.raise_for_status()

    records = response.json().get("vulnerabilities", [])

    vulnerabilities = []

    for record in records:

        cve = record.get("cve", {})

        # Extract English vulnerability description
        descriptions = cve.get("descriptions", [])

        description = next(
            (
                item["value"]
                for item in descriptions
                if item.get("lang") == "en"
            ),
            "No description available"
        )

        # Extract CVSS severity information
        metrics = cve.get("metrics", {})
        cvss = metrics.get("cvssMetricV31", [])

        score = None
        severity = "Unknown"

        if cvss:
            score_data = cvss[0]["cvssData"]
            score = score_data.get("baseScore")
            severity = score_data.get(
                "baseSeverity",
                "Unknown"
            )

        # Store vulnerability information
        vulnerabilities.append({
            "id": cve.get("id"),
            "description": description,
            "score": score,
            "severity": severity,
            "published": cve.get("published")
        })

    return vulnerabilities


def generate_report():

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    report = {
        "project": "Cyber Threat Intelligence",
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "total_vulnerabilities": 0,
        "vulnerabilities": []
    }

    # Collect vulnerability information
    report["vulnerabilities"] = collect_vulnerabilities()

    report["total_vulnerabilities"] = len(
        report["vulnerabilities"]
    )

    # Save report as JSON
    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print("Vulnerability report generated.")
    print("Total records:", report["total_vulnerabilities"])
    print("Saved to:", OUTPUT_FILE)


if __name__ == "__main__":
    generate_report()
