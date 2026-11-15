
import json
import requests
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
OUTPUT_FILE = DATA_DIR / "vulnerabilities.json"

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def collect_vulnerabilities():
    params = {
        "resultsPerPage": 20
    }

    response = requests.get(
        NVD_API,
        params=params,
        timeout=30
    )

    response.raise_for_status()

    records = response.json().get("vulnerabilities", [])

    vulnerabilities = []

    for record in records:
        cve = record.get("cve", {})

        descriptions = cve.get("descriptions", [])
        description = next(
            (
                item["value"]
                for item in descriptions
                if item.get("lang") == "en"
            ),
            "No description available"
        )

        metrics = cve.get("metrics", {})
        cvss = metrics.get("cvssMetricV31", [])

        score = None
        severity = "Unknown"

        if cvss:
            score_data = cvss[0]["cvssData"]
            score = score_data.get("baseScore")
            severity = score_data.get("baseSeverity", "Unknown")

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

    report["vulnerabilities"] = collect_vulnerabilities()
    report["total_vulnerabilities"] = len(
        report["vulnerabilities"]
    )

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print("Vulnerability report generated.")
    print("Records:", report["total_vulnerabilities"])


if __name__ == "__main__":
    generate_report()
