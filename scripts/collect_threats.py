
import json
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
OUTPUT_FILE = DATA_DIR / "vulnerabilities.json"


def generate_report():
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    report = {
        "project": "Cyber Threat Intelligence",
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "vulnerabilities": []
    }

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print("Threat intelligence report generated.")


if __name__ == "__main__":
    generate_report()
