
import json
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_collector_generates_report():
    script = PROJECT_ROOT / "scripts" / "collect_threats.py"

    result = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True,
        text=True
    )

    assert result.returncode == 0

    output_file = PROJECT_ROOT / "data" / "vulnerabilities.json"

    assert output_file.exists()

    report = json.loads(output_file.read_text())

    assert report["project"] == "Cyber Threat Intelligence"
    assert "vulnerabilities" in report
