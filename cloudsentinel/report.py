"""Turn analysis results into a terminal report and a JSON report."""

import json
import os
from datetime import datetime, timezone

from cloudsentinel.checks import PASS, WARNING, NEEDS_ATTENTION

# Order used to sort findings: most serious first.
SEVERITY_ORDER = {NEEDS_ATTENTION: 0, WARNING: 1, PASS: 2}


def summarise(results):
    """Count how many findings of each status exist across all buckets."""
    summary = {PASS: 0, WARNING: 0, NEEDS_ATTENTION: 0}
    for bucket in results:
        for finding in bucket["findings"]:
            summary[finding["status"]] += 1
    return summary


def format_terminal_report(results):
    """Build the human-readable report as one string."""
    lines = []
    lines.append("=" * 64)
    lines.append("CloudSentinel: S3 Storage Security Report")
    lines.append("=" * 64)

    for bucket in results:
        lines.append("")
        lines.append(f"Bucket: {bucket['bucket_name']}  (region: {bucket['region']})")
        lines.append("-" * 64)

        # Sort so the most serious findings appear first.
        ordered = sorted(bucket["findings"], key=lambda f: SEVERITY_ORDER[f["status"]])
        for finding in ordered:
            lines.append(f"  [{finding['status']}] {finding['check']}  (risk: {finding['risk']})")
            lines.append(f"      {finding['message']}")
            if finding["status"] != PASS:
                lines.append(f"      Fix: {finding['recommendation']}")

    summary = summarise(results)
    lines.append("")
    lines.append("=" * 64)
    lines.append("SUMMARY")
    lines.append(f"  Buckets analysed : {len(results)}")
    lines.append(f"  PASS             : {summary[PASS]}")
    lines.append(f"  WARNING          : {summary[WARNING]}")
    lines.append(f"  NEEDS ATTENTION  : {summary[NEEDS_ATTENTION]}")
    lines.append("=" * 64)
    return "\n".join(lines)


def build_json_report(results, source):
    """Build the data structure that is saved as the JSON report."""
    return {
        "tool": "CloudSentinel",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "data_source": source,
        "summary": summarise(results),
        "buckets": results,
    }


def save_json_report(results, source, output_path):
    """Write the JSON report to a file, creating the folder if needed."""
    folder = os.path.dirname(output_path)
    if folder:
        os.makedirs(folder, exist_ok=True)

    report = build_json_report(results, source)
    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)
    return output_path