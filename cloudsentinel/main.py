"""CloudSentinel entry point: load data, analyse buckets, print and save reports."""

import argparse
import json
import sys

from cloudsentinel.checks import analyse_bucket
from cloudsentinel.report import format_terminal_report, save_json_report

DEFAULT_INPUT = "data/sample_buckets.json"
DEFAULT_OUTPUT = "reports/report.json"


def load_buckets(path):
    """Read bucket data from a JSON file and validate its basic shape."""
    try:
        with open(path, "r", encoding="utf-8") as file:
            data = json.load(file)
    except FileNotFoundError:
        raise ValueError(f"Input file not found: {path}")
    except json.JSONDecodeError as error:
        raise ValueError(f"Input file is not valid JSON ({error}).")

    if not isinstance(data, list):
        raise ValueError("Input JSON must be a list of buckets.")
    for index, bucket in enumerate(data):
        if not isinstance(bucket, dict):
            raise ValueError(f"Item {index} in the input is not a bucket object.")
    return data


def parse_arguments(argv):
    """Read options typed after the command."""
    parser = argparse.ArgumentParser(
        description="CloudSentinel: check S3 bucket settings for security issues."
    )
    parser.add_argument("--input", default=DEFAULT_INPUT, help="JSON file with bucket data")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="where to save the JSON report")
    return parser.parse_args(argv)


def main(argv=None):
    """Run the tool. Returns 0 on success and 1 on error."""
    args = parse_arguments(argv)

    try:
        buckets = load_buckets(args.input)
        results = [analyse_bucket(bucket) for bucket in buckets]
        print(format_terminal_report(results))
        saved_to = save_json_report(results, args.input, args.output)
    except ValueError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    except OSError as error:
        print(f"Error: could not write the report ({error}).", file=sys.stderr)
        return 1

    print(f"\nJSON report saved to: {saved_to}")
    return 0


if __name__ == "__main__":
    sys.exit(main())