"""Automated tests for the CloudSentinel checks, reports and CLI."""

import json

import pytest

from cloudsentinel.checks import (
    NEEDS_ATTENTION,
    PASS,
    WARNING,
    analyse_bucket,
    check_encryption,
    check_public_access,
    check_versioning,
)
from cloudsentinel.main import load_buckets, main
from cloudsentinel.report import summarise


def secure_bucket():
    """A bucket where everything is configured safely."""
    return {
        "bucket_name": "secure-bucket",
        "region": "ap-south-1",
        "public_access_block": {
            "block_public_acls": True,
            "ignore_public_acls": True,
            "block_public_policy": True,
            "restrict_public_buckets": True,
        },
        "encryption": {"enabled": True, "algorithm": "aws:kms"},
        "versioning": "Enabled",
    }


def insecure_bucket():
    """A bucket where nothing is protected."""
    return {
        "bucket_name": "insecure-bucket",
        "region": "ap-south-1",
        "public_access_block": {
            "block_public_acls": False,
            "ignore_public_acls": False,
            "block_public_policy": False,
            "restrict_public_buckets": False,
        },
        "encryption": {"enabled": False, "algorithm": None},
        "versioning": "Disabled",
    }


# ---------- Public access block ----------

def test_public_access_all_on_passes():
    finding = check_public_access(secure_bucket())
    assert finding["status"] == PASS
    assert finding["risk"] == "LOW"


def test_public_access_all_off_needs_attention():
    finding = check_public_access(insecure_bucket())
    assert finding["status"] == NEEDS_ATTENTION
    assert finding["risk"] == "HIGH"


def test_public_access_partial_is_warning():
    bucket = secure_bucket()
    bucket["public_access_block"]["block_public_policy"] = False
    finding = check_public_access(bucket)
    assert finding["status"] == WARNING
    assert "block_public_policy" in finding["message"]


def test_public_access_missing_section_needs_attention():
    bucket = secure_bucket()
    del bucket["public_access_block"]
    assert check_public_access(bucket)["status"] == NEEDS_ATTENTION


# ---------- Encryption ----------

def test_encryption_kms_passes():
    assert check_encryption(secure_bucket())["status"] == PASS


def test_encryption_aes256_passes():
    bucket = secure_bucket()
    bucket["encryption"]["algorithm"] = "AES256"
    assert check_encryption(bucket)["status"] == PASS


def test_encryption_disabled_needs_attention():
    finding = check_encryption(insecure_bucket())
    assert finding["status"] == NEEDS_ATTENTION
    assert finding["risk"] == "HIGH"


def test_encryption_unknown_algorithm_is_warning():
    bucket = secure_bucket()
    bucket["encryption"]["algorithm"] = "something-else"
    assert check_encryption(bucket)["status"] == WARNING


# ---------- Versioning ----------

def test_versioning_enabled_passes():
    assert check_versioning(secure_bucket())["status"] == PASS


def test_versioning_suspended_is_warning():
    bucket = secure_bucket()
    bucket["versioning"] = "Suspended"
    assert check_versioning(bucket)["status"] == WARNING


def test_versioning_disabled_is_warning():
    assert check_versioning(insecure_bucket())["status"] == WARNING


# ---------- Whole-bucket analysis and summary ----------

def test_secure_bucket_has_no_problems():
    result = analyse_bucket(secure_bucket())
    assert len(result["findings"]) == 3
    assert all(f["status"] == PASS for f in result["findings"])


def test_insecure_bucket_has_problems():
    result = analyse_bucket(insecure_bucket())
    statuses = [f["status"] for f in result["findings"]]
    assert statuses.count(NEEDS_ATTENTION) == 2
    assert statuses.count(WARNING) == 1


def test_summary_counts_are_correct():
    results = [analyse_bucket(secure_bucket()), analyse_bucket(insecure_bucket())]
    summary = summarise(results)
    assert summary[PASS] == 3
    assert summary[WARNING] == 1
    assert summary[NEEDS_ATTENTION] == 2


# ---------- Error handling and CLI ----------

def test_load_buckets_missing_file_raises_clear_error():
    with pytest.raises(ValueError, match="not found"):
        load_buckets("does_not_exist.json")


def test_load_buckets_invalid_json_raises_clear_error(tmp_path):
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("{ this is not json")
    with pytest.raises(ValueError, match="not valid JSON"):
        load_buckets(str(bad_file))


def test_load_buckets_rejects_non_list(tmp_path):
    bad_file = tmp_path / "object.json"
    bad_file.write_text('{"bucket_name": "x"}')
    with pytest.raises(ValueError, match="list of buckets"):
        load_buckets(str(bad_file))


def test_main_returns_1_for_missing_input(capsys):
    exit_code = main(["--input", "nope.json"])
    assert exit_code == 1
    assert "Error" in capsys.readouterr().err


def test_main_writes_json_report(tmp_path):
    input_file = tmp_path / "buckets.json"
    input_file.write_text(json.dumps([secure_bucket(), insecure_bucket()]))
    output_file = tmp_path / "out" / "report.json"

    exit_code = main(["--input", str(input_file), "--output", str(output_file)])

    assert exit_code == 0
    report = json.loads(output_file.read_text())
    assert report["tool"] == "CloudSentinel"
    assert report["summary"]["NEEDS ATTENTION"] == 2
    assert len(report["buckets"]) == 2