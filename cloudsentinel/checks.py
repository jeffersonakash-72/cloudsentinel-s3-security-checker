"""Security checks for S3 bucket configuration data.

Each check looks at one bucket and returns a "finding": a dictionary
describing the result, the risk level and the recommended fix.
"""

# The three possible results of a check.
PASS = "PASS"
WARNING = "WARNING"
NEEDS_ATTENTION = "NEEDS ATTENTION"

# The four switches that make up S3 "Block Public Access".
PUBLIC_ACCESS_SETTINGS = [
    "block_public_acls",
    "ignore_public_acls",
    "block_public_policy",
    "restrict_public_buckets",
]


def make_finding(check, status, risk, message, recommendation):
    """Build one finding in a consistent format."""
    return {
        "check": check,
        "status": status,
        "risk": risk,
        "message": message,
        "recommendation": recommendation,
    }


def check_public_access(bucket):
    """Check whether all four Block Public Access switches are on."""
    settings = bucket.get("public_access_block")
    check_name = "Public access block"

    if not isinstance(settings, dict):
        return make_finding(
            check_name, NEEDS_ATTENTION, "HIGH",
            "No public access block configuration was found.",
            "Enable all four S3 Block Public Access settings on this bucket.",
        )

    # Collect the names of any switches that are not exactly True.
    missing = [name for name in PUBLIC_ACCESS_SETTINGS if settings.get(name) is not True]

    if len(missing) == len(PUBLIC_ACCESS_SETTINGS):
        return make_finding(
            check_name, NEEDS_ATTENTION, "HIGH",
            "All four public access protections are off.",
            "Enable all four S3 Block Public Access settings unless this "
            "bucket must intentionally serve public content.",
        )
    if missing:
        return make_finding(
            check_name, WARNING, "MEDIUM",
            "Some public access protections are off: " + ", ".join(missing) + ".",
            "Turn on the missing Block Public Access settings.",
        )
    return make_finding(
        check_name, PASS, "LOW",
        "All four public access protections are on.",
        "No action needed.",
    )


def check_encryption(bucket):
    """Check whether default encryption is enabled."""
    settings = bucket.get("encryption")
    check_name = "Encryption"

    if not isinstance(settings, dict) or settings.get("enabled") is not True:
        return make_finding(
            check_name, NEEDS_ATTENTION, "HIGH",
            "Default encryption is not enabled.",
            "Enable default encryption (SSE-S3 or SSE-KMS) on the bucket.",
        )

    algorithm = settings.get("algorithm")
    if algorithm == "aws:kms":
        return make_finding(
            check_name, PASS, "LOW",
            "Encryption is enabled using AWS KMS.",
            "No action needed.",
        )
    if algorithm == "AES256":
        return make_finding(
            check_name, PASS, "LOW",
            "Encryption is enabled using S3-managed keys (AES256).",
            "Consider KMS keys if you need audit trails or key control.",
        )
    return make_finding(
        check_name, WARNING, "MEDIUM",
        "Encryption is enabled but the algorithm is unrecognised.",
        "Verify the encryption algorithm in the S3 console.",
    )


def check_versioning(bucket):
    """Check whether versioning is turned on."""
    status = bucket.get("versioning")
    check_name = "Versioning"

    if status == "Enabled":
        return make_finding(
            check_name, PASS, "LOW",
            "Versioning is enabled.",
            "No action needed.",
        )
    if status == "Suspended":
        return make_finding(
            check_name, WARNING, "MEDIUM",
            "Versioning was turned on before but is now suspended.",
            "Re-enable versioning to protect against accidental deletion.",
        )
    return make_finding(
        check_name, WARNING, "MEDIUM",
        "Versioning is disabled.",
        "Enable versioning so deleted or overwritten files can be recovered.",
    )


def analyse_bucket(bucket):
    """Run all three checks on one bucket and return the results."""
    return {
        "bucket_name": bucket.get("bucket_name", "unknown"),
        "region": bucket.get("region", "unknown"),
        "findings": [
            check_public_access(bucket),
            check_encryption(bucket),
            check_versioning(bucket),
        ],
    }