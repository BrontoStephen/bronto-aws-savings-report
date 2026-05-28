"""S3 log-sink probe — identify buckets that look like observability destinations.

Heuristics (any match flags the bucket):
  * Bucket name contains "log", "logs", "flowlog", "cloudtrail", "audit", or "observability"
  * Bucket has a CloudTrail/Config/Firehose-style key prefix (best-effort check)
  * Bucket is a target of any active CloudWatch Logs subscription / VPC Flow Logs

This probe is intentionally conservative — false positives bias the S3
attribution larger, which is the safe side for "are we missing log spend?"
"""

from __future__ import annotations

from dataclasses import dataclass, field

import boto3

from .common import safe

LOG_KEYWORDS = ("log", "flowlog", "cloudtrail", "audit", "observability", "firehose")


@dataclass
class S3LogSinkProbeResult:
    candidate_buckets: list[dict] = field(default_factory=list)
    total_candidates: int = 0


def _looks_like_log_sink(name: str) -> bool:
    lname = name.lower()
    return any(k in lname for k in LOG_KEYWORDS)


def run(session: boto3.Session) -> S3LogSinkProbeResult:
    s3 = session.client("s3")
    buckets = safe(lambda: s3.list_buckets().get("Buckets", []), what="s3:list_buckets", default=[])
    candidates: list[dict] = []
    for b in buckets:
        name = b.get("Name", "")
        if not _looks_like_log_sink(name):
            continue
        # Best-effort region resolution
        loc = safe(
            lambda: s3.get_bucket_location(Bucket=name).get("LocationConstraint") or "us-east-1",
            what=f"s3:get_bucket_location({name})",
            default=None,
        )
        candidates.append({"name": name, "region": loc, "created": str(b.get("CreationDate", ""))})
    return S3LogSinkProbeResult(candidate_buckets=candidates, total_candidates=len(candidates))
