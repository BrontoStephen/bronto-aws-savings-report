"""CloudWatch Logs probe — log groups, retention, stored bytes."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

import boto3

from .common import for_regions, safe


@dataclass
class LogsProbeResult:
    group_count: int = 0
    stored_bytes: int = 0
    retention_histogram: dict[str, int] = field(default_factory=dict)
    groups_never_expire: int = 0
    by_region: dict[str, dict] = field(default_factory=dict)


def _retention_bucket(days: int | None) -> str:
    if days is None:
        return "never"
    if days <= 7:
        return "<=7d"
    if days <= 30:
        return "<=30d"
    if days <= 90:
        return "<=90d"
    if days <= 365:
        return "<=365d"
    return ">365d"


def _probe_region(session: boto3.Session, region: str) -> dict:
    logs = session.client("logs", region_name=region)
    groups = 0
    stored = 0
    hist: Counter[str] = Counter()
    never = 0
    paginator = logs.get_paginator("describe_log_groups")
    for page in paginator.paginate():
        for g in page.get("logGroups", []):
            groups += 1
            stored += int(g.get("storedBytes", 0))
            retention = g.get("retentionInDays")
            hist[_retention_bucket(retention)] += 1
            if retention is None:
                never += 1
    return {
        "group_count": groups,
        "stored_bytes": stored,
        "retention_histogram": dict(hist),
        "groups_never_expire": never,
    }


def run(session: boto3.Session, regions: list[str]) -> LogsProbeResult:
    per_region = for_regions(regions, lambda r: safe(lambda: _probe_region(session, r), what=f"logs:{r}", default={}))
    result = LogsProbeResult(by_region=per_region)
    hist: Counter[str] = Counter()
    for r, data in per_region.items():
        if not data:
            continue
        result.group_count += data.get("group_count", 0)
        result.stored_bytes += data.get("stored_bytes", 0)
        result.groups_never_expire += data.get("groups_never_expire", 0)
        for k, v in data.get("retention_histogram", {}).items():
            hist[k] += v
    result.retention_histogram = dict(hist)
    return result
