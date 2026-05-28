"""X-Ray probe — traces received (from CloudWatch metric) + sampling rules."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import boto3

from .common import for_regions, safe


@dataclass
class XRayProbeResult:
    sampling_rules: int = 0
    traces_received: float = 0.0
    by_region: dict[str, dict] = field(default_factory=dict)


def _probe_region(session: boto3.Session, region: str, days: int) -> dict:
    xray = session.client("xray", region_name=region)
    rules = 0
    paginator = xray.get_paginator("get_sampling_rules")
    for page in paginator.paginate():
        rules += len(page.get("SamplingRuleRecords", []))

    cw = session.client("cloudwatch", region_name=region)
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    resp = cw.get_metric_statistics(
        Namespace="AWS/X-Ray",
        MetricName="TracesReceived",
        StartTime=start,
        EndTime=end,
        Period=86400,
        Statistics=["Sum"],
    )
    traces = sum(p.get("Sum", 0.0) for p in resp.get("Datapoints", []))
    return {"sampling_rules": rules, "traces_received": traces}


def run(session: boto3.Session, regions: list[str], days: int = 30) -> XRayProbeResult:
    per_region = for_regions(regions, lambda r: safe(lambda: _probe_region(session, r, days), what=f"xray:{r}", default={}))
    result = XRayProbeResult(by_region=per_region)
    for r, data in per_region.items():
        if not data:
            continue
        result.sampling_rules += data.get("sampling_rules", 0)
        result.traces_received += data.get("traces_received", 0.0)
    return result
