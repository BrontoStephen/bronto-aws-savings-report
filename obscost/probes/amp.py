"""Amazon Managed Service for Prometheus probe."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import boto3

from .common import for_regions, safe


@dataclass
class AMPProbeResult:
    workspace_count: int = 0
    ingested_samples: float = 0.0
    by_region: dict[str, dict] = field(default_factory=dict)


def _probe_region(session: boto3.Session, region: str, days: int) -> dict:
    amp = session.client("amp", region_name=region)
    workspaces: list[dict] = []
    paginator = amp.get_paginator("list_workspaces")
    for page in paginator.paginate():
        workspaces.extend(page.get("workspaces", []))

    cw = session.client("cloudwatch", region_name=region)
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    samples = 0.0
    for ws in workspaces:
        wsid = ws.get("workspaceId")
        if not wsid:
            continue
        resp = cw.get_metric_statistics(
            Namespace="AWS/Prometheus",
            MetricName="IngestedSamples",
            Dimensions=[{"Name": "WorkspaceId", "Value": wsid}],
            StartTime=start,
            EndTime=end,
            Period=86400,
            Statistics=["Sum"],
        )
        samples += sum(p.get("Sum", 0.0) for p in resp.get("Datapoints", []))
    return {"workspaces": len(workspaces), "ingested_samples": samples}


def run(session: boto3.Session, regions: list[str], days: int = 30) -> AMPProbeResult:
    per_region = for_regions(regions, lambda r: safe(lambda: _probe_region(session, r, days), what=f"amp:{r}", default={}))
    result = AMPProbeResult(by_region=per_region)
    for r, data in per_region.items():
        if not data:
            continue
        result.workspace_count += data.get("workspaces", 0)
        result.ingested_samples += data.get("ingested_samples", 0.0)
    return result
