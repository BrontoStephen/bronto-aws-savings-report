"""Amazon Managed Grafana probe."""

from __future__ import annotations

from dataclasses import dataclass, field

import boto3

from .common import for_regions, safe


@dataclass
class AMGProbeResult:
    workspace_count: int = 0
    by_region: dict[str, dict] = field(default_factory=dict)


def _probe_region(session: boto3.Session, region: str) -> dict:
    g = session.client("grafana", region_name=region)
    workspaces: list[dict] = []
    paginator = g.get_paginator("list_workspaces")
    for page in paginator.paginate():
        workspaces.extend(page.get("workspaces", []))
    return {"workspaces": len(workspaces)}


def run(session: boto3.Session, regions: list[str]) -> AMGProbeResult:
    per_region = for_regions(regions, lambda r: safe(lambda: _probe_region(session, r), what=f"amg:{r}", default={}))
    result = AMGProbeResult(by_region=per_region)
    for r, data in per_region.items():
        if not data:
            continue
        result.workspace_count += data.get("workspaces", 0)
    return result
