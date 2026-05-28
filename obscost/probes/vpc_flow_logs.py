"""VPC Flow Logs probe — counts by destination type."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

import boto3

from .common import for_regions, safe


@dataclass
class VPCFlowLogsProbeResult:
    flow_log_count: int = 0
    by_destination: dict[str, int] = field(default_factory=dict)
    by_region: dict[str, dict] = field(default_factory=dict)


def _probe_region(session: boto3.Session, region: str) -> dict:
    ec2 = session.client("ec2", region_name=region)
    dest_counts: Counter[str] = Counter()
    total = 0
    paginator = ec2.get_paginator("describe_flow_logs")
    for page in paginator.paginate():
        for fl in page.get("FlowLogs", []):
            total += 1
            dest_counts[fl.get("LogDestinationType", "unknown")] += 1
    return {"count": total, "destinations": dict(dest_counts)}


def run(session: boto3.Session, regions: list[str]) -> VPCFlowLogsProbeResult:
    per_region = for_regions(regions, lambda r: safe(lambda: _probe_region(session, r), what=f"vpc-flow:{r}", default={}))
    result = VPCFlowLogsProbeResult(by_region=per_region)
    combined: Counter[str] = Counter()
    for r, data in per_region.items():
        if not data:
            continue
        result.flow_log_count += data.get("count", 0)
        for k, v in data.get("destinations", {}).items():
            combined[k] += v
    result.by_destination = dict(combined)
    return result
