"""CloudWatch Metrics / Alarms / Dashboards probe."""

from __future__ import annotations

from dataclasses import dataclass, field

import boto3

from .common import for_regions, safe


@dataclass
class MetricsProbeResult:
    custom_metric_count: int = 0
    alarm_count: int = 0
    dashboard_count: int = 0
    by_region: dict[str, dict] = field(default_factory=dict)


def _probe_region(session: boto3.Session, region: str) -> dict:
    cw = session.client("cloudwatch", region_name=region)
    # Custom metrics = metrics whose namespace doesn't start with "AWS/".
    custom = 0
    paginator = cw.get_paginator("list_metrics")
    for page in paginator.paginate():
        for m in page.get("Metrics", []):
            ns = m.get("Namespace", "")
            if not ns.startswith("AWS/"):
                custom += 1
    alarms = 0
    alarm_paginator = cw.get_paginator("describe_alarms")
    for page in alarm_paginator.paginate():
        alarms += len(page.get("MetricAlarms", []))
        alarms += len(page.get("CompositeAlarms", []))
    dash = 0
    dash_paginator = cw.get_paginator("list_dashboards")
    for page in dash_paginator.paginate():
        dash += len(page.get("DashboardEntries", []))
    return {"custom_metrics": custom, "alarms": alarms, "dashboards": dash}


def run(session: boto3.Session, regions: list[str]) -> MetricsProbeResult:
    per_region = for_regions(regions, lambda r: safe(lambda: _probe_region(session, r), what=f"cloudwatch:{r}", default={}))
    result = MetricsProbeResult(by_region=per_region)
    for r, data in per_region.items():
        if not data:
            continue
        result.custom_metric_count += data.get("custom_metrics", 0)
        result.alarm_count += data.get("alarms", 0)
        result.dashboard_count += data.get("dashboards", 0)
    return result
