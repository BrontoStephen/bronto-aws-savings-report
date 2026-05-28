"""CloudTrail probe — trails + data event selector status."""

from __future__ import annotations

from dataclasses import dataclass, field

import boto3

from .common import for_regions, safe


@dataclass
class CloudTrailProbeResult:
    trail_count: int = 0
    trails_with_data_events: int = 0
    multi_region_trails: int = 0
    by_region: dict[str, dict] = field(default_factory=dict)


def _probe_region(session: boto3.Session, region: str) -> dict:
    ct = session.client("cloudtrail", region_name=region)
    trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
    data_evt_trails = 0
    multi = 0
    for t in trails:
        if t.get("IsMultiRegionTrail"):
            multi += 1
        try:
            sel = ct.get_event_selectors(TrailName=t["TrailARN"])
            for s in sel.get("EventSelectors", []):
                if s.get("DataResources"):
                    data_evt_trails += 1
                    break
            for s in sel.get("AdvancedEventSelectors", []) or []:
                fields = s.get("FieldSelectors", [])
                if any(f.get("Field") == "eventCategory" and "Data" in (f.get("Equals") or []) for f in fields):
                    data_evt_trails += 1
                    break
        except Exception:  # noqa: BLE001
            continue
    return {"trails": len(trails), "data_event_trails": data_evt_trails, "multi_region": multi}


def run(session: boto3.Session, regions: list[str]) -> CloudTrailProbeResult:
    per_region = for_regions(regions, lambda r: safe(lambda: _probe_region(session, r), what=f"cloudtrail:{r}", default={}))
    result = CloudTrailProbeResult(by_region=per_region)
    for r, data in per_region.items():
        if not data:
            continue
        result.trail_count += data.get("trails", 0)
        result.trails_with_data_events += data.get("data_event_trails", 0)
        result.multi_region_trails += data.get("multi_region", 0)
    return result
