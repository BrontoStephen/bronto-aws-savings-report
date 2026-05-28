"""OpenSearch Service probe — domains, instance types, storage."""

from __future__ import annotations

from dataclasses import dataclass, field

import boto3

from .common import for_regions, safe


@dataclass
class OpenSearchProbeResult:
    domain_count: int = 0
    total_storage_gb: float = 0.0
    domains: list[dict] = field(default_factory=list)
    by_region: dict[str, dict] = field(default_factory=dict)


def _probe_region(session: boto3.Session, region: str) -> dict:
    es = session.client("opensearch", region_name=region)
    names = [d["DomainName"] for d in es.list_domain_names().get("DomainNames", [])]
    if not names:
        return {"domains": [], "storage_gb": 0.0}
    # describe_domains takes up to 5 names per call
    domains_info: list[dict] = []
    storage = 0.0
    for i in range(0, len(names), 5):
        chunk = names[i : i + 5]
        resp = es.describe_domains(DomainNames=chunk)
        for d in resp.get("DomainStatusList", []):
            cluster = d.get("ClusterConfig", {})
            ebs = d.get("EBSOptions", {})
            vol_gb = float(ebs.get("VolumeSize", 0)) * float(cluster.get("InstanceCount", 0))
            storage += vol_gb
            domains_info.append(
                {
                    "name": d.get("DomainName"),
                    "instance_type": cluster.get("InstanceType"),
                    "instance_count": cluster.get("InstanceCount"),
                    "ebs_volume_size_gb": ebs.get("VolumeSize"),
                    "region": region,
                }
            )
    return {"domains": domains_info, "storage_gb": storage}


def run(session: boto3.Session, regions: list[str]) -> OpenSearchProbeResult:
    per_region = for_regions(regions, lambda r: safe(lambda: _probe_region(session, r), what=f"opensearch:{r}", default={}))
    result = OpenSearchProbeResult(by_region=per_region)
    for r, data in per_region.items():
        if not data:
            continue
        result.domains.extend(data.get("domains", []))
        result.domain_count += len(data.get("domains", []))
        result.total_storage_gb += data.get("storage_gb", 0.0)
    return result
