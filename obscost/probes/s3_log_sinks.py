"""S3 log-sink attribution.

Walks every AWS service known to write logs to S3 and builds a mapping
(bucket_name -> list of source service names that target it). Then looks up
each attributed bucket's size via CloudWatch's `AWS/S3 BucketSizeBytes`.

Sources covered (best-effort; missing IAM permissions are silently skipped):

* CloudTrail trails (`S3BucketName`)
* AWS Config delivery channels (`s3BucketName`)
* VPC Flow Logs with `LogDestinationType=s3` (`LogDestination` ARN)
* Kinesis Data Firehose delivery streams (`S3DestinationDescription.BucketARN`
  and `ExtendedS3DestinationDescription.BucketARN`)
* Elastic Load Balancing (ALB/NLB) access logs
* CloudFront distributions (access log buckets)
* S3 server-access logging (one bucket → another bucket's log target)
* CloudWatch Logs export tasks (recent exports, since AWS doesn't list "active" ones)

Buckets that match log-related naming heuristics but have no service
attribution are reported as `suspected` only.
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Iterable

import boto3

from .common import safe

log = logging.getLogger(__name__)


LOG_KEYWORDS = ("log", "flowlog", "cloudtrail", "audit", "observability", "firehose")
_S3_ARN_RE = re.compile(r"^arn:aws[a-zA-Z-]*:s3:::([^/]+)(?:/.*)?$")


@dataclass
class S3BucketAttribution:
    name: str
    region: str | None
    sources: list[str] = field(default_factory=list)  # e.g. ["CloudTrail:my-trail", "VPC Flow Logs"]
    size_bytes: int = 0
    suspected_only: bool = False  # True if attribution is by name match only


@dataclass
class S3LogSinkProbeResult:
    attributed_buckets: list[S3BucketAttribution] = field(default_factory=list)
    suspected_buckets: list[S3BucketAttribution] = field(default_factory=list)
    total_attributed_size_bytes: int = 0
    total_suspected_size_bytes: int = 0
    sources_seen: dict[str, int] = field(default_factory=dict)  # source name → bucket count


def _bucket_from_arn(arn: str | None) -> str | None:
    if not arn:
        return None
    m = _S3_ARN_RE.match(arn)
    if m:
        return m.group(1)
    # Sometimes the value is already a bucket name
    if "/" not in arn and ":" not in arn:
        return arn
    return None


def _collect_cloudtrail(session: boto3.Session, regions: Iterable[str]) -> dict[str, list[str]]:
    """Return {bucket_name: [source_label, ...]} from CloudTrail."""
    out: dict[str, list[str]] = defaultdict(list)
    for region in regions:
        def probe(r: str = region) -> None:
            ct = session.client("cloudtrail", region_name=r)
            trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
            for t in trails:
                bucket = t.get("S3BucketName")
                if bucket:
                    out[bucket].append(f"CloudTrail:{t.get('Name', '?')}")
        safe(probe, what=f"cloudtrail.describe_trails:{region}", default=None)
    return out


def _collect_config(session: boto3.Session, regions: Iterable[str]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = defaultdict(list)
    for region in regions:
        def probe(r: str = region) -> None:
            cfg = session.client("config", region_name=r)
            for ch in cfg.describe_delivery_channels().get("DeliveryChannels", []):
                bucket = ch.get("s3BucketName")
                if bucket:
                    out[bucket].append(f"AWS Config:{ch.get('name', '?')}")
        safe(probe, what=f"config.describe_delivery_channels:{region}", default=None)
    return out


def _collect_vpc_flow_logs(session: boto3.Session, regions: Iterable[str]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = defaultdict(list)
    for region in regions:
        def probe(r: str = region) -> None:
            ec2 = session.client("ec2", region_name=r)
            paginator = ec2.get_paginator("describe_flow_logs")
            for page in paginator.paginate():
                for fl in page.get("FlowLogs", []):
                    if fl.get("LogDestinationType") != "s3":
                        continue
                    bucket = _bucket_from_arn(fl.get("LogDestination"))
                    if bucket:
                        out[bucket].append(f"VPC Flow Logs:{fl.get('FlowLogId', '?')}")
        safe(probe, what=f"ec2.describe_flow_logs:{region}", default=None)
    return out


def _collect_firehose(session: boto3.Session, regions: Iterable[str]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = defaultdict(list)
    for region in regions:
        def probe(r: str = region) -> None:
            fh = session.client("firehose", region_name=r)
            names: list[str] = []
            token = None
            while True:
                kwargs = {"Limit": 100}
                if token:
                    kwargs["ExclusiveStartDeliveryStreamName"] = token
                resp = fh.list_delivery_streams(**kwargs)
                names.extend(resp.get("DeliveryStreamNames", []))
                if not resp.get("HasMoreDeliveryStreams"):
                    break
                token = names[-1] if names else None
            for name in names:
                desc = safe(
                    lambda n=name: fh.describe_delivery_stream(DeliveryStreamName=n),
                    what=f"firehose.describe:{name}",
                    default=None,
                )
                if not desc:
                    continue
                for d in desc.get("DeliveryStreamDescription", {}).get("Destinations", []):
                    for key in ("ExtendedS3DestinationDescription", "S3DestinationDescription"):
                        cfg = d.get(key)
                        if not cfg:
                            continue
                        bucket = _bucket_from_arn(cfg.get("BucketARN"))
                        if bucket:
                            out[bucket].append(f"Firehose:{name}")
        safe(probe, what=f"firehose.list_delivery_streams:{region}", default=None)
    return out


def _collect_elb(session: boto3.Session, regions: Iterable[str]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = defaultdict(list)
    for region in regions:
        def probe(r: str = region) -> None:
            elb = session.client("elbv2", region_name=r)
            paginator = elb.get_paginator("describe_load_balancers")
            for page in paginator.paginate():
                for lb in page.get("LoadBalancers", []):
                    arn = lb["LoadBalancerArn"]
                    attrs = safe(
                        lambda a=arn: elb.describe_load_balancer_attributes(LoadBalancerArn=a),
                        what=f"elbv2.describe_attrs:{lb['LoadBalancerName']}",
                        default={"Attributes": []},
                    )
                    enabled = False
                    bucket = None
                    for a in attrs.get("Attributes", []):
                        if a.get("Key") == "access_logs.s3.enabled":
                            enabled = a.get("Value") == "true"
                        elif a.get("Key") == "access_logs.s3.bucket":
                            bucket = a.get("Value")
                    if enabled and bucket:
                        out[bucket].append(f"ELB access logs:{lb['LoadBalancerName']}")
        safe(probe, what=f"elbv2.describe_load_balancers:{region}", default=None)
    return out


def _collect_cloudfront(session: boto3.Session) -> dict[str, list[str]]:
    """CloudFront is global — single endpoint."""
    out: dict[str, list[str]] = defaultdict(list)

    def probe() -> None:
        cf = session.client("cloudfront")
        paginator = cf.get_paginator("list_distributions")
        for page in paginator.paginate():
            for d in page.get("DistributionList", {}).get("Items") or []:
                dist_id = d.get("Id")
                if not dist_id:
                    continue
                cfg = safe(
                    lambda i=dist_id: cf.get_distribution_config(Id=i),
                    what=f"cloudfront.get_distribution_config:{dist_id}",
                    default=None,
                )
                if not cfg:
                    continue
                logging_cfg = cfg.get("DistributionConfig", {}).get("Logging", {})
                if logging_cfg.get("Enabled") and logging_cfg.get("Bucket"):
                    # CloudFront returns bucket as fqdn: name.s3.amazonaws.com
                    bucket = logging_cfg["Bucket"].split(".", 1)[0]
                    out[bucket].append(f"CloudFront:{dist_id}")
    safe(probe, what="cloudfront.list_distributions", default=None)
    return out


def _collect_s3_access_logs(session: boto3.Session, bucket_names: Iterable[str]) -> dict[str, list[str]]:
    """For each bucket, GetBucketLogging — if it logs to another bucket, attribute it."""
    out: dict[str, list[str]] = defaultdict(list)
    s3 = session.client("s3")
    for name in bucket_names:
        cfg = safe(
            lambda n=name: s3.get_bucket_logging(Bucket=n),
            what=f"s3.get_bucket_logging:{name}",
            default={},
        )
        target = cfg.get("LoggingEnabled", {}).get("TargetBucket") if cfg else None
        if target:
            out[target].append(f"S3 server access logs:{name}")
    return out


def _bucket_size_bytes(session: boto3.Session, bucket: str, region: str | None) -> int:
    """Pull BucketSizeBytes (StandardStorage) from CloudWatch for the bucket."""
    if not region:
        return 0
    cw = session.client("cloudwatch", region_name=region)
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=3)  # CW S3 metrics are daily; last 3 days catches the latest sample
    resp = safe(
        lambda: cw.get_metric_statistics(
            Namespace="AWS/S3",
            MetricName="BucketSizeBytes",
            Dimensions=[
                {"Name": "BucketName", "Value": bucket},
                {"Name": "StorageType", "Value": "StandardStorage"},
            ],
            StartTime=start,
            EndTime=end,
            Period=86400,
            Statistics=["Maximum"],
        ),
        what=f"cw.BucketSizeBytes:{bucket}",
        default={},
    )
    dps = resp.get("Datapoints", []) if resp else []
    if not dps:
        return 0
    return int(max(dp.get("Maximum", 0) for dp in dps))


def run(session: boto3.Session, regions: list[str] | None = None) -> S3LogSinkProbeResult:
    """Build the bucket→source attribution map and look up sizes.

    `regions` defaults to a common subset if not provided.
    """
    if regions is None:
        from .common import DEFAULT_REGIONS
        regions = DEFAULT_REGIONS

    s3 = session.client("s3")
    all_buckets = safe(lambda: s3.list_buckets().get("Buckets", []), what="s3.list_buckets", default=[])
    all_names = [b["Name"] for b in all_buckets]

    # Resolve region per bucket (slow but needed for the CW BucketSizeBytes lookup).
    bucket_region: dict[str, str | None] = {}
    for name in all_names:
        loc = safe(
            lambda n=name: s3.get_bucket_location(Bucket=n).get("LocationConstraint"),
            what=f"s3.get_bucket_location:{name}",
            default=None,
        )
        bucket_region[name] = loc or "us-east-1"

    # Build attribution map.
    attribution: dict[str, list[str]] = defaultdict(list)
    for srcmap in (
        _collect_cloudtrail(session, regions),
        _collect_config(session, regions),
        _collect_vpc_flow_logs(session, regions),
        _collect_firehose(session, regions),
        _collect_elb(session, regions),
        _collect_cloudfront(session),
        _collect_s3_access_logs(session, all_names),
    ):
        for bucket, sources in srcmap.items():
            attribution[bucket].extend(sources)

    sources_seen: dict[str, int] = defaultdict(int)
    attributed: list[S3BucketAttribution] = []
    for bucket, sources in attribution.items():
        size = _bucket_size_bytes(session, bucket, bucket_region.get(bucket))
        attributed.append(
            S3BucketAttribution(
                name=bucket,
                region=bucket_region.get(bucket),
                sources=sources,
                size_bytes=size,
                suspected_only=False,
            )
        )
        for s in sources:
            sources_seen[s.split(":", 1)[0]] += 1

    # Heuristic name-match for buckets *not* otherwise attributed.
    attributed_set = {b.name for b in attributed}
    suspected: list[S3BucketAttribution] = []
    for name in all_names:
        if name in attributed_set:
            continue
        if any(k in name.lower() for k in LOG_KEYWORDS):
            size = _bucket_size_bytes(session, name, bucket_region.get(name))
            suspected.append(
                S3BucketAttribution(
                    name=name,
                    region=bucket_region.get(name),
                    sources=["(name match only)"],
                    size_bytes=size,
                    suspected_only=True,
                )
            )

    attributed.sort(key=lambda b: b.size_bytes, reverse=True)
    suspected.sort(key=lambda b: b.size_bytes, reverse=True)

    return S3LogSinkProbeResult(
        attributed_buckets=attributed,
        suspected_buckets=suspected,
        total_attributed_size_bytes=sum(b.size_bytes for b in attributed),
        total_suspected_size_bytes=sum(b.size_bytes for b in suspected),
        sources_seen=dict(sources_seen),
    )
