"""Cost Explorer queries for observability spend.

Cost Explorer is a region-pinned global service — it only lives in us-east-1.
We query the management account's CE endpoint; CE already aggregates spend
across the entire organization linked accounts when called by the payer.
For per-account detail we use the LINKED_ACCOUNT dimension instead of
assume-rolling into every member account (faster, fewer permissions).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import date, timedelta
from typing import Optional

import boto3

log = logging.getLogger(__name__)

# Service dimension values that count as "observability" for this audit.
# CloudTrail data events are billable under "AWS CloudTrail".
# S3 is included separately and reported as "unattributed" unless --probe
# identifies log-sink buckets.
OBS_SERVICES = [
    "Amazon CloudWatch",
    "AmazonCloudWatch",
    "AWS X-Ray",
    "Amazon Managed Service for Prometheus",
    "Amazon Managed Grafana",
    "Amazon OpenSearch Service",
    "AWS CloudTrail",
]

# Firehose is the transport layer for CW MetricStream → Bronto. Fetched
# via a dedicated CE call (separate service) and merged into the main
# report's lines. Both naming variants exist in different accounts.
FIREHOSE_SERVICES = ["Amazon Kinesis Firehose", "Amazon Data Firehose"]

S3_SERVICE = "Amazon Simple Storage Service"


# Buckets we classify spend into for the report.
BUCKETS = [
    "CloudWatch Logs",
    "CloudWatch Metrics",
    "CloudWatch MetricStream (floor)",
    "CloudWatch Alarms",
    "CloudWatch Dashboards",
    "CloudWatch Insights",
    "CloudWatch Synthetics",
    "CloudWatch Other",
    "X-Ray",
    "Managed Prometheus",
    "Managed Grafana",
    "OpenSearch",
    "CloudTrail",
    "Firehose (floor)",
    "S3 (unattributed)",
]


def _classify(service: str, usage_type: str) -> str:
    """Map a (service, usage_type) pair to one of BUCKETS.

    Floor buckets ("CloudWatch MetricStream (floor)", "Firehose (floor)")
    represent AWS-side charges that *survive* a Bronto migration — they
    are the unavoidable egress/transport layer. They still contribute to
    gb_ingested (the bytes flow into Bronto) but are kept on the AWS
    side of the apples-to-apples comparison.
    """
    ut = usage_type or ""
    svc = service or ""

    if svc.startswith("AWS X-Ray") or "XRay" in ut:
        return "X-Ray"
    if svc == "Amazon Managed Service for Prometheus":
        return "Managed Prometheus"
    if svc == "Amazon Managed Grafana":
        return "Managed Grafana"
    if svc == "Amazon OpenSearch Service":
        return "OpenSearch"
    if svc == "AWS CloudTrail":
        return "CloudTrail"
    if svc in FIREHOSE_SERVICES:
        return "Firehose (floor)"
    if svc == S3_SERVICE:
        return "S3 (unattributed)"

    # CloudWatch sub-buckets — usage-type strings are surprisingly varied.
    u = ut.lower()
    # Order matters:
    #   1. MetricStream (floor) before generic Metrics — it's an
    #      egress/transport charge on top of CW Metrics, and it's floor.
    #   2. Insights (DataScanned-Bytes) before Logs — the region prefix
    #      can contain the substring "log".
    if "metricstream" in u:
        return "CloudWatch MetricStream (floor)"
    if "datascanned" in u or "queryscanned" in u or "insight" in u:
        return "CloudWatch Insights"
    if "logs" in u or "log-" in u or "vpcflowlog" in u or "dataprocessing-bytes" in u:
        return "CloudWatch Logs"
    if "alarm" in u:
        return "CloudWatch Alarms"
    if "dashboard" in u:
        return "CloudWatch Dashboards"
    if "canary" in u or "synthetic" in u:
        return "CloudWatch Synthetics"
    if "metric" in u or "request" in u or "cw:metricmonitor" in u:
        return "CloudWatch Metrics"
    return "CloudWatch Other"


@dataclass
class UsageLine:
    """One (account, service, usage_type) line for the window."""

    account_id: str
    service: str
    usage_type: str
    bucket: str
    amount_usd: float
    quantity: float
    unit: str


@dataclass
class CostReport:
    start: str
    end: str
    lines: list[UsageLine] = field(default_factory=list)
    accounts_seen: set[str] = field(default_factory=set)

    def by_account(self) -> dict[str, float]:
        """Per-account totals — pass A only (account_id != '*')."""
        out: dict[str, float] = {}
        for ln in self.lines:
            if ln.account_id == "*":
                continue
            out[ln.account_id] = out.get(ln.account_id, 0.0) + ln.amount_usd
        return out

    def by_bucket(self) -> dict[str, float]:
        """Per-bucket totals — pass B only (usage-type detail, sub-classifies CW)."""
        out: dict[str, float] = {}
        for ln in self.lines:
            if ln.account_id != "*":
                continue
            out[ln.bucket] = out.get(ln.bucket, 0.0) + ln.amount_usd
        return out

    def total(self, include_s3_unattributed: bool = False) -> float:
        """Org-wide observability total — pass B only (avoid double-count)."""
        return sum(
            ln.amount_usd
            for ln in self.lines
            if ln.account_id == "*"
            and (include_s3_unattributed or ln.bucket != "S3 (unattributed)")
        )

    def quantity_by_bucket(self) -> dict[str, dict[str, float]]:
        """Total quantity per bucket, keyed by unit (since units vary). Pass B only."""
        out: dict[str, dict[str, float]] = {}
        for ln in self.lines:
            if ln.account_id != "*":
                continue
            out.setdefault(ln.bucket, {})
            out[ln.bucket][ln.unit] = out[ln.bucket].get(ln.unit, 0.0) + ln.quantity
        return out


def fetch_costs(
    mgmt_session: boto3.Session,
    start: str,
    end: str,
    account_ids: Optional[list[str]] = None,
) -> CostReport:
    """Query Cost Explorer once at the payer level, grouped by LINKED_ACCOUNT
    + SERVICE + USAGE_TYPE, filtered to observability services + S3."""

    ce = mgmt_session.client("ce", region_name="us-east-1")

    services = OBS_SERVICES + [S3_SERVICE]
    cost_filter: dict = {"Dimensions": {"Key": "SERVICE", "Values": services}}
    if account_ids:
        cost_filter = {
            "And": [
                cost_filter,
                {"Dimensions": {"Key": "LINKED_ACCOUNT", "Values": list(account_ids)}},
            ]
        }

    report = CostReport(start=start, end=end)

    # CE supports max 2 GroupBy keys. We need 3 (account, service, usage_type),
    # so we do two passes and join: pass 1 = (LINKED_ACCOUNT, USAGE_TYPE),
    # pass 2 = (LINKED_ACCOUNT, SERVICE). The bucket classifier only needs
    # usage_type for CW sub-bucketing; service is needed for non-CW services.
    # Simpler: group by (SERVICE, USAGE_TYPE), and use a separate pass for
    # per-account totals.

    # Pass A: per-account totals (LINKED_ACCOUNT, SERVICE)
    paginator_token: Optional[str] = None
    while True:
        kwargs = dict(
            TimePeriod={"Start": start, "End": end},
            Granularity="MONTHLY",
            Metrics=["UnblendedCost", "UsageQuantity"],
            Filter=cost_filter,
            GroupBy=[
                {"Type": "DIMENSION", "Key": "LINKED_ACCOUNT"},
                {"Type": "DIMENSION", "Key": "SERVICE"},
            ],
        )
        if paginator_token:
            kwargs["NextPageToken"] = paginator_token
        resp = ce.get_cost_and_usage(**kwargs)
        for period in resp.get("ResultsByTime", []):
            for group in period.get("Groups", []):
                keys = group.get("Keys", [])
                if len(keys) < 2:
                    continue
                account_id, service = keys[0], keys[1]
                metrics = group.get("Metrics", {})
                amount = float(metrics.get("UnblendedCost", {}).get("Amount", 0.0))
                qty = float(metrics.get("UsageQuantity", {}).get("Amount", 0.0))
                unit = metrics.get("UsageQuantity", {}).get("Unit", "")
                report.accounts_seen.add(account_id)
                bucket = _classify(service, "")
                report.lines.append(
                    UsageLine(
                        account_id=account_id,
                        service=service,
                        usage_type="",
                        bucket=bucket,
                        amount_usd=amount,
                        quantity=qty,
                        unit=unit,
                    )
                )
        paginator_token = resp.get("NextPageToken")
        if not paginator_token:
            break

    # Pass B: usage-type detail (SERVICE, USAGE_TYPE) — used for sub-classification
    # of CloudWatch and for volume math. We keep these as a separate set of lines
    # tagged with the synthetic account_id "*" so the report renderer can find them.
    paginator_token = None
    while True:
        kwargs = dict(
            TimePeriod={"Start": start, "End": end},
            Granularity="MONTHLY",
            Metrics=["UnblendedCost", "UsageQuantity"],
            Filter=cost_filter,
            GroupBy=[
                {"Type": "DIMENSION", "Key": "SERVICE"},
                {"Type": "DIMENSION", "Key": "USAGE_TYPE"},
            ],
        )
        if paginator_token:
            kwargs["NextPageToken"] = paginator_token
        resp = ce.get_cost_and_usage(**kwargs)
        for period in resp.get("ResultsByTime", []):
            for group in period.get("Groups", []):
                keys = group.get("Keys", [])
                if len(keys) < 2:
                    continue
                service, usage_type = keys[0], keys[1]
                metrics = group.get("Metrics", {})
                amount = float(metrics.get("UnblendedCost", {}).get("Amount", 0.0))
                qty = float(metrics.get("UsageQuantity", {}).get("Amount", 0.0))
                unit = metrics.get("UsageQuantity", {}).get("Unit", "")
                bucket = _classify(service, usage_type)
                report.lines.append(
                    UsageLine(
                        account_id="*",
                        service=service,
                        usage_type=usage_type,
                        bucket=bucket,
                        amount_usd=amount,
                        quantity=qty,
                        unit=unit,
                    )
                )
        paginator_token = resp.get("NextPageToken")
        if not paginator_token:
            break

    return report


def fetch_firehose_costs(
    mgmt_session: boto3.Session,
    start: str,
    end: str,
    account_ids: Optional[list[str]] = None,
) -> list:
    """Pull Kinesis Firehose / Data Firehose spend (the transport layer
    for CloudWatch MetricStream → Bronto). Separate CE call because
    Firehose is a distinct AWS service. Returns a list of UsageLine
    objects ready to be merged into CostReport.lines.
    """
    ce = mgmt_session.client("ce", region_name="us-east-1")
    cost_filter: dict = {"Dimensions": {"Key": "SERVICE", "Values": FIREHOSE_SERVICES}}
    if account_ids:
        cost_filter = {
            "And": [
                cost_filter,
                {"Dimensions": {"Key": "LINKED_ACCOUNT", "Values": list(account_ids)}},
            ]
        }

    lines: list[UsageLine] = []
    token: Optional[str] = None
    while True:
        kwargs = dict(
            TimePeriod={"Start": start, "End": end},
            Granularity="MONTHLY",
            Metrics=["UnblendedCost", "UsageQuantity"],
            Filter=cost_filter,
            GroupBy=[
                {"Type": "DIMENSION", "Key": "SERVICE"},
                {"Type": "DIMENSION", "Key": "USAGE_TYPE"},
            ],
        )
        if token:
            kwargs["NextPageToken"] = token
        try:
            resp = ce.get_cost_and_usage(**kwargs)
        except Exception as e:  # noqa: BLE001
            log.warning("Firehose CE query failed: %s", e)
            return lines
        for period in resp.get("ResultsByTime", []):
            for group in period.get("Groups", []):
                keys = group.get("Keys", [])
                if len(keys) < 2:
                    continue
                service, usage_type = keys[0], keys[1]
                m = group.get("Metrics", {})
                amount = float(m.get("UnblendedCost", {}).get("Amount", 0.0))
                qty = float(m.get("UsageQuantity", {}).get("Amount", 0.0))
                unit = m.get("UsageQuantity", {}).get("Unit", "")
                lines.append(
                    UsageLine(
                        account_id="*",
                        service=service,
                        usage_type=usage_type,
                        bucket="Firehose (floor)",
                        amount_usd=amount,
                        quantity=qty,
                        unit=unit,
                    )
                )
        token = resp.get("NextPageToken")
        if not token:
            break
    return lines


def fetch_recent_spend_by_service(
    mgmt_session: boto3.Session,
    days: int = 7,
    account_ids: Optional[list[str]] = None,
) -> dict[str, float]:
    """Trailing-N-day spend grouped by SERVICE — used for decom detection.

    A service with spend > 0 in the analysis window but $0 in the trailing
    `days` window is flagged as decommissioned and excluded from the
    forward-looking AWS baseline. Filtered to observability services +
    Firehose so we never flag broad services (EC2, S3) as decom.
    """
    ce = mgmt_session.client("ce", region_name="us-east-1")
    today = date.today()
    start = (today - timedelta(days=days)).isoformat()
    end = today.isoformat()

    services = OBS_SERVICES + FIREHOSE_SERVICES
    cost_filter: dict = {"Dimensions": {"Key": "SERVICE", "Values": services}}
    if account_ids:
        cost_filter = {
            "And": [
                cost_filter,
                {"Dimensions": {"Key": "LINKED_ACCOUNT", "Values": list(account_ids)}},
            ]
        }

    spend_by_service: dict[str, float] = {svc: 0.0 for svc in services}
    token: Optional[str] = None
    while True:
        kwargs = dict(
            TimePeriod={"Start": start, "End": end},
            Granularity="DAILY",
            Metrics=["UnblendedCost"],
            Filter=cost_filter,
            GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
        )
        if token:
            kwargs["NextPageToken"] = token
        try:
            resp = ce.get_cost_and_usage(**kwargs)
        except Exception as e:  # noqa: BLE001
            log.warning("Trailing-%dd CE probe failed: %s", days, e)
            return spend_by_service
        for period in resp.get("ResultsByTime", []):
            for group in period.get("Groups", []):
                keys = group.get("Keys", [])
                if not keys:
                    continue
                svc = keys[0]
                amount = float(
                    group.get("Metrics", {}).get("UnblendedCost", {}).get("Amount", 0.0)
                )
                spend_by_service[svc] = spend_by_service.get(svc, 0.0) + amount
        token = resp.get("NextPageToken")
        if not token:
            break
    return spend_by_service
