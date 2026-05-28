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

S3_SERVICE = "Amazon Simple Storage Service"


# Buckets we classify spend into for the report.
BUCKETS = [
    "CloudWatch Logs",
    "CloudWatch Metrics",
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
    "S3 (unattributed)",
]


def _classify(service: str, usage_type: str) -> str:
    """Map a (service, usage_type) pair to one of BUCKETS."""
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
    if svc == S3_SERVICE:
        return "S3 (unattributed)"

    # CloudWatch sub-buckets — usage-type strings are surprisingly varied.
    u = ut.lower()
    # Order matters: Insights (DataScanned-Bytes) must be checked before
    # the generic Logs check, otherwise the "log" substring in the prefix
    # would steal it.
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
