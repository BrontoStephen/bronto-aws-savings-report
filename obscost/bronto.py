"""Bronto.io cost projection model.

Pricing source: https://bronto.io/pricing
  - Ingest: $0.10/GB, uniform across logs, metrics, and traces.
  - Retention: 12 months included on all plans.
  - Search: excluded from this projection per user request.

We convert AWS Cost Explorer usage quantities (in GB, traces, samples, events)
into a single "GB ingested" number, then project the cost across three plans:
Starter ($25/mo, 1 TB included), Pro ($500/mo, 5 TB), Enterprise ($0.10/GB).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

import yaml

from .cost_explorer import CostReport, UsageLine

log = logging.getLogger(__name__)

GB = 1024 ** 3
TB_TO_GB = 1024


@dataclass
class BrontoPricing:
    ingest_per_gb_usd: float
    included_retention_months: int
    extended_retention_per_gb_month_usd: float | None
    search_per_gb_usd: float
    plans: list[dict]
    bytes_per_xray_trace: int
    bytes_per_prometheus_sample: int
    bytes_per_cloudtrail_event: int

    @classmethod
    def load(cls, path: str | Path) -> "BrontoPricing":
        with open(path, "r") as f:
            data = yaml.safe_load(f)
        return cls(
            ingest_per_gb_usd=float(data["ingest_per_gb_usd"]),
            included_retention_months=int(data["included_retention_months"]),
            extended_retention_per_gb_month_usd=(
                None
                if data.get("extended_retention_per_gb_month_usd") is None
                else float(data["extended_retention_per_gb_month_usd"])
            ),
            search_per_gb_usd=float(data.get("search_per_gb_usd", 0.0)),
            plans=list(data.get("plans", [])),
            bytes_per_xray_trace=int(data.get("bytes_per_xray_trace", 2048)),
            bytes_per_prometheus_sample=int(data.get("bytes_per_prometheus_sample", 8)),
            bytes_per_cloudtrail_event=int(data.get("bytes_per_cloudtrail_event", 1536)),
        )


@dataclass
class BrontoProjection:
    gb_ingested: float = 0.0
    per_source_gb: dict[str, float] = field(default_factory=dict)
    plan_costs: dict[str, float] = field(default_factory=dict)
    cheapest_plan: str = ""
    cheapest_cost: float = 0.0
    months_in_window: float = 0.0
    extended_retention_note: str | None = None


def _months_between(start: str, end: str) -> float:
    from datetime import date

    s = date.fromisoformat(start)
    e = date.fromisoformat(end)
    return max((e - s).days / 30.4375, 0.0)


def _line_to_gb(line: UsageLine, pricing: BrontoPricing) -> float:
    """Convert a Cost Explorer usage line into estimated GB ingested.

    Returns 0 for lines that don't represent ingestion (retention storage,
    API requests, dashboards, alarms, instance hours, etc.).
    """
    ut = (line.usage_type or "").lower()
    unit = (line.unit or "").lower()
    qty = line.quantity

    # CloudWatch Logs ingestion (the dominant cost in most accounts).
    # Usage type: "DataProcessing-Bytes", quantity reported in GB.
    if line.bucket == "CloudWatch Logs" and "dataprocessing-bytes" in ut:
        # CE reports this in GB already.
        return qty

    # X-Ray traces — count → bytes → GB.
    if line.bucket == "X-Ray" and "tracesrecorded" in ut:
        return (qty * pricing.bytes_per_xray_trace) / GB

    # Managed Prometheus ingested samples.
    if line.bucket == "Managed Prometheus" and "samples" in ut:
        return (qty * pricing.bytes_per_prometheus_sample) / GB

    # CloudTrail data events.
    if line.bucket == "CloudTrail" and ("dataevents" in ut or "data-events" in ut):
        return (qty * pricing.bytes_per_cloudtrail_event) / GB

    # OpenSearch — no clean ingestion meter from CE; left to probe.
    return 0.0


def project(report: CostReport, pricing: BrontoPricing) -> BrontoProjection:
    """Convert observability usage into a Bronto cost projection."""
    proj = BrontoProjection(months_in_window=_months_between(report.start, report.end))

    per_source: dict[str, float] = {}
    for line in report.lines:
        if line.account_id != "*":
            # Only count usage-type detail lines (pass B) to avoid double-counting.
            continue
        gb = _line_to_gb(line, pricing)
        if gb <= 0:
            continue
        per_source[line.bucket] = per_source.get(line.bucket, 0.0) + gb
        proj.gb_ingested += gb

    proj.per_source_gb = per_source

    # Project across each plan.
    months = max(proj.months_in_window, 1e-9)
    for plan in pricing.plans:
        name = plan["name"]
        fee = float(plan["monthly_fee_usd"]) * months
        included_gb = float(plan["included_tb"]) * TB_TO_GB * months
        overage_gb = max(proj.gb_ingested - included_gb, 0.0)
        overage_cost = overage_gb * pricing.ingest_per_gb_usd
        proj.plan_costs[name] = fee + overage_cost

    if proj.plan_costs:
        proj.cheapest_plan, proj.cheapest_cost = min(proj.plan_costs.items(), key=lambda kv: kv[1])

    if pricing.extended_retention_per_gb_month_usd is None:
        proj.extended_retention_note = (
            "Extended retention (>12 months) priced via 'contact sales' — "
            "not included in projection."
        )
    return proj
