"""Bronto.io cost projection model.

Pricing source: https://bronto.io/pricing
  - Ingest: $0.10/GB, uniform across logs, metrics, and traces.
  - Retention: 12 months included on all plans.
  - Search: per-plan (Starter 20 TB, Pro 500 TB, Enterprise pay-go),
    overage $1/TB.

Apples-to-apples comparison
---------------------------
The naive "AWS bill vs Bronto bill" comparison overstates savings because
some AWS charges survive a migration. We split bucket totals into:

  * **Floor** (survives migration) — CloudWatch MetricStream (egress
    from CW Metrics — same fee whether destination is Bronto, Datadog,
    S3) and Kinesis/Data Firehose (transport for MetricStream → Bronto).
  * **Displaceable** — everything else. OpenSearch is displaceable:
    Bronto absorbs log-search / SIEM / time-series-analytics workloads.
    Vector / RAG / e-commerce search are exceptions called out in
    caveats — apply judgment.

Apples-to-apples savings = AWS_total_forward − (AWS_floor + Bronto).

Decommissioned services
-----------------------
Any service with spend in the analysis window but $0 in a trailing-7-day
probe is flagged decommissioned and excluded from the forward-looking
baseline. See `detect_decommissioned()`.

OpenSearch displacement scenarios
---------------------------------
Cost Explorer doesn't expose OpenSearch ingest GB. `opensearch_footprint()`
backs out cluster shape from CE line items; `opensearch_scenarios()`
projects Bronto cost across retention assumptions (7/14/30/90d) using
AWS's published sizing rules. This repo also runs direct OpenSearch
probes (see obscost.probes.opensearch) when `--probe` is set.

Ingest sources (Cost Explorer usage types):
  * CloudWatch Logs: DataProcessing-Bytes (customer), VendedLog-Bytes (ALB/CF/etc.)
  * CloudWatch custom metrics: MetricMonitorUsage (metric-months)
  * CloudWatch MetricStream (floor): MetricStreamUsage (per metric update)
  * X-Ray: TracesRecorded
  * Managed Prometheus: IngestedSamples
  * CloudTrail: PaidEventsRecorded (data events)
  * OpenSearch: estimated from --probe storage size (CE doesn't meter ingest)
  * Firehose (floor): transport bytes

Search sources: CW Logs Insights DataScanned-Bytes; CW GMD-Metrics;
X-Ray TracesRetrieved/Scanned.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

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
    bytes_per_metric_month: int
    bytes_per_metric_stream_update: int
    bytes_per_metric_query: int
    bytes_per_trace_query: int
    opensearch_retention_months_assumption: float

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
            bytes_per_metric_month=int(data.get("bytes_per_metric_month", 3_440_000)),
            bytes_per_metric_stream_update=int(data.get("bytes_per_metric_stream_update", 80)),
            bytes_per_metric_query=int(data.get("bytes_per_metric_query", 5120)),
            bytes_per_trace_query=int(data.get("bytes_per_trace_query", 2048)),
            opensearch_retention_months_assumption=float(
                data.get("opensearch_retention_months_assumption", 1.0)
            ),
        )


SIGNAL_TYPE = {
    "CloudWatch Logs": "logs",
    "CloudTrail": "logs",
    "CloudWatch Metrics": "metrics",
    "CloudWatch MetricStream (floor)": "metrics",
    "Managed Prometheus": "metrics",
    "X-Ray": "traces",
    # OpenSearch can be any of the three — bucket it under "logs" since
    # that's the most common use case, but flag in caveats.
    "OpenSearch": "logs",
    "Firehose (floor)": "metrics",
}


def signal_type(bucket: str) -> str:
    return SIGNAL_TYPE.get(bucket, "other")


# AWS-side cost surfaces that survive a Bronto migration. The bytes still
# flow into Bronto (so they DO contribute to gb_ingested), but the fee is
# unavoidable on the AWS side — keep them on the AWS plate in the
# apples-to-apples comparison.
FLOOR_BUCKETS = frozenset({
    "CloudWatch MetricStream (floor)",
    "Firehose (floor)",
})


# Map AWS Service dimension → buckets we'd consider decommissioned if
# the service has $0 spend in the trailing window. We deliberately omit
# Amazon CloudWatch and Amazon S3 — too broad; false positives would
# distort the report.
SERVICE_TO_BUCKETS = {
    "Amazon OpenSearch Service": ["OpenSearch"],
    "AWS X-Ray": ["X-Ray"],
    "Amazon Managed Service for Prometheus": ["Managed Prometheus"],
    "Amazon Managed Grafana": ["Managed Grafana"],
    "AWS CloudTrail": ["CloudTrail"],
    "Amazon Kinesis Firehose": ["Firehose (floor)"],
    "Amazon Data Firehose": ["Firehose (floor)"],
}


def detect_decommissioned(
    bucket_cost: dict[str, float],
    recent_spend_by_service: dict[str, float],
) -> set[str]:
    """Return the set of buckets whose upstream AWS service had spend in
    the analysis window but $0 in the trailing-7-day probe."""
    decom: set[str] = set()
    for svc, buckets in SERVICE_TO_BUCKETS.items():
        if recent_spend_by_service.get(svc, 0.0) > 0:
            continue
        for b in buckets:
            if bucket_cost.get(b, 0.0) > 0:
                decom.add(b)
    return decom


# --- OpenSearch displacement analysis ----------------------------------
# Published us-east-1 OpenSearch search-node rates (on-demand).
# Source: https://aws.amazon.com/opensearch-service/pricing/
_OS_INSTANCE_RATES_USD_PER_HR = {
    "r6g.large": 0.154,
    "r6g.xlarge": 0.335,
    "r6g.2xlarge": 0.670,
    "m6g.large": 0.142,
    "m6g.xlarge": 0.284,
    "c6g.large": 0.126,
    "c6g.xlarge": 0.252,
    "t3.small": 0.036,
    "t3.medium": 0.073,
}
_OS_GP3_RATE_USD_PER_GB_MO = 0.122
_OS_GP2_RATE_USD_PER_GB_MO = 0.135

# Sizing constants from AWS pricing examples + general OpenSearch ops guidance.
_OS_FREE_SPACE_HEADROOM = 0.85      # OS reserves 15% for disk-full safety
_OS_LUCENE_OVERHEAD = 0.91          # ~10% indexing overhead vs raw
_OS_TYPICAL_UTILIZATION = 0.80      # clusters don't run at 100% full


@dataclass
class OpenSearchFootprint:
    instance_type: str | None
    instance_hours: float
    instance_rate: float
    node_days: float
    ebs_type: str | None
    ebs_gb_months: float
    ebs_rate: float
    ebs_gb_provisioned: float


@dataclass
class OpenSearchScenario:
    retention_days: int
    raw_resident_gb: float
    ingest_per_day_gb: float
    ingest_over_window_gb: float
    fits_in_starter: bool
    incremental_bronto_cost: float


@dataclass
class OpenSearchDisplacement:
    footprint: OpenSearchFootprint
    raw_resident_gb: float
    usable_gb: float
    scenarios: list[OpenSearchScenario]


def opensearch_footprint(report: CostReport) -> OpenSearchFootprint | None:
    """Back out OpenSearch cluster shape from Cost Explorer line items."""
    inst_lines: dict[str, dict[str, float]] = {}
    ebs_lines: dict[str, dict[str, float]] = {}
    for line in report.lines:
        if line.account_id != "*" or line.bucket != "OpenSearch":
            continue
        utl = (line.usage_type or "").lower()
        if "esinstance:" in utl:
            inst_type = line.usage_type.split(":", 1)[1].lower()
            d = inst_lines.setdefault(inst_type, {"cost": 0.0, "hours": 0.0})
            d["cost"] += line.amount_usd
            d["hours"] += line.quantity
        elif "gp3-storage" in utl:
            d = ebs_lines.setdefault("gp3", {"cost": 0.0, "gb_months": 0.0})
            d["cost"] += line.amount_usd
            d["gb_months"] += line.quantity
        elif "gp2" in utl and "storage" in utl:
            d = ebs_lines.setdefault("gp2", {"cost": 0.0, "gb_months": 0.0})
            d["cost"] += line.amount_usd
            d["gb_months"] += line.quantity

    if not inst_lines and not ebs_lines:
        return None

    primary_inst = max(inst_lines.items(), key=lambda kv: kv[1]["cost"], default=(None, None))
    primary_ebs = max(ebs_lines.items(), key=lambda kv: kv[1]["cost"], default=(None, None))
    months = _months_between(report.start, report.end) or 1.0

    fp = OpenSearchFootprint(
        instance_type=primary_inst[0],
        instance_hours=0.0,
        instance_rate=0.0,
        node_days=0.0,
        ebs_type=primary_ebs[0],
        ebs_gb_months=0.0,
        ebs_rate=0.0,
        ebs_gb_provisioned=0.0,
    )
    if primary_inst[0]:
        fp.instance_hours = primary_inst[1]["hours"]
        fp.instance_rate = _OS_INSTANCE_RATES_USD_PER_HR.get(
            primary_inst[0],
            (primary_inst[1]["cost"] / primary_inst[1]["hours"]) if primary_inst[1]["hours"] > 0 else 0.0,
        )
        fp.node_days = primary_inst[1]["hours"] / 24
    if primary_ebs[0]:
        fp.ebs_gb_months = primary_ebs[1]["gb_months"]
        fp.ebs_rate = _OS_GP3_RATE_USD_PER_GB_MO if primary_ebs[0] == "gp3" else _OS_GP2_RATE_USD_PER_GB_MO
        fp.ebs_gb_provisioned = primary_ebs[1]["gb_months"] / months
    return fp


def opensearch_scenarios(
    fp: OpenSearchFootprint,
    gb_ingested_other: float,
    starter_included_ingest_gb: float,
    window_days: int,
) -> OpenSearchDisplacement | None:
    """Project Bronto incremental cost to absorb OpenSearch at retention 7/14/30/90d.
    Assumes single-node domain (0 replicas)."""
    if not fp or fp.ebs_gb_provisioned <= 0:
        return None
    usable_gb = fp.ebs_gb_provisioned * _OS_FREE_SPACE_HEADROOM * _OS_LUCENE_OVERHEAD
    raw_resident_gb = usable_gb * _OS_TYPICAL_UTILIZATION
    scenarios: list[OpenSearchScenario] = []
    for retention_days in (7, 14, 30, 90):
        ingest_per_day = raw_resident_gb / retention_days
        ingest_over_window = ingest_per_day * window_days
        remaining_headroom = starter_included_ingest_gb - gb_ingested_other
        overage_gb = max(0.0, ingest_over_window - remaining_headroom)
        incremental_cost = overage_gb * 0.10
        scenarios.append(OpenSearchScenario(
            retention_days=retention_days,
            raw_resident_gb=raw_resident_gb,
            ingest_per_day_gb=ingest_per_day,
            ingest_over_window_gb=ingest_over_window,
            fits_in_starter=(overage_gb == 0.0),
            incremental_bronto_cost=incremental_cost,
        ))
    return OpenSearchDisplacement(
        footprint=fp,
        raw_resident_gb=raw_resident_gb,
        usable_gb=usable_gb,
        scenarios=scenarios,
    )


@dataclass
class BrontoProjection:
    gb_ingested: float = 0.0
    gb_searched: float = 0.0
    per_source_gb: dict[str, float] = field(default_factory=dict)
    per_signal_gb: dict[str, float] = field(default_factory=dict)
    search_gb_by_signal: dict[str, float] = field(default_factory=dict)
    plan_costs: dict[str, float] = field(default_factory=dict)
    plan_ingest_costs: dict[str, float] = field(default_factory=dict)
    plan_search_costs: dict[str, float] = field(default_factory=dict)
    plan_search_allowance_gb: dict[str, float] = field(default_factory=dict)
    cheapest_plan: str = ""
    cheapest_cost: float = 0.0
    months_in_window: float = 0.0
    extended_retention_note: str | None = None

    # --- Apples-to-apples comparison fields ---
    obs_total_as_billed: float = 0.0
    obs_total_forward: float = 0.0
    decommissioned: set[str] = field(default_factory=set)
    decom_spend: float = 0.0
    aws_floor: float = 0.0
    aws_floor_historical: float = 0.0
    displaceable: float = 0.0
    post_migration_cost: float = 0.0
    apples_savings_abs: float = 0.0
    apples_savings_pct: float = 0.0
    naive_savings_abs: float = 0.0
    naive_savings_pct: float = 0.0

    os_displacement: OpenSearchDisplacement | None = None


def _months_between(start: str, end: str) -> float:
    s = date.fromisoformat(start)
    e = date.fromisoformat(end)
    return max((e - s).days / 30.4375, 0.0)


def _line_to_gb(line: UsageLine, pricing: BrontoPricing) -> float:
    """Convert a Cost Explorer usage line into estimated GB ingested.

    Returns 0 for lines that don't represent ingestion (retention storage,
    API requests, dashboards, alarms, instance hours, search/scan, etc.).
    """
    ut = (line.usage_type or "").lower()
    qty = line.quantity

    if line.bucket == "CloudWatch Logs":
        # Both customer-published logs and vended logs (ALB/CloudFront/etc.)
        # are reported in GB and both represent ingest.
        if "dataprocessing-bytes" in ut or "vendedlog-bytes" in ut:
            return qty
    if line.bucket == "CloudWatch Metrics":
        # Custom metrics published (metric-months).
        if "metricmonitor" in ut:
            return (qty * pricing.bytes_per_metric_month) / GB
    if line.bucket == "CloudWatch MetricStream (floor)":
        # Metric Streams forwarding (per metric update). The AWS-side fee
        # is unavoidable (it's the floor) but the bytes themselves still
        # flow into Bronto, so they count toward gb_ingested.
        if "metricstream" in ut:
            return (qty * pricing.bytes_per_metric_stream_update) / GB
    if line.bucket == "X-Ray" and "tracesrecorded" in ut:
        return (qty * pricing.bytes_per_xray_trace) / GB
    if line.bucket == "Managed Prometheus" and "samples" in ut:
        return (qty * pricing.bytes_per_prometheus_sample) / GB
    if line.bucket == "CloudTrail" and (
        "dataevents" in ut or "data-events" in ut or "paideventsrecorded" in ut
    ):
        return (qty * pricing.bytes_per_cloudtrail_event) / GB
    return 0.0


def _line_to_search_gb(line: UsageLine, pricing: BrontoPricing) -> tuple[float, str]:
    """Return (GB scanned, signal) for any usage line representing a
    query/scan that Bronto would bill against its search rate.

    Covers:
      * CloudWatch Logs Insights — `DataScanned-Bytes` (already GB)
      * CloudWatch GetMetricData — `CW:GMD-Metrics` (metrics × bytes/query)
      * X-Ray trace retrieval / scan — `TracesRetrieved`, `TracesScanned`
        (traces × bytes/query)
    """
    ut = (line.usage_type or "").lower()
    qty = line.quantity
    if line.bucket == "CloudWatch Insights" and "datascanned" in ut:
        return line.quantity, "logs"
    if line.bucket == "CloudWatch Metrics" and "gmd-metrics" in ut:
        return (qty * pricing.bytes_per_metric_query) / GB, "metrics"
    if line.bucket == "X-Ray" and ("tracesretrieved" in ut or "tracesscanned" in ut):
        return (qty * pricing.bytes_per_trace_query) / GB, "traces"
    return 0.0, ""


def _search_allowance_gb(plan: dict, gb_ingested: float) -> float:
    """Search inclusion is per-plan: either a flat `search_included_tb`
    or a `search_multiplier_of_ingest` (Enterprise = 100× ingested)."""
    if "search_included_tb" in plan:
        return float(plan["search_included_tb"]) * TB_TO_GB
    if "search_multiplier_of_ingest" in plan:
        return float(plan["search_multiplier_of_ingest"]) * gb_ingested
    return 0.0


def project(
    report: CostReport,
    pricing: BrontoPricing,
    opensearch_storage_gb: float = 0.0,
    recent_spend_by_service: dict[str, float] | None = None,
) -> BrontoProjection:
    """Convert observability usage into a Bronto cost projection.

    `opensearch_storage_gb` (if provided, typically from --probe) is divided
    by `opensearch_retention_months_assumption` to estimate monthly ingest,
    then scaled to the window length. Contributes to the OpenSearch row
    in `per_source_gb` and to `gb_ingested`.

    `recent_spend_by_service` (from `fetch_recent_spend_by_service`) drives
    the decommissioned-service detection and the forward-looking baseline.
    Without it, the apples-to-apples fields use the full-window total
    (no decom carve-out).

    Each plan has its own search inclusion model (flat TB or multiplier on
    ingested volume). Search overage is uniformly `search_per_gb_usd`.
    Cheapest plan (ingest + search) wins.
    """
    proj = BrontoProjection(months_in_window=_months_between(report.start, report.end))

    per_source: dict[str, float] = {}
    search_by_signal: dict[str, float] = {"logs": 0.0, "metrics": 0.0, "traces": 0.0}
    for line in report.lines:
        if line.account_id != "*":
            continue
        gb = _line_to_gb(line, pricing)
        if gb > 0:
            per_source[line.bucket] = per_source.get(line.bucket, 0.0) + gb
            proj.gb_ingested += gb
        search_gb, search_signal = _line_to_search_gb(line, pricing)
        if search_gb > 0:
            proj.gb_searched += search_gb
            if search_signal:
                search_by_signal[search_signal] = (
                    search_by_signal.get(search_signal, 0.0) + search_gb
                )
    proj.search_gb_by_signal = search_by_signal

    # OpenSearch ingestion estimate from probe data.
    if opensearch_storage_gb > 0:
        retention = max(pricing.opensearch_retention_months_assumption, 0.001)
        monthly_ingest = opensearch_storage_gb / retention
        windowed = monthly_ingest * proj.months_in_window
        per_source["OpenSearch"] = per_source.get("OpenSearch", 0.0) + windowed
        proj.gb_ingested += windowed

    proj.per_source_gb = per_source

    # Roll up per-source into the three signal types (logs/metrics/traces).
    per_signal: dict[str, float] = {"logs": 0.0, "metrics": 0.0, "traces": 0.0}
    for src, gb in per_source.items():
        sig = signal_type(src)
        per_signal[sig] = per_signal.get(sig, 0.0) + gb
    proj.per_signal_gb = per_signal

    months = max(proj.months_in_window, 1e-9)
    for plan in pricing.plans:
        name = plan["name"]
        fee = float(plan["monthly_fee_usd"]) * months
        included_ingest_gb = float(plan["included_tb"]) * TB_TO_GB * months
        ingest_overage_gb = max(proj.gb_ingested - included_ingest_gb, 0.0)
        ingest_cost = fee + ingest_overage_gb * pricing.ingest_per_gb_usd

        included_search_gb = _search_allowance_gb(plan, proj.gb_ingested)
        search_overage_gb = max(proj.gb_searched - included_search_gb, 0.0)
        search_cost = search_overage_gb * pricing.search_per_gb_usd

        proj.plan_ingest_costs[name] = ingest_cost
        proj.plan_search_costs[name] = search_cost
        proj.plan_search_allowance_gb[name] = included_search_gb
        proj.plan_costs[name] = ingest_cost + search_cost

    if proj.plan_costs:
        proj.cheapest_plan, proj.cheapest_cost = min(
            proj.plan_costs.items(), key=lambda kv: kv[1]
        )

    if pricing.extended_retention_per_gb_month_usd is None:
        proj.extended_retention_note = (
            "Extended retention (>12 months) priced via 'contact sales' — "
            "not included in projection."
        )

    # --- Apples-to-apples comparison ---------------------------------------
    bucket_cost = report.by_bucket()
    proj.obs_total_as_billed = sum(
        c for b, c in bucket_cost.items() if b != "S3 (unattributed)"
    )

    if recent_spend_by_service is not None:
        proj.decommissioned = detect_decommissioned(bucket_cost, recent_spend_by_service)
    proj.decom_spend = sum(c for b, c in bucket_cost.items() if b in proj.decommissioned)
    proj.obs_total_forward = proj.obs_total_as_billed - proj.decom_spend

    proj.aws_floor_historical = sum(
        c for b, c in bucket_cost.items() if b in FLOOR_BUCKETS
    )
    proj.aws_floor = sum(
        c for b, c in bucket_cost.items()
        if b in FLOOR_BUCKETS and b not in proj.decommissioned
    )
    proj.displaceable = max(proj.obs_total_forward - proj.aws_floor, 0.0)
    proj.post_migration_cost = proj.aws_floor + proj.cheapest_cost
    proj.apples_savings_abs = proj.obs_total_forward - proj.post_migration_cost
    proj.apples_savings_pct = (
        (proj.apples_savings_abs / proj.obs_total_forward * 100.0)
        if proj.obs_total_forward > 0
        else 0.0
    )
    proj.naive_savings_abs = proj.obs_total_as_billed - proj.cheapest_cost
    proj.naive_savings_pct = (
        (proj.naive_savings_abs / proj.obs_total_as_billed * 100.0)
        if proj.obs_total_as_billed > 0
        else 0.0
    )

    # OpenSearch displacement — derived from CE line items. The sibling
    # repo's --probe results are surfaced separately in the report renderer.
    fp = opensearch_footprint(report)
    if fp is not None:
        headroom_plan = next(
            (p for p in pricing.plans if float(p.get("included_tb", 0)) > 0),
            None,
        )
        if headroom_plan:
            included_ingest_gb = float(headroom_plan["included_tb"]) * TB_TO_GB * months
            window_days = int(round(proj.months_in_window * 30.4375))
            proj.os_displacement = opensearch_scenarios(
                fp,
                gb_ingested_other=proj.gb_ingested,
                starter_included_ingest_gb=included_ingest_gb,
                window_days=max(window_days, 1),
            )

    return proj
