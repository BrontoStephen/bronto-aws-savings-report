"""Markdown report renderer."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .bronto import BrontoPricing, BrontoProjection, TB_TO_GB
from .cost_explorer import CostReport
from .org import Account


def _usd(x: float) -> str:
    return f"${x:,.2f}"


def _pct(x: float, total: float) -> str:
    if total <= 0:
        return "0.0%"
    return f"{(x / total) * 100:.1f}%"


@dataclass
class ProbeBundle:
    """All optional probe results bundled together. Any field may be None
    if that probe wasn't run or had no results."""

    cloudwatch_logs: Optional[object] = None
    cloudwatch_metrics: Optional[object] = None
    xray: Optional[object] = None
    amp: Optional[object] = None
    amg: Optional[object] = None
    opensearch: Optional[object] = None
    vpc_flow_logs: Optional[object] = None
    cloudtrail: Optional[object] = None
    s3_log_sinks: Optional[object] = None


def render(
    *,
    report: CostReport,
    accounts: list[Account],
    skipped: list[tuple[str, str]],
    projection: BrontoProjection,
    pricing: BrontoPricing,
    mgmt_account_id: str,
    probes: Optional[ProbeBundle] = None,
) -> str:
    obs_total = report.total(include_s3_unattributed=False)
    s3_unattr = report.by_bucket().get("S3 (unattributed)", 0.0)
    bronto_total = projection.cheapest_cost
    savings = obs_total - bronto_total
    savings_pct = _pct(savings, obs_total) if obs_total > 0 else "n/a"
    window_days = max(int(round(projection.months_in_window * 30.4375)), 1)

    lines: list[str] = []
    lines.append("# AWS Observability Cost Audit")
    lines.append("")
    lines.append(f"_Window: {report.start} → {report.end} ({window_days} days)_")
    lines.append(
        f"_Management account: {mgmt_account_id} — accounts scanned: {len(accounts)}"
        f"{f' (skipped: {len(skipped)})' if skipped else ''}_"
    )
    lines.append("")

    # Executive summary
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"- **Total AWS observability spend ({window_days}d):** {_usd(obs_total)}")
    lines.append(
        f"- **Projected Bronto spend (same volume, {projection.cheapest_plan} plan):** "
        f"{_usd(bronto_total)}"
    )
    if projection.gb_searched > 0:
        ingest_cost = projection.plan_ingest_costs.get(projection.cheapest_plan, 0.0)
        search_cost = projection.plan_search_costs.get(projection.cheapest_plan, 0.0)
        lines.append(
            f"  - Ingest: {_usd(ingest_cost)} ({projection.gb_ingested:,.1f} GB) · "
            f"Search: {_usd(search_cost)} ({projection.gb_searched:,.1f} GB scanned)"
        )
    if obs_total > 0:
        lines.append(f"- **Projected savings:** {_usd(savings)} ({savings_pct})")
    if s3_unattr > 0:
        lines.append(
            f"- _S3 (unattributed) spend in the same window: {_usd(s3_unattr)} — "
            "not included in totals above; run with `--probe` to attribute log-sink buckets._"
        )
    lines.append("")

    # Spend by bucket
    lines.append("## Spend by Service")
    lines.append("")
    lines.append("| Service / Bucket | Spend | % of obs total |")
    lines.append("| --- | ---: | ---: |")
    by_bucket = report.by_bucket()
    for bucket, amt in sorted(by_bucket.items(), key=lambda kv: kv[1], reverse=True):
        if bucket == "S3 (unattributed)":
            continue
        lines.append(f"| {bucket} | {_usd(amt)} | {_pct(amt, obs_total)} |")
    if s3_unattr > 0:
        lines.append(f"| _S3 (unattributed)_ | _{_usd(s3_unattr)}_ | _(excluded)_ |")
    lines.append(f"| **Total** | **{_usd(obs_total)}** | **100.0%** |")
    lines.append("")

    # Spend by account
    lines.append("## Spend by Account")
    lines.append("")
    lines.append("| Account ID | Name | Spend |")
    lines.append("| --- | --- | ---: |")
    by_account = report.by_account()
    name_by_id = {a.id: a.name for a in accounts}
    for acct_id, amt in sorted(by_account.items(), key=lambda kv: kv[1], reverse=True):
        if acct_id == "*":
            continue
        lines.append(f"| {acct_id} | {name_by_id.get(acct_id, '?')} | {_usd(amt)} |")
    lines.append("")

    if skipped:
        lines.append("### Accounts skipped")
        lines.append("")
        for acct_id, reason in skipped:
            lines.append(f"- `{acct_id}` — {reason}")
        lines.append("")

    # Volume & retention from probes
    if probes is not None:
        lines.append("## Volume & Retention (from --probe)")
        lines.append("")
        if probes.cloudwatch_logs is not None:
            p = probes.cloudwatch_logs
            gb = p.stored_bytes / (1024 ** 3)
            lines.append(
                f"- **CloudWatch Logs:** {p.group_count:,} groups, "
                f"{gb:,.1f} GB stored, "
                f"{p.groups_never_expire:,} with no retention policy."
            )
            if p.retention_histogram:
                hist = ", ".join(f"{k}: {v}" for k, v in sorted(p.retention_histogram.items()))
                lines.append(f"  - Retention histogram: {hist}")
        if probes.cloudwatch_metrics is not None:
            p = probes.cloudwatch_metrics
            lines.append(
                f"- **CloudWatch Metrics:** {p.custom_metric_count:,} custom metrics, "
                f"{p.alarm_count:,} alarms, {p.dashboard_count:,} dashboards."
            )
        if probes.xray is not None:
            p = probes.xray
            lines.append(
                f"- **X-Ray:** {p.traces_received:,.0f} traces received in the last 30d "
                f"({p.sampling_rules} sampling rules)."
            )
        if probes.amp is not None:
            p = probes.amp
            lines.append(
                f"- **Managed Prometheus:** {p.workspace_count} workspaces, "
                f"{p.ingested_samples:,.0f} samples in last 30d."
            )
        if probes.amg is not None:
            p = probes.amg
            lines.append(f"- **Managed Grafana:** {p.workspace_count} workspaces.")
        if probes.opensearch is not None:
            p = probes.opensearch
            lines.append(
                f"- **OpenSearch:** {p.domain_count} domains, "
                f"{p.total_storage_gb:,.0f} GB provisioned storage."
            )
        if probes.vpc_flow_logs is not None:
            p = probes.vpc_flow_logs
            dests = ", ".join(f"{k}: {v}" for k, v in p.by_destination.items())
            lines.append(
                f"- **VPC Flow Logs:** {p.flow_log_count} flow logs ({dests or 'none'})."
            )
        if probes.cloudtrail is not None:
            p = probes.cloudtrail
            lines.append(
                f"- **CloudTrail:** {p.trail_count} trails, "
                f"{p.trails_with_data_events} with data events, "
                f"{p.multi_region_trails} multi-region."
            )
        if probes.s3_log_sinks is not None:
            p = probes.s3_log_sinks
            attrib_gb = p.total_attributed_size_bytes / (1024 ** 3)
            susp_gb = p.total_suspected_size_bytes / (1024 ** 3)
            lines.append(
                f"- **S3 log sinks:** {len(p.attributed_buckets)} buckets attributed to log sources "
                f"({attrib_gb:,.1f} GB stored); "
                f"{len(p.suspected_buckets)} additional name-match candidates ({susp_gb:,.1f} GB)."
            )
            if p.sources_seen:
                srcs = ", ".join(f"{k}: {v}" for k, v in sorted(p.sources_seen.items()))
                lines.append(f"  - Sources detected: {srcs}")
        lines.append("")

        # Dedicated S3 attribution section if we have data.
        if probes.s3_log_sinks is not None and (probes.s3_log_sinks.attributed_buckets or probes.s3_log_sinks.suspected_buckets):
            lines.append("### S3 Log-Sink Attribution")
            lines.append("")
            if probes.s3_log_sinks.attributed_buckets:
                lines.append("**Confirmed** (attributed to a specific AWS log source):")
                lines.append("")
                lines.append("| Bucket | Region | Size | Source(s) |")
                lines.append("| --- | --- | ---: | --- |")
                for b in probes.s3_log_sinks.attributed_buckets[:40]:
                    size_gb = b.size_bytes / (1024 ** 3)
                    srcs = "; ".join(sorted(set(b.sources)))
                    lines.append(f"| `{b.name}` | {b.region or '?'} | {size_gb:,.2f} GB | {srcs} |")
                if len(probes.s3_log_sinks.attributed_buckets) > 40:
                    lines.append(f"| _…and {len(probes.s3_log_sinks.attributed_buckets) - 40} more_ |  |  |  |")
                lines.append("")
            if probes.s3_log_sinks.suspected_buckets:
                lines.append("**Suspected** (bucket name matches log heuristics — verify manually):")
                lines.append("")
                lines.append("| Bucket | Region | Size |")
                lines.append("| --- | --- | ---: |")
                for b in probes.s3_log_sinks.suspected_buckets[:20]:
                    size_gb = b.size_bytes / (1024 ** 3)
                    lines.append(f"| `{b.name}` | {b.region or '?'} | {size_gb:,.2f} GB |")
                if len(probes.s3_log_sinks.suspected_buckets) > 20:
                    lines.append(f"| _…and {len(probes.s3_log_sinks.suspected_buckets) - 20} more_ |  |  |")
                lines.append("")

    # Bronto projection detail
    lines.append("## Bronto Projection Detail")
    lines.append("")
    lines.append(
        f"_Ingest volume (CW Logs, custom Metrics, Metric Streams, X-Ray, "
        f"AMP, CloudTrail data events, OpenSearch when probed): "
        f"**{projection.gb_ingested:,.1f} GB** over {window_days} days._"
    )
    if projection.gb_searched > 0:
        lines.append(
            f"_Search/scan volume (CW Logs Insights `DataScanned-Bytes`): "
            f"**{projection.gb_searched:,.1f} GB** over {window_days} days._"
        )
    lines.append("")
    if projection.per_source_gb:
        lines.append("| Source | GB ingested |")
        lines.append("| --- | ---: |")
        for src, gb in sorted(projection.per_source_gb.items(), key=lambda kv: kv[1], reverse=True):
            lines.append(f"| {src} | {gb:,.1f} |")
        lines.append("")
    lines.append(
        "| Plan | Monthly fee | Included ingest | Search allowance | "
        "Ingest cost | Search cost | Total |"
    )
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: |")
    for plan in pricing.plans:
        name = plan["name"]
        fee = float(plan["monthly_fee_usd"])
        inc = float(plan["included_tb"])
        ingest_cost = projection.plan_ingest_costs.get(name, 0.0)
        search_cost = projection.plan_search_costs.get(name, 0.0)
        total = projection.plan_costs.get(name, 0.0)
        allowance_gb = projection.plan_search_allowance_gb.get(name, 0.0)
        if "search_multiplier_of_ingest" in plan:
            allowance_label = (
                f"{plan['search_multiplier_of_ingest']}× ingest "
                f"({allowance_gb / TB_TO_GB:,.1f} TB)"
            )
        else:
            allowance_label = f"{allowance_gb / TB_TO_GB:,.0f} TB"
        cheapest = " ←" if name == projection.cheapest_plan else ""
        lines.append(
            f"| {name}{cheapest} | {_usd(fee)} | {inc} TB/mo | {allowance_label} | "
            f"{_usd(ingest_cost)} | {_usd(search_cost)} | {_usd(total)} |"
        )
    if projection.gb_searched > 0:
        lines.append("")
        lines.append(
            f"_Search overage: ${pricing.search_per_gb_usd * 1024:.0f}/TB on all "
            f"plans once the included allowance is exceeded._"
        )
    lines.append("")

    # Caveats
    lines.append("## Caveats")
    lines.append("")
    lines.append(
        "- S3 spend is reported separately and **not** rolled into observability totals. "
        "The `S3 (unattributed)` figure includes every S3 bucket in the account — most "
        "of which are usually product/data buckets, not log sinks. Run with `--probe` "
        "and read the **S3 Log-Sink Attribution** section above for the real log-sink "
        "subset."
    )
    lines.append(
        "- Bronto's per-GB projection only counts data Bronto would actually ingest "
        "(log bytes, metric data points, trace data, CloudTrail events, OpenSearch "
        "indexed data). AWS charges that Bronto does **not** levy — alarm-monitor "
        "hours, dashboard fees, API request tiers, retention storage beyond 12 months, "
        "EBS volumes for OpenSearch nodes — show up as AWS spend with no Bronto "
        "counterpart, which is why the projected savings can look large."
    )
    lines.append(
        "- Bronto search inclusion varies per plan: Starter bundles 20 TB, "
        "Pro bundles 500 TB, Enterprise scales as 100× the customer's actual "
        "ingested volume. Overage on any plan is $1/TB."
    )
    if projection.extended_retention_note:
        lines.append(f"- {projection.extended_retention_note}")
    lines.append(
        "- OpenSearch ingest is estimated from probe-reported provisioned storage "
        "divided by `opensearch_retention_months_assumption` in "
        "`config/bronto_pricing.yaml` (default: 1 month). Tune for your actual "
        "index retention."
    )
    lines.append(
        "- CloudWatch custom metrics are converted to GB at "
        "`bytes_per_metric_month` (default 3.4 MB/metric-month, ~1-min resolution). "
        "Tune for your actual datapoint resolution."
    )
    lines.append(
        "- Trace and CloudTrail event volumes are converted to GB using configurable "
        "bytes-per-event assumptions in `config/bronto_pricing.yaml`."
    )
    lines.append("")
    return "\n".join(lines)
