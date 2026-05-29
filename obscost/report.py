"""Markdown report renderer.

Layout: blockquote callout → full Executive Summary (top bookend) →
spend tables → projection detail → caveats → TL;DR Executive Summary
(bottom bookend, mirrors the headline so a reader who scrolls down
still sees the savings figure).

Annualized savings = window savings × (365 / window_days). Always
paired with a disclaimer about not modeling company growth, retention
changes, or workload shifts.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .bronto import (
    FLOOR_BUCKETS,
    BrontoPricing,
    BrontoProjection,
    TB_TO_GB,
    signal_type,
)
from .cost_explorer import CostReport
from .org import Account


ANNUALIZATION_DISCLAIMER = (
    "Extrapolated from current usage; does not account for company "
    "growth, retention changes, or workload shifts."
)


def _annualized(savings_abs: float, window_days: int) -> float:
    if window_days <= 0:
        return 0.0
    return savings_abs * (365.0 / window_days)


def _bucket_status(bucket: str, decommissioned: set[str]) -> str:
    if bucket in decommissioned:
        return "_decommissioned_"
    if bucket in FLOOR_BUCKETS:
        return "**floor (survives)**"
    return "displaceable"


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
    obs_total = projection.obs_total_as_billed or report.total(include_s3_unattributed=False)
    obs_total_forward = projection.obs_total_forward or obs_total
    s3_unattr = report.by_bucket().get("S3 (unattributed)", 0.0)
    bronto_total = projection.cheapest_cost
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

    annualized_savings = _annualized(projection.apples_savings_abs, window_days)

    # Lead with apples-to-apples forward-looking savings.
    if obs_total_forward > 0:
        callout = (
            f"> **Projected savings (forward-looking, apples-to-apples): "
            f"{projection.apples_savings_pct:.1f}% "
            f"({_usd(projection.apples_savings_abs)} over {window_days} days)** — "
            f"post-migration AWS+Bronto cost {_usd(projection.post_migration_cost)} "
            f"vs **{_usd(obs_total_forward)}** AWS run-rate"
        )
        if projection.decom_spend > 0:
            callout += f" (excludes {_usd(projection.decom_spend)} of decommissioned services)"
        callout += (
            f". Unavoidable AWS-side floor: **{_usd(projection.aws_floor)}** "
            f"(MetricStream + Firehose). "
            f"**Projected annual savings: {_usd(annualized_savings)}/year (extrapolated)**."
        )
        lines.append(callout)
        lines.append("")

    # Executive summary
    lines.append("## Executive Summary")
    lines.append("")
    if projection.decommissioned:
        decom_list = ", ".join(sorted(projection.decommissioned))
        lines.append(
            f"⚠️  **Decommissioned services detected**: {decom_list} had spend in the "
            f"{window_days}-day window but $0 in the trailing 7 days. Excluded from "
            f"forward-looking projection. Historical spend: {_usd(projection.decom_spend)}."
        )
        lines.append("")
    if obs_total > 0:
        lines.append(
            f"- **Projected savings (forward-looking, apples-to-apples):** "
            f"{_usd(projection.apples_savings_abs)} "
            f"({projection.apples_savings_pct:.1f}%)"
        )
        lines.append(
            f"- **Projected annual savings**: {_usd(annualized_savings)}/year "
            f"_({ANNUALIZATION_DISCLAIMER})_"
        )
    lines.append(
        f"- AWS observability spend, as-billed over {window_days} days: "
        f"**{_usd(obs_total)}**"
    )
    if projection.decom_spend > 0:
        lines.append(
            f"- AWS observability spend, forward-looking (ex-decommissioned): "
            f"**{_usd(obs_total_forward)}**"
        )
    lines.append(
        f"- Post-migration cost: **{_usd(projection.post_migration_cost)}** "
        f"= AWS floor {_usd(projection.aws_floor)} + Bronto {projection.cheapest_plan} "
        f"{_usd(bronto_total)}"
    )
    cw_ms = report.by_bucket().get("CloudWatch MetricStream (floor)", 0.0)
    fh = report.by_bucket().get("Firehose (floor)", 0.0)
    floor_parts: list[str] = []
    if cw_ms > 0:
        floor_parts.append(f"MetricStream {_usd(cw_ms)}")
    if fh > 0:
        floor_parts.append(f"Firehose {_usd(fh)}")
    if floor_parts:
        lines.append(
            f"- **AWS-side floor** ({_usd(projection.aws_floor)}, survives migration): "
            + " + ".join(floor_parts)
        )
    lines.append(
        f"- **Displaceable AWS spend** (eliminated by Bronto): "
        f"{_usd(projection.displaceable)}"
    )
    bronto_line = (
        f"- Projected Bronto spend (cheapest = **{projection.cheapest_plan}**): "
        f"**{_usd(bronto_total)}**"
    )
    if projection.gb_searched > 0:
        ingest_cost = projection.plan_ingest_costs.get(projection.cheapest_plan, 0.0)
        search_cost = projection.plan_search_costs.get(projection.cheapest_plan, 0.0)
        bronto_line += f" — ingest {_usd(ingest_cost)} + search {_usd(search_cost)}"
    lines.append(bronto_line)
    if projection.per_signal_gb:
        sig = projection.per_signal_gb
        lines.append(
            f"- Ingest by signal type: Logs {sig.get('logs', 0):,.1f} GB · "
            f"Metrics {sig.get('metrics', 0):,.1f} GB · "
            f"Traces {sig.get('traces', 0):,.1f} GB "
            f"(total **{projection.gb_ingested:,.1f} GB**)"
        )
    if s3_unattr > 0:
        lines.append(
            f"- _S3 (unattributed) spend in the same window: {_usd(s3_unattr)} — "
            "not included in totals above; run with `--probe` to attribute log-sink buckets._"
        )
    lines.append("")

    # Spend by bucket — with Status column (floor / displaceable / decom)
    lines.append("## Spend by Service")
    lines.append("")
    lines.append(
        "Status legend: **floor** = survives migration (AWS egress charges); "
        "**displaceable** = eliminated by Bronto; **decommissioned** = had spend "
        "in window but $0 in trailing 7d, excluded from forward-looking projection."
    )
    lines.append("")
    lines.append("| Service / Bucket | Spend | % of obs total | Status |")
    lines.append("| --- | ---: | ---: | --- |")
    by_bucket = report.by_bucket()
    for bucket, amt in sorted(by_bucket.items(), key=lambda kv: kv[1], reverse=True):
        if bucket == "S3 (unattributed)":
            continue
        status = _bucket_status(bucket, projection.decommissioned)
        lines.append(f"| {bucket} | {_usd(amt)} | {_pct(amt, obs_total)} | {status} |")
    if s3_unattr > 0:
        lines.append(
            f"| _S3 (unattributed)_ | _{_usd(s3_unattr)}_ | _(excluded)_ | excluded from comparison |"
        )
    lines.append(
        f"| **Total (observability, as-billed)** | **{_usd(obs_total)}** | 100.0% | |"
    )
    if projection.decom_spend > 0:
        lines.append(f"| ↳ minus decommissioned | −{_usd(projection.decom_spend)} | | |")
        lines.append(
            f"| **= Forward-looking total** | **{_usd(obs_total_forward)}** | | |"
        )
    if obs_total_forward > 0:
        lines.append(
            f"| ↳ floor subtotal (forward) | {_usd(projection.aws_floor)} | "
            f"{_pct(projection.aws_floor, obs_total_forward)} | survives |"
        )
        lines.append(
            f"| ↳ displaceable subtotal | {_usd(projection.displaceable)} | "
            f"{_pct(projection.displaceable, obs_total_forward)} | eliminated |"
        )
    lines.append("")

    # AWS-side Floor detail
    lines.append("## AWS-side Floor (post-migration, forward-looking)")
    lines.append("")
    lines.append(
        "These AWS charges remain after switching log / metric / trace storage and "
        "querying to Bronto. They are kept on the AWS side of the comparison."
    )
    lines.append("")
    lines.append("| Line | Spend | Status | Why it survives |")
    lines.append("| --- | ---: | --- | --- |")
    floor_rows_data = [
        (
            "CloudWatch MetricStream",
            cw_ms,
            "CloudWatch MetricStream (floor)",
            (
                "$0.003 per 1K metric updates streamed out of CW Metrics — same fee "
                "regardless of destination (Bronto, Datadog, S3). Avoidable only by "
                "re-sourcing AWS-platform metrics away from CW."
            ),
        ),
        (
            "Kinesis Firehose",
            fh,
            "Firehose (floor)",
            "Transport layer for MetricStream → Bronto. Billed per GB delivered "
            "+ cross-region transfer.",
        ),
    ]
    for label, amt, bucket_name, why in floor_rows_data:
        if amt <= 0:
            continue
        status = "**decommissioned**" if bucket_name in projection.decommissioned else "active"
        lines.append(f"| {label} | {_usd(amt)} | {status} | {why} |")
    lines.append(
        f"| **Total floor (forward-looking)** | **{_usd(projection.aws_floor)}** | | |"
    )
    if projection.aws_floor_historical > projection.aws_floor:
        lines.append(
            f"| _Historical floor incl. decommissioned_ | "
            f"_{_usd(projection.aws_floor_historical)}_ | | |"
        )
    lines.append("")

    # OpenSearch Displacement Analysis
    os_aws_cost = by_bucket.get("OpenSearch", 0.0)
    if projection.os_displacement is not None and os_aws_cost > 0:
        os_decom = "OpenSearch" in projection.decommissioned
        title = "## OpenSearch: Decommissioned" if os_decom else "## OpenSearch Displacement Analysis"
        lines.append(title)
        lines.append("")
        if os_decom:
            lines.append(
                f"**The OpenSearch domain went silent in the trailing 7 days** "
                f"(was active during the analysis window). The {_usd(os_aws_cost)} "
                "in the historical window is excluded from the forward-looking "
                "projection above. The displacement scenario below is retained "
                "as reference for what the workload *would have* cost on Bronto."
            )
        else:
            lines.append(
                "OpenSearch is treated as **displaceable** — Bronto can absorb "
                "log-search / SIEM / time-series-analytics workloads (caveats for "
                "vector / RAG / e-commerce search at the end of this section). "
                "This section estimates the Bronto cost to absorb the workload, "
                "using the cluster shape backed out of Cost Explorer line items + "
                "[AWS's published OpenSearch pricing](https://aws.amazon.com/opensearch-service/pricing/) "
                "sizing rules. The `--probe` results (below) corroborate this with "
                "direct API attempts where they succeed."
            )
        lines.append("")

        fp = projection.os_displacement.footprint
        lines.append("### Cluster footprint (inferred from Cost Explorer)")
        lines.append("")
        if fp.instance_type:
            lines.append(
                f"- **Instance**: {fp.instance_hours:.0f} hours of "
                f"`{fp.instance_type}.search` @ ${fp.instance_rate:.4f}/hr "
                f"({fp.node_days:.1f} node-days over {window_days}-day window)"
            )
        if fp.ebs_type:
            lines.append(
                f"- **Storage**: {fp.ebs_gb_months:.1f} GB-months of "
                f"{fp.ebs_type.upper()} @ ${fp.ebs_rate:.3f}/GB-mo → "
                f"**~{fp.ebs_gb_provisioned:.0f} GB provisioned**"
            )
        # Probe corroboration
        if probes is not None and probes.opensearch is not None:
            p = probes.opensearch
            if p.domain_count > 0:
                lines.append(
                    f"- **Direct probe**: `opensearch list-domain-names` "
                    f"succeeded — {p.domain_count} domain(s) visible in the "
                    f"current principal's account ({p.total_storage_gb:,.0f} GB "
                    "provisioned)."
                )
            else:
                lines.append(
                    "- **Direct probe attempted, returned 0 domains** — "
                    "`aws opensearch list-domain-names` ran in this run's regions "
                    "but the OpenSearch domain likely lives in a *linked account* "
                    "we don't have cross-account access to. Productionizing would "
                    "need a cross-account read-only role."
                )
        lines.append("")

        disp = projection.os_displacement
        lines.append("### Sizing logic (from AWS OpenSearch pricing examples)")
        lines.append("")
        lines.append(f"- Provisioned EBS: **{fp.ebs_gb_provisioned:.0f} GB**")
        lines.append("- × 0.85 free-space headroom (OS reserves space to avoid disk-full)")
        lines.append("- × 0.91 Lucene/segment overhead (indexing produces ~10% overhead vs raw)")
        lines.append(f"- = **{disp.usable_gb:.0f} GB usable** for actual data")
        lines.append("- × 0.80 typical utilization (clusters don't run at 100% full)")
        lines.append(
            f"- = **{disp.raw_resident_gb:.0f} GB raw data resident** at steady state"
        )
        lines.append("")
        lines.append(
            "Single-node domain ⇒ 0 replicas. For multi-node with 1 replica, "
            "halve the raw data estimate."
        )
        lines.append("")

        starter_incl_gb = float(
            next((p["included_tb"] for p in pricing.plans if p["name"].lower() == "starter"), 0)
        ) * TB_TO_GB * max(projection.months_in_window, 1e-9)
        headroom = max(starter_incl_gb - projection.gb_ingested, 0.0)
        lines.append("### Bronto cost to absorb, by retention scenario")
        lines.append("")
        lines.append(
            f"Resident data is the same regardless of retention — the difference "
            f"is *flow*. Shorter retention means higher daily ingest rate to "
            f"maintain the same {disp.raw_resident_gb:.0f} GB resident."
        )
        lines.append("")
        lines.append(
            f"Current observability ingest projection: **{projection.gb_ingested:,.1f} GB** "
            f"out of Starter's **{starter_incl_gb:,.1f} GB** included → headroom "
            f"of **{headroom:,.1f} GB** before any overage."
        )
        lines.append("")
        lines.append(
            "| Retention | Daily ingest | Total ingest over window | Fits Starter? | "
            "Bronto incremental | OpenSearch saved | Net savings |"
        )
        lines.append("| --- | ---: | ---: | :---: | ---: | ---: | ---: |")
        for sc in disp.scenarios:
            fits = "✓" if sc.fits_in_starter else "overage"
            net = os_aws_cost - sc.incremental_bronto_cost
            lines.append(
                f"| {sc.retention_days}d | {sc.ingest_per_day_gb:,.1f} GB/day | "
                f"{sc.ingest_over_window_gb:,.1f} GB | {fits} | "
                f"{_usd(sc.incremental_bronto_cost)} | {_usd(os_aws_cost)} | "
                f"**{_usd(net)}** |"
            )
        lines.append("")
        lines.append(
            "**Caveat — does Bronto actually replace this OpenSearch workload?** "
            f"A `{fp.instance_type or 'small'}` + ~{fp.ebs_gb_provisioned:.0f} GB "
            "cluster could be any of:"
        )
        lines.append("")
        lines.append("- **Log search / SIEM** → ✅ Bronto displaces fully.")
        lines.append(
            "- **Application search** (e-commerce, doc search) → "
            "❌ Bronto does not displace; OpenSearch stays."
        )
        lines.append(
            "- **Time-series analytics / dashboarding** → ✅ Bronto displaces "
            "(it's effectively logs + metrics)."
        )
        lines.append("- **Vector / RAG embeddings** → ❌ Bronto does not displace.")
        lines.append("")
        lines.append(
            "Without describe-domain access we can't tell which. Apply judgment "
            "based on what team owns this domain."
        )
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
        sbs = projection.search_gb_by_signal
        lines.append(
            f"_Search/scan volume: **{projection.gb_searched:,.1f} GB** "
            f"over {window_days} days "
            f"(Logs {sbs.get('logs', 0):,.1f} · "
            f"Metrics {sbs.get('metrics', 0):,.1f} · "
            f"Traces {sbs.get('traces', 0):,.1f})._"
        )
    lines.append("")
    if projection.per_source_gb:
        lines.append("| Signal | Source | GB ingested |")
        lines.append("| --- | --- | ---: |")
        for src, gb in sorted(projection.per_source_gb.items(), key=lambda kv: kv[1], reverse=True):
            lines.append(f"| {signal_type(src)} | {src} | {gb:,.1f} |")
        sig = projection.per_signal_gb
        lines.append(f"| **logs** | **subtotal** | **{sig.get('logs', 0):,.1f}** |")
        lines.append(f"| **metrics** | **subtotal** | **{sig.get('metrics', 0):,.1f}** |")
        lines.append(f"| **traces** | **subtotal** | **{sig.get('traces', 0):,.1f}** |")
        lines.append("")
    lines.append("### Plan comparison (apples-to-apples — Bronto + AWS floor vs current AWS)")
    lines.append("")
    lines.append(
        f"AWS floor surviving migration: **{_usd(projection.aws_floor)}** "
        "(added to each plan's total below)."
    )
    lines.append("")
    lines.append(
        "| Plan | Monthly fee | Included ingest | Search allowance | "
        "Bronto cost | + AWS floor | All-in total |"
    )
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: |")
    for plan in pricing.plans:
        name = plan["name"]
        fee = float(plan["monthly_fee_usd"])
        inc = float(plan["included_tb"])
        bronto_cost = projection.plan_costs.get(name, 0.0)
        allowance_gb = projection.plan_search_allowance_gb.get(name, 0.0)
        if "search_multiplier_of_ingest" in plan:
            allowance_label = (
                f"{plan['search_multiplier_of_ingest']}× ingest "
                f"({allowance_gb / TB_TO_GB:,.1f} TB)"
            )
        elif allowance_gb > 0:
            allowance_label = f"{allowance_gb / TB_TO_GB:,.0f} TB"
        else:
            allowance_label = "$1/TB from byte 1"
        incl_label = f"{inc} TB/mo" if inc > 0 else "$0.10/GB from byte 1"
        all_in = bronto_cost + projection.aws_floor
        cheapest = " ←" if name == projection.cheapest_plan else ""
        lines.append(
            f"| {name}{cheapest} | {_usd(fee)} | {incl_label} | {allowance_label} | "
            f"{_usd(bronto_cost)} | {_usd(projection.aws_floor)} | "
            f"**{_usd(all_in)}** |"
        )
    lines.append(
        f"| _Status quo (forward-looking, ex-decom)_ | — | — | — | — | — | "
        f"**{_usd(obs_total_forward)}** |"
    )
    if projection.decom_spend > 0:
        lines.append(
            f"| _Status quo (as-billed, incl. decom)_ | — | — | — | — | — | "
            f"_{_usd(obs_total)}_ |"
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
        "- **Apples-to-apples comparison** assumes you keep AWS-platform metrics "
        "flowing into Bronto via CloudWatch MetricStream → Firehose. That path is "
        "the cost floor you cannot avoid without re-sourcing metrics away from "
        "CloudWatch entirely (e.g., OTel Collector scraping services directly)."
    )
    lines.append(
        "- **OpenSearch is in the displaceable bucket** — Bronto absorbs log-search, "
        "SIEM, and time-series workloads. **It does not displace** application "
        "search (e-commerce, doc search), vector / RAG embeddings, or similar use "
        "cases. Use the displacement section + your knowledge of the domain's "
        "purpose to decide whether the saving is real."
    )
    lines.append(
        "- **Decommissioned services** are detected via a trailing-7-day Cost Explorer "
        "probe (`granularity=DAILY`, grouped by SERVICE). Any observability service "
        "with spend in the analysis window but $0 in the trailing 7 days is flagged "
        "and excluded from the forward-looking baseline. CloudWatch and S3 are "
        "deliberately excluded from this check (too broad — false positives would "
        "distort the report)."
    )
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
    alarms_plus_dashboards = (
        by_bucket.get("CloudWatch Alarms", 0.0)
        + by_bucket.get("CloudWatch Dashboards", 0.0)
    )
    if alarms_plus_dashboards > 0:
        lines.append(
            f"- **Transition overlap**: if you keep CloudWatch Alarms/Dashboards "
            f"running in parallel during the migration, add up to "
            f"**{_usd(alarms_plus_dashboards)}** back onto the post-migration total "
            f"until they're cut over."
        )
    lines.append(
        "- Bronto search inclusion: Starter bundles 20 TB, Pro bundles 500 TB, "
        "Enterprise is pay-as-you-go ($0.10/GB ingest + $1/TB search from byte 1, "
        "no inclusion). Overage on Starter/Pro is $1/TB. Cheapest plan wins."
    )
    if projection.os_displacement:
        lines.append(
            "- **OpenSearch sizing constants** (0.85 / 0.91 / 0.80) come from "
            "[AWS OpenSearch pricing examples](https://aws.amazon.com/opensearch-service/pricing/) "
            "plus general operational guidance. Cluster ingest cannot be derived from "
            "Cost Explorer alone — instance hours and EBS are billed, not bytes."
        )
    lines.append(
        "- Enterprise tier adds non-price perks not captured in this projection: "
        "dedicated Slack channel + TAM, SLA guarantee, custom MSA, HIPAA/SOC2 "
        "on request, extendable retention beyond 12 months."
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

    # TL;DR Executive Summary (bookend) — mirrors the headline so a reader
    # who scrolls to the bottom doesn't have to scroll back to the top.
    lines.append("## TL;DR — Cost Savings")
    lines.append("")
    if obs_total_forward > 0:
        lines.append(
            f"- **Apples-to-apples savings**: {_usd(projection.apples_savings_abs)} "
            f"({projection.apples_savings_pct:.1f}%) over {window_days} days."
        )
        lines.append(
            f"- **Annualized**: {_usd(annualized_savings)}/year "
            f"_({ANNUALIZATION_DISCLAIMER})_"
        )
        if projection.cheapest_plan:
            lines.append(
                f"- **Winning Bronto plan**: {projection.cheapest_plan} "
                f"({_usd(bronto_total)} over the window)."
            )
        lines.append("")
        lines.append("_Detailed assumptions in caveats above._")
        lines.append("")
    return "\n".join(lines)
