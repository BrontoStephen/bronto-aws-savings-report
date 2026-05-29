#!/usr/bin/env python3
"""AWS Observability Cost Audit + Bronto.io Savings Report.

Usage:
  python aws_obs_cost.py [--start YYYY-MM-DD] [--end YYYY-MM-DD]
                         [--profile PROFILE] [--role-name ROLE]
                         [--accounts a,b,c] [--probe]
                         [--bronto-config PATH] [--out PATH]
                         [--regions r1,r2,...]

See README.md for IAM permissions required.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from datetime import date, timedelta
from pathlib import Path

# Make the obscost package importable when run from the repo root.
HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from obscost import bronto, cost_explorer, org, report  # noqa: E402
from obscost.probes import (  # noqa: E402
    amg,
    amp,
    cloudtrail,
    cloudwatch_logs,
    cloudwatch_metrics,
    opensearch,
    s3_log_sinks,
    vpc_flow_logs,
    xray,
)
from obscost.probes.common import DEFAULT_REGIONS  # noqa: E402


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    today = date.today()
    default_start = (today - timedelta(days=90)).isoformat()
    default_end = today.isoformat()
    default_pricing = str(HERE / "config" / "bronto_pricing.yaml")

    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--start", default=default_start, help="Start date YYYY-MM-DD (default: 90 days ago)")
    p.add_argument("--end", default=default_end, help="End date YYYY-MM-DD (default: today)")
    p.add_argument("--profile", default=os.environ.get("AWS_PROFILE"), help="AWS profile for the management account")
    p.add_argument("--role-name", default="OrganizationAccountAccessRole", help="Role to assume in member accounts")
    p.add_argument("--accounts", default="", help="Comma-separated account IDs to include (default: all)")
    p.add_argument("--probe", action="store_true", help="Run per-service usage probes (slower, richer report)")
    p.add_argument("--bronto-config", default=default_pricing, help="Path to bronto_pricing.yaml")
    p.add_argument("--out", default="report.md", help="Output Markdown file")
    p.add_argument(
        "--regions",
        default=",".join(DEFAULT_REGIONS),
        help="Comma-separated regions to scan with probes (default: common observability regions)",
    )
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    return p.parse_args(argv)


def _run_probes(session, regions: list[str]):
    """Run all probes against one account session, return a ProbeBundle."""
    bundle = report.ProbeBundle()
    bundle.cloudwatch_logs = cloudwatch_logs.run(session, regions)
    bundle.cloudwatch_metrics = cloudwatch_metrics.run(session, regions)
    bundle.xray = xray.run(session, regions)
    bundle.amp = amp.run(session, regions)
    bundle.amg = amg.run(session, regions)
    bundle.opensearch = opensearch.run(session, regions)
    bundle.vpc_flow_logs = vpc_flow_logs.run(session, regions)
    bundle.cloudtrail = cloudtrail.run(session, regions)
    bundle.s3_log_sinks = s3_log_sinks.run(session, regions)
    return bundle


def _merge_bundles(bundles: list[report.ProbeBundle]) -> report.ProbeBundle:
    """Sum probe results across accounts into one bundle for the org-wide report."""
    if not bundles:
        return report.ProbeBundle()
    if len(bundles) == 1:
        return bundles[0]

    out = report.ProbeBundle()

    # CloudWatch Logs
    from obscost.probes.cloudwatch_logs import LogsProbeResult
    cw = LogsProbeResult()
    for b in bundles:
        if not b.cloudwatch_logs:
            continue
        cw.group_count += b.cloudwatch_logs.group_count
        cw.stored_bytes += b.cloudwatch_logs.stored_bytes
        cw.groups_never_expire += b.cloudwatch_logs.groups_never_expire
        for k, v in b.cloudwatch_logs.retention_histogram.items():
            cw.retention_histogram[k] = cw.retention_histogram.get(k, 0) + v
    out.cloudwatch_logs = cw

    from obscost.probes.cloudwatch_metrics import MetricsProbeResult
    m = MetricsProbeResult()
    for b in bundles:
        if not b.cloudwatch_metrics:
            continue
        m.custom_metric_count += b.cloudwatch_metrics.custom_metric_count
        m.alarm_count += b.cloudwatch_metrics.alarm_count
        m.dashboard_count += b.cloudwatch_metrics.dashboard_count
    out.cloudwatch_metrics = m

    from obscost.probes.xray import XRayProbeResult
    x = XRayProbeResult()
    for b in bundles:
        if not b.xray:
            continue
        x.sampling_rules += b.xray.sampling_rules
        x.traces_received += b.xray.traces_received
    out.xray = x

    from obscost.probes.amp import AMPProbeResult
    ap = AMPProbeResult()
    for b in bundles:
        if not b.amp:
            continue
        ap.workspace_count += b.amp.workspace_count
        ap.ingested_samples += b.amp.ingested_samples
    out.amp = ap

    from obscost.probes.amg import AMGProbeResult
    ag = AMGProbeResult()
    for b in bundles:
        if not b.amg:
            continue
        ag.workspace_count += b.amg.workspace_count
    out.amg = ag

    from obscost.probes.opensearch import OpenSearchProbeResult
    os_p = OpenSearchProbeResult()
    for b in bundles:
        if not b.opensearch:
            continue
        os_p.domain_count += b.opensearch.domain_count
        os_p.total_storage_gb += b.opensearch.total_storage_gb
        os_p.domains.extend(b.opensearch.domains)
    out.opensearch = os_p

    from obscost.probes.vpc_flow_logs import VPCFlowLogsProbeResult
    v = VPCFlowLogsProbeResult()
    for b in bundles:
        if not b.vpc_flow_logs:
            continue
        v.flow_log_count += b.vpc_flow_logs.flow_log_count
        for k, c in b.vpc_flow_logs.by_destination.items():
            v.by_destination[k] = v.by_destination.get(k, 0) + c
    out.vpc_flow_logs = v

    from obscost.probes.cloudtrail import CloudTrailProbeResult
    ct = CloudTrailProbeResult()
    for b in bundles:
        if not b.cloudtrail:
            continue
        ct.trail_count += b.cloudtrail.trail_count
        ct.trails_with_data_events += b.cloudtrail.trails_with_data_events
        ct.multi_region_trails += b.cloudtrail.multi_region_trails
    out.cloudtrail = ct

    from obscost.probes.s3_log_sinks import S3LogSinkProbeResult
    s3 = S3LogSinkProbeResult()
    for b in bundles:
        if not b.s3_log_sinks:
            continue
        s3.attributed_buckets.extend(b.s3_log_sinks.attributed_buckets)
        s3.suspected_buckets.extend(b.s3_log_sinks.suspected_buckets)
        s3.total_attributed_size_bytes += b.s3_log_sinks.total_attributed_size_bytes
        s3.total_suspected_size_bytes += b.s3_log_sinks.total_suspected_size_bytes
        for src, count in b.s3_log_sinks.sources_seen.items():
            s3.sources_seen[src] = s3.sources_seen.get(src, 0) + count
    s3.attributed_buckets.sort(key=lambda b: b.size_bytes, reverse=True)
    s3.suspected_buckets.sort(key=lambda b: b.size_bytes, reverse=True)
    out.s3_log_sinks = s3

    return out


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    log = logging.getLogger("aws_obs_cost")

    pricing = bronto.BrontoPricing.load(args.bronto_config)
    log.info("Loaded Bronto pricing from %s (ingest=$%.2f/GB)", args.bronto_config, pricing.ingest_per_gb_usd)

    oc = org.OrgClient(profile=args.profile, role_name=args.role_name)
    log.info("Management account: %s", oc.mgmt_account_id)

    filter_ids = [a.strip() for a in args.accounts.split(",") if a.strip()] or None
    accounts = oc.list_accounts(filter_ids=filter_ids)
    log.info("Discovered %d active account(s)", len(accounts))

    # Cost Explorer is called once from the management account — it aggregates
    # the whole org for us. We still walk per-account for probes only.
    cost = cost_explorer.fetch_costs(
        mgmt_session=oc._mgmt_session,
        start=args.start,
        end=args.end,
        account_ids=[a.id for a in accounts] if filter_ids else None,
    )
    log.info("Cost Explorer returned %d usage lines across %d account(s)",
             len(cost.lines), len(cost.accounts_seen))

    # Firehose is the transport layer for CW MetricStream → Bronto. Pulled
    # as a separate CE call (different service dimension) and merged into
    # the main report's lines so Firehose (floor) appears in per-bucket totals.
    firehose_lines = cost_explorer.fetch_firehose_costs(
        mgmt_session=oc._mgmt_session,
        start=args.start,
        end=args.end,
        account_ids=[a.id for a in accounts] if filter_ids else None,
    )
    if firehose_lines:
        cost.lines.extend(firehose_lines)
        log.info("Firehose CE query: %d additional usage lines", len(firehose_lines))

    # Trailing-7-day probe to detect decommissioned services.
    recent_spend = cost_explorer.fetch_recent_spend_by_service(
        mgmt_session=oc._mgmt_session,
        days=7,
        account_ids=[a.id for a in accounts] if filter_ids else None,
    )
    decom_active = [s for s, v in recent_spend.items() if v > 0]
    log.info("Trailing-7d probe: %d services with non-zero spend", len(decom_active))

    skipped: list[tuple[str, str]] = []
    probe_bundle: report.ProbeBundle | None = None
    if args.probe:
        regions = [r.strip() for r in args.regions.split(",") if r.strip()]
        log.info("Running probes across %d region(s) for %d account(s)…", len(regions), len(accounts))
        bundles: list[report.ProbeBundle] = []
        for acct in accounts:
            session = oc.session_for(acct)
            if session is None:
                skipped.append((acct.id, "AssumeRole failed"))
                continue
            log.info("  Probing %s (%s)", acct.id, acct.name)
            bundles.append(_run_probes(session, regions))
        probe_bundle = _merge_bundles(bundles)

    opensearch_storage_gb = 0.0
    if probe_bundle and probe_bundle.opensearch is not None:
        opensearch_storage_gb = probe_bundle.opensearch.total_storage_gb
    projection = bronto.project(
        cost, pricing,
        opensearch_storage_gb=opensearch_storage_gb,
        recent_spend_by_service=recent_spend,
    )
    log.info(
        "Projected Bronto cost: $%.2f (plan: %s) on %.1f GB ingested; "
        "apples-to-apples savings $%.2f (%.1f%%)",
        projection.cheapest_cost, projection.cheapest_plan, projection.gb_ingested,
        projection.apples_savings_abs, projection.apples_savings_pct,
    )
    if projection.decommissioned:
        log.info("Decommissioned: %s", ", ".join(sorted(projection.decommissioned)))

    md = report.render(
        report=cost,
        accounts=accounts,
        skipped=skipped,
        projection=projection,
        pricing=pricing,
        mgmt_account_id=oc.mgmt_account_id,
        probes=probe_bundle,
    )
    out_path = Path(args.out)
    out_path.write_text(md)
    print(f"Wrote report to {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
