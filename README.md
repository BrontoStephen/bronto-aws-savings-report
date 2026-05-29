# AWS Observability Cost Audit → Bronto.io Savings Report

Audit what AWS bills you for observability and project what the same
ingested volume would cost on [Bronto.io](https://bronto.io/pricing).
**Apples-to-apples**: AWS charges that survive a Bronto migration
(CloudWatch MetricStream + Firehose — the "floor") stay on the AWS
side; only displaceable spend is replaced by the Bronto plan.

## How to run this — three options

### 1. Recommended — use [PROMPT.md](https://github.com/BrontoStephen/aws-observability-bill-vs-bronto/blob/main/PROMPT.md) with any LLM coding agent

Paste the sibling repo's [PROMPT.md](https://github.com/BrontoStephen/aws-observability-bill-vs-bronto/blob/main/PROMPT.md)
into [Claude Code](https://claude.com/claude-code),
[OpenAI Codex CLI](https://github.com/openai/codex-cli),
[Google Antigravity](https://antigravity.google), or any LLM agent with
AWS CLI access. The LLM runs `aws ce` calls directly and produces the
same Markdown report — **and you can keep going from there**: pivot
into specific accounts, drill into anomalies, probe odd usage types,
ask "why is X so high?". A fixed script can't do that. A prompt can.

### 2. No LLM available? Run the CE-only Python.

Either this repo without `--probe`, or the dedicated sibling repo
[`aws-observability-bill-vs-bronto`](https://github.com/BrontoStephen/aws-observability-bill-vs-bronto)
which is the same code minus the probes. Fast, deterministic, no
regional walks. Same output structure as option 1.

```sh
python aws_obs_cost.py
```

### 3. Deepest analysis — this repo with `--probe` (you're here).

`--probe` adds cross-account walks, regional probes for OpenSearch /
VPC Flow Logs / AMP, and S3 log-sink attribution. ~3 minutes; richest
output. Use when the Cost Explorer view isn't enough — e.g. OpenSearch
lives in a linked account, or you want bucket-level S3 attribution.

```sh
python aws_obs_cost.py --probe
```

---

This Python CLI walks your AWS Organization, totals every dollar AWS bills
for observability (CloudWatch, X-Ray, AMP/AMG, OpenSearch, VPC Flow Logs,
CloudTrail data events, Kinesis Firehose, plus S3 log sinks), then projects
what the same ingested volume would cost on Bronto: $0.10/GB ingest with
12-month retention bundled, plus per-plan search allowances (Starter
20 TB / Pro 500 TB / Enterprise pay-as-you-go) with $1/TB overage.

Services silent in the trailing 7 days are flagged as decommissioned and
excluded from the forward-looking baseline.

OpenSearch is displaceable for log-search / SIEM / time-series workloads;
vector / RAG / application search are the exceptions. The OpenSearch
displacement section estimates Bronto incremental cost across retention
scenarios using AWS's [published pricing examples](https://aws.amazon.com/opensearch-service/pricing/)
to size the cluster from CE line items. With `--probe`, direct
`opensearch list-domain-names` / `cloudwatch list-metrics --namespace AWS/ES`
attempts are made and corroborated in the report.

## Install

```sh
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Run

Default (last 90 days, all org accounts, Cost Explorer only — fast):

```sh
python aws_obs_cost.py
```

Single account, custom window:

```sh
python aws_obs_cost.py --accounts 123456789012 --start 2026-04-01 --end 2026-05-01
```

Add per-service usage probes (slower; surfaces retention, log group sizes,
custom metric counts, trace volumes, OpenSearch domains, etc.):

```sh
python aws_obs_cost.py --probe
```

Use a non-default profile and role:

```sh
python aws_obs_cost.py --profile mycompany-payer --role-name OrgReadOnly
```

Output is Markdown written to `report.md` (override with `--out`).

## Required IAM permissions

### Management / payer account (whichever profile you pass via `--profile`)

```
organizations:ListAccounts
sts:AssumeRole
ce:GetCostAndUsage      # Cost Explorer must be enabled
```

Cost Explorer is enabled per-organization in the Billing console — one-time
toggle. After enabling it can take ~24 hours for data to populate.

### Member-account role (default `OrganizationAccountAccessRole`)

For the **default** Cost Explorer-only run, no member-account role is needed:
all spend data is pulled from the management account via the `LINKED_ACCOUNT`
dimension.

For `--probe`, the role needs read-only access to each service:

```
logs:Describe*
cloudwatch:List*
cloudwatch:Describe*
cloudwatch:GetMetricStatistics
xray:Get*
aps:List*
grafana:List*
es:List*
es:Describe*
ec2:DescribeFlowLogs
cloudtrail:Describe*
cloudtrail:GetEventSelectors
s3:ListAllMyBuckets
s3:GetBucketLocation
```

`ReadOnlyAccess` covers all of the above.

## Configuring Bronto pricing

Edit [config/bronto_pricing.yaml](config/bronto_pricing.yaml) to change the
rate card or the bytes-per-trace / bytes-per-sample / bytes-per-event
assumptions used to convert counts into ingest volume.

## Output

The report includes:

- **Executive summary** — AWS total, Bronto projection, savings %
- **Spend by service** — CloudWatch Logs, Metrics, Alarms, Dashboards, Insights,
  X-Ray, Managed Prometheus, Managed Grafana, OpenSearch, CloudTrail.
- **Spend by account**
- **Volume & retention** (with `--probe`)
- **Bronto projection detail** across all three plans (Starter, Pro, Enterprise)
- **Caveats** — S3 attribution, retention assumptions, etc.

## What it counts as Bronto ingest

| Source | Cost Explorer usage type | How GB is derived |
| --- | --- | --- |
| CloudWatch Logs — customer | `DataProcessing-Bytes` | Direct (GB) |
| CloudWatch Logs — vended | `VendedLog-Bytes` | Direct (GB) — ALB, CloudFront, Route 53, etc. |
| CloudWatch Logs Insights (search) | `DataScanned-Bytes` | Direct (GB) — counted toward Bronto search |
| CloudWatch custom metrics | `MetricMonitorUsage` | metric-months × bytes/metric-month |
| CloudWatch Metric Streams | `MetricStreamUsage` | updates × bytes/update |
| X-Ray | `TracesRecorded` | traces × bytes/trace |
| Managed Prometheus | `IngestedSamples` | samples × bytes/sample |
| CloudTrail data events | `PaidEventsRecorded` | events × bytes/event |
| OpenSearch | (via `--probe`) | storage ÷ retention assumption |

All bytes-per-unit assumptions live in
[config/bronto_pricing.yaml](config/bronto_pricing.yaml).

### Bronto pricing model

- **Ingest:** $0.10/GB, uniform across logs/metrics/traces.
- **Retention:** 12 months included on all plans.
- **Search:** included on every plan, overage at $1/TB:

  | Plan | Monthly fee | Ingest | Search | Notes |
  | --- | --- | --- | --- | --- |
  | Starter | $25 | 1 TB included | 20 TB included | email support, no SSO |
  | Pro | $500 | 5 TB included | 500 TB included | SSO + RBAC, priority support |
  | Enterprise | custom | $0.10/GB pay-as-you-go | $1/TB pay-as-you-go | dedicated Slack + TAM, SLA, HIPAA/SOC2, extendable retention |

  Worked Enterprise example from Bronto: 1 GB ingest + 300 GB search =
  $0.10 + $0.30 = **$0.40**.

  Projector picks the cheapest total (ingest + search) and shows all three side by side.

## Notes & caveats

- **S3 attribution.** With `--probe`, the script walks every log-producing
  AWS service (CloudTrail, AWS Config, VPC Flow Logs, Kinesis Firehose, ALB
  access logs, CloudFront, S3 server access logs) to build a **real**
  bucket → source map. Buckets without a confirmed source are reported as
  "suspected" by name match only — useful for spotting omissions but not
  authoritative. Bucket sizes are pulled from CloudWatch `BucketSizeBytes`.
- **Bronto savings can look large.** Bronto charges for ingested bytes
  (and search overage) — not alarm hours, dashboards, API requests,
  retention storage beyond 12 months, or OpenSearch node EBS. AWS
  charges that have no Bronto counterpart show up as net savings even
  though Bronto isn't "doing less" — it just bills differently.
- **OpenSearch ingest** is estimated from provisioned storage ÷
  `opensearch_retention_months_assumption` (default 1 month). Tune for
  your real index retention.
- **Extended retention** beyond 12 months is "contact sales" on Bronto,
  so it's footnoted rather than estimated.
