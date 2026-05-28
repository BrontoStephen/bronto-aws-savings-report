# AWS Observability Cost Audit → Bronto.io Savings Report

A Python CLI that walks your AWS Organization, totals every dollar AWS bills
for observability (CloudWatch, X-Ray, AMP/AMG, OpenSearch, VPC Flow Logs,
CloudTrail data events, plus S3 log sinks), then projects what the same
ingested volume would cost on [Bronto.io](https://bronto.io/pricing) at
$0.10/GB ingest with 12-month retention bundled. Search pricing is excluded.

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

## Notes & caveats

- S3 spend is reported separately and **not** rolled into observability totals
  by default. With `--probe`, candidate log-sink buckets are listed by name
  match heuristics so you can decide what to attribute.
- Bronto **search** pricing is excluded from the projection per spec.
- Extended retention beyond 12 months is "contact sales" on Bronto, so the
  projection footnotes it rather than guessing a number.
- OpenSearch ingestion is not metered by Cost Explorer in a useful form;
  `--probe` surfaces domain count and storage size for context.
