# Cloudsplaining baseline (v0.9.1)

- `bN_auth_details.json` (N = 1..6): IAM state of benchmark N on LocalStack
  (`benchmarks/benchN/setup_aws.sh`), exported with
  `aws iam get-account-authorization-details --filter Role User Group LocalManagedPolicy`
  pointed at the LocalStack endpoint. The filter drops LocalStack's seeded AWS-managed policy
  catalog, which crashes Cloudsplaining's parser with a `KeyError`.
- `bN_output/`: Cloudsplaining's results (`iam-results-*.json`, `iam-findings-*.json`,
  `iam-report-*.html`) from `cloudsplaining scan` on that input, with the default exclusions,
  which exclude `AdministratorAccess` (visible in each results file).

The exact original command lines were not archived; the description above is what the stored
file names and the notes in `evaluation_complete_final.md` Section 3.2 support.
