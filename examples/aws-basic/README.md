# AWS example: S3 bucket via forge-iaas

A minimal AWS-provider workspace. It proves the whole AWS path:
`tofu init` downloads the `hashicorp/aws` provider, the plan talks
to AWS with the workspace's credentials, and the apply creates
exactly one S3 bucket.

## Credentials: env variables, not terraform variables

This is the part that used to be broken in forge-iaas, and the
reason this example exists. The AWS provider authenticates from
**process environment**, so credentials must be stored on the
workspace with category `"env"`:

```
fiaas variable set <workspace> AWS_ACCESS_KEY_ID=... --sensitive --category env
fiaas variable set <workspace> AWS_SECRET_ACCESS_KEY=... --sensitive --category env
fiaas variable set <workspace> AWS_SESSION_TOKEN=... --sensitive --category env   # only for temporary credentials
```

(Use the API/MCP `variable_set` with `"category": "env"` if you
prefer those surfaces; the CLI flag name follows the API field.)

Region is the opposite: it is an HCL input, so set it as a
terraform variable:

```
fiaas variable set <workspace> aws_region=ap-southeast-1
fiaas variable set <workspace> bucket_name=my-unique-bucket-name
```

If you set `AWS_REGION` as an env variable instead, the provider
reads that too — just don't do both with different values.

## What forge-iaas does with them

- Env variables reach the `tofu` subprocess verbatim.
- Terraform variables reach it as `TF_VAR_<key>`.
- Sensitive values are encrypted at rest, masked in API/MCP/logs,
  and redacted from tofu error output.
- Ambient AWS credentials from the *server process* environment
  are stripped unless the workspace sets them explicitly, so a
  workspace can never silently run on the server's credentials.
  A workspace with no AWS credentials fails loudly at plan time
  with the provider's own "no valid credential sources" error —
  it never fabricates a plan.

## Cost note

The forge-iaas cost estimate for `aws_s3_bucket` is a static
$2/month placeholder (see `internal/policy`), labeled as an
estimate, not a cloud bill. Real AWS pricing for S3 depends on
storage class, requests, and transfer — check the AWS pricing page
before treating the estimate as a budget.

## Practical notes

- `tofu init` downloads the AWS provider binary — about 676 MB
  for v5.100.0 in our test. Don't run it in a small tmpfs
  (`/tmp` on this VM is 512 MB and init failed there with "no
  space left on device"); run it on real disk.
- Verified 2026-10-25 with OpenTofu 1.13.2 (checksum-verified
  binary) and fake credentials, no real AWS account:
  - `tofu init` succeeds and installs `hashicorp/aws` v5.100.0.
  - A forge-iaas plan with AWS env variables set reaches
    `awaiting_approval` with `add=1` for `aws_s3_bucket.example`
    (when the provider block sets the `skip_*` validation flags
    — see below).
  - The same plan with NO AWS env variables fails loudly with
    the provider's own "No valid credential sources found" —
    which is also the proof that env variables are what make
    the first plan work, and that forge-iaas does not silently
    fall back to ambient credentials.
  - Without the `skip_*` flags, a plan with invalid credentials
    hangs in the provider's `ConfigureProvider` (STS account
    lookup) for 170+ seconds in our proxied environment before
    timing out — that is provider retry behaviour with bad
    credentials, not a forge-iaas env-passing failure (the
    with-credentials plan above proves the env path). With
    real credentials, STS succeeds and this does not apply.
    For a first smoke test without a real account, add to the
    provider block (diagnostic only, not for production):
    `skip_credentials_validation`, `skip_metadata_api_check`,
    `skip_region_validation`, `skip_requesting_account_id`.
- The provider is the only component that talks to AWS.
  forge-iaas itself never calls an AWS API.

## What is NOT supported yet

- `AWS_PROFILE` / shared credentials files: forge-iaas passes the
  variable through if you set it, but it does not provision or
  mount a credentials file on the runner — use static or session
  env credentials, or OIDC (deferred, see docs/TODO.md).
- Other providers (Azure, GCP, Kubernetes, …) work the same way
  in principle — any provider that reads env credentials — but
  only AWS has an example and an env-passthrough test so far.
