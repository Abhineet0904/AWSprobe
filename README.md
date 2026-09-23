# AWSprobe

One command to find out what an AWS CLI profile can actually see.

```
aws lambda list-functions --profile ABC
aws s3 ls --profile ABC
aws ec2 describe-instances --profile ABC
... one command per service, forever ...
```

vs.

```
python3 aws_probe.py --profile ABC
```

## Why

Used other tools designed for this purpose but :
- Either they are powerful but module-based - you run each service check one at a time from its interactive shell.
- Or they enumerate AWS permissions by taking credential values directly (`--access_key`, `--secret_key`, and `--session_token`), and do not accept an AWS CLI profile directly.

`aws_probe.py` instead accepts an AWS CLI profile and lets the AWS SDK resolve credentials, supporting configurations such as temporary credentials, role-based profiles, credential_process, and SSO without manually extracting credential values.

So the only flag you ever need is `--profile`, same as the AWS CLI itself.

## Install

```bash
git clone https://github.com/Abhineet0904/AWSprobe.git
cd AWSprobe
pip install -r requirements.txt --break-system-packages   # Kali/Debian needs this flag
```

## Usage

```bash
# Basic scan, current default region for the profile
python3 aws_probe.py --profile ABC

# Scan every enabled region (needs ec2:DescribeRegions, else falls back)
python3 aws_probe.py --profile ABC --all-regions

# Specific regions only
python3 aws_probe.py --profile ABC --region us-east-1 --region eu-west-1

# Limit to specific services
python3 aws_probe.py --profile ABC --services s3,iam,lambda,ec2

# Show every resource found (default truncates to 5 per check)
python3 aws_probe.py --profile ABC --full

# Save full machine-readable output too
python3 aws_probe.py --profile ABC --json report.json

# List all supported services
python3 aws_probe.py --list-services
```

## Example

![Screenshot 1](screenshots/Screenshot_2026-09-22_212559.png)

![Screenshot 2](screenshots/Screenshot_2026-09-22_212639.png)

![Screenshot 3](screenshots/Screenshot_2026-09-22_212748.png)

![Screenshot 4](screenshots/Screenshot_2026-09-22_212828.png)

![Screenshot 5](screenshots/Screenshot_2026-09-22_212845.png)

## What it does

1. Calls `sts:GetCallerIdentity` first, so you immediately know which account/identity/ARN the profile resolves to (and fails fast with a clear error if the creds are missing/expired).
2. Currently runs **141 checks** across **44 services** (IAM, S3, EC2, Lambda, RDS, DynamoDB, ECS, EKS, CloudFormation, SNS, SQS, CloudWatch Logs, KMS, Secrets Manager, SSM, ELBv2, Auto Scaling, API Gateway, CloudTrail, Config, Redshift, ElastiCache, EFS, SageMaker, Glue, Athena, CodeBuild, CodePipeline, ECR, GuardDuty, WAFv2, ACM, Backup, Transfer, Batch, Step Functions, EventBridge, Firehose, OpenSearch, Route 53, CloudFront, SES, Organizations, and more) using a thread pool.
3. For each service, runs two types of checks:
   - **Read checks** — `List*` / `Describe*` / `Get*` calls that return actual resources with their ARNs.
   - **Write/permission probes** — attempts calls like `run_task`, `update_service`, `put_object`, `attach_user_policy`, etc. with dummy/nonexistent resource IDs to confirm whether the permission exists, *without actually modifying anything*. Results are labelled `[WRITE]` or `[READ]` in the output.
4. Buckets every check into **Accessible (with resources)**, **Accessible (empty)**, **Access Denied**, and **Error/Not Applicable**, printing the ARN (or best available identifier) of every resource it finds.
5. Optionally dumps the whole thing as JSON for feeding into other tooling.

## What it does *not* do

- **Write probes are safe by design** — every mutating API call uses either EC2's native `DryRun=True` flag, or targets a clearly fake/nonexistent resource ID (e.g. a fake cluster name, a fake account `000000000000`, an invalid ARN), so the call fails at the resource-lookup stage before any real action is taken. Nothing is ever created, modified, or deleted.
- It doesn't brute-force or guess credentials — it only tests what the profile you already configured can do.
- It isn't exhaustive for every AWS service that exists (AWS has 300+). It covers the ones most relevant during an authorized assessment or access audit. PRs adding more `SERVICE_CHECKS` entries are welcome — the format is documented in-line in `aws_probe.py`.

## ⚠️ Use responsibly

Only run this against AWS accounts/credentials you own or are explicitly authorized to test. AWS API calls can still trigger CloudTrail, GuardDuty, or other security monitoring alerts, including the permission probes performed by this tool.
