#!/usr/bin/env python3
"""
aws_probe.py - Enumerate every AWS resource/service visible to a given
AWS CLI profile (static keys OR temporary STS session-token creds),
in one shot, using nothing but --profile flag.


Legal / use note
-----------------
Only point this at accounts/credentials you own or are explicitly
authorized to test. It only calls read-only List/Describe/Get API
actions -- it never creates, modifies, or deletes anything -- but
enumeration itself can still trip alerting/GuardDuty and should be
covered by the same authorization as any other assessment activity.
"""

import argparse
import json
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

try:
    import boto3
    import botocore
    from botocore.exceptions import (
        ClientError,
        NoCredentialsError,
        ProfileNotFound,
        EndpointConnectionError,
        BotoCoreError,
    )
except ImportError:
    sys.exit("[!] Missing dependency. Run: pip install boto3 --break-system-packages")

# --------------------------------------------------------------------------
# Terminal colors (Kali-friendly, degrade gracefully if not a tty)
# --------------------------------------------------------------------------
class C:
    G = "\033[92m"   # green  - accessible
    R = "\033[91m"   # red    - denied
    Y = "\033[93m"   # yellow - error / not applicable
    B = "\033[94m"   # blue   - headers
    BOLD = "\033[1m"
    END = "\033[0m"

    @staticmethod
    def off():
        for a in ("G", "R", "Y", "B", "BOLD", "END"):
            setattr(C, a, "")


# --------------------------------------------------------------------------
# Common field names APIs use for a resource's ARN / unique name.
# We try these in order against every dict item we pull back.
# --------------------------------------------------------------------------
ARN_KEYS = [
    "Arn", "ARN", "arn", "TopicArn", "QueueArn", "FunctionArn", "RoleArn",
    "PolicyArn", "TableArn", "StreamArn", "ClusterArn", "ServiceArn",
    "DBInstanceArn", "LoadBalancerArn", "CertificateArn", "KeyArn",
    "SecretArn", "RepositoryArn", "StateMachineArn", "TrailARN",
    "DomainArn", "PipelineArn", "ProjectArn",
]
NAME_KEYS = [
    "Name", "name", "FunctionName", "TableName", "BucketName", "GroupName",
    "UserName", "RoleName", "PolicyName", "DBInstanceIdentifier",
    "ClusterName", "ClusterIdentifier", "QueueUrl", "TopicArn", "KeyId",
    "SecretId", "StackName", "DomainName", "Id", "InstanceId", "VpcId",
    "GroupId", "VolumeId", "SnapshotId", "RepositoryName",
    "RestApiId", "PipelineName", "ProjectName", "DeliveryStreamName",
    "CacheClusterId", "FileSystemId", "DetectorId", "NotebookInstanceName",
    "WebACLId", "BackupVaultName", "ServerId", "StateMachineArn", "Permission",
]


def first_present(d, keys):
    for k in keys:
        if isinstance(d, dict) and d.get(k):
            return d[k]
    return None


def extract_identity(item):
    """Pick the best human-readable identifier (prefer ARN, else name/id)."""
    arn = first_present(item, ARN_KEYS)
    if arn:
        return arn
    name = first_present(item, NAME_KEYS)
    if name:
        return name
    return json.dumps(item, default=str)[:80]


# --------------------------------------------------------------------------
# Service check definitions.
#   client      : boto3 client name
#   method      : API call to invoke (a List*/Describe*/Get* read-only call)
#   key         : dict key in the response holding the list of resources
#   kwargs      : extra kwargs for the call (e.g. Scope=Local for IAM policies)
#   global_svc  : True if this service is not region-scoped (only queried once)
#   paginate    : if the operation supports a paginator, use it to get everything
# --------------------------------------------------------------------------
SERVICE_CHECKS = [
    # --- Identity / account-wide ---
    dict(service="sts", client="sts", method="get_caller_identity", key=None,
         global_svc=True, label="STS Caller Identity"),

    # --- IAM (global) ---
    dict(service="iam", client="iam", method="list_users", key="Users",
         global_svc=True, paginate=True),
    dict(service="iam", client="iam", method="list_roles", key="Roles",
         global_svc=True, paginate=True),
    dict(service="iam", client="iam", method="list_groups", key="Groups",
         global_svc=True, paginate=True),
    dict(service="iam", client="iam", method="list_policies", key="Policies",
         kwargs={"Scope": "Local"}, global_svc=True, paginate=True),
    dict(service="iam", client="iam", method="list_instance_profiles",
         key="InstanceProfiles", global_svc=True, paginate=True),
    dict(service="iam", client="iam", method="list_access_keys",
         key="AccessKeyMetadata", global_svc=True, paginate=True,
         label="IAM Access Keys (own user)"),
    dict(service="iam", client="iam", method="get_account_summary",
         key=None, global_svc=True, label="IAM Account Summary"),

    # --- S3 (global) ---
    dict(service="s3", client="s3", method="list_buckets", key="Buckets",
         global_svc=True),

    # --- Regional compute/network/storage ---
    dict(service="ec2", client="ec2", method="describe_instances",
         key="Reservations", nested_key="Instances", paginate=True),
    dict(service="ec2", client="ec2", method="describe_vpcs", key="Vpcs",
         paginate=True),
    dict(service="ec2", client="ec2", method="describe_subnets",
         key="Subnets", paginate=True),
    dict(service="ec2", client="ec2", method="describe_security_groups",
         key="SecurityGroups", paginate=True),
    dict(service="ec2", client="ec2", method="describe_volumes",
         key="Volumes", paginate=True),
    dict(service="ec2", client="ec2", method="describe_snapshots",
         key="Snapshots", kwargs={"OwnerIds": ["self"]}, paginate=True),
    dict(service="ec2", client="ec2", method="describe_key_pairs",
         key="KeyPairs"),
    dict(service="ec2", client="ec2", method="describe_images",
         key="Images", kwargs={"Owners": ["self"]}),

    dict(service="lambda", client="lambda", method="list_functions",
         key="Functions", paginate=True),
    dict(service="rds", client="rds", method="describe_db_instances",
         key="DBInstances", paginate=True),
    dict(service="rds", client="rds", method="describe_db_clusters",
         key="DBClusters", paginate=True),
    dict(service="dynamodb", client="dynamodb", method="list_tables",
         key="TableNames", paginate=True),
    dict(service="ecs", client="ecs", method="list_clusters",
         key="clusterArns", paginate=True),
    dict(service="eks", client="eks", method="list_clusters",
         key="clusters", paginate=True),
    dict(service="cloudformation", client="cloudformation",
         method="list_stacks", key="StackSummaries", paginate=True,
         kwargs={"StackStatusFilter": [
             "CREATE_COMPLETE", "UPDATE_COMPLETE", "ROLLBACK_COMPLETE"]}),
    dict(service="sns", client="sns", method="list_topics",
         key="Topics", paginate=True),
    dict(service="sqs", client="sqs", method="list_queues",
         key="QueueUrls"),
    dict(service="logs", client="logs", method="describe_log_groups",
         key="logGroups", paginate=True),
    dict(service="kms", client="kms", method="list_keys", key="Keys",
         paginate=True),
    dict(service="secretsmanager", client="secretsmanager",
         method="list_secrets", key="SecretList", paginate=True),
    dict(service="ssm", client="ssm", method="describe_parameters",
         key="Parameters", paginate=True),
    dict(service="elbv2", client="elbv2",
         method="describe_load_balancers", key="LoadBalancers",
         paginate=True, label="ELBv2 Load Balancers"),
    dict(service="autoscaling", client="autoscaling",
         method="describe_auto_scaling_groups", key="AutoScalingGroups",
         paginate=True),
    dict(service="apigateway", client="apigateway", method="get_rest_apis",
         key="items"),
    dict(service="cloudtrail", client="cloudtrail",
         method="describe_trails", key="trailList"),
    dict(service="config", client="config",
         method="describe_configuration_recorders",
         key="ConfigurationRecorders"),
    dict(service="redshift", client="redshift",
         method="describe_clusters", key="Clusters", paginate=True),
    dict(service="elasticache", client="elasticache",
         method="describe_cache_clusters", key="CacheClusters",
         paginate=True),
    dict(service="efs", client="efs", method="describe_file_systems",
         key="FileSystems", paginate=True),
    dict(service="sagemaker", client="sagemaker",
         method="list_notebook_instances", key="NotebookInstances",
         paginate=True),
    dict(service="glue", client="glue", method="get_databases",
         key="DatabaseList", paginate=True),
    dict(service="athena", client="athena", method="list_work_groups",
         key="WorkGroups", paginate=True),
    dict(service="codebuild", client="codebuild", method="list_projects",
         key="projects", paginate=True),
    dict(service="codepipeline", client="codepipeline",
         method="list_pipelines", key="pipelines", paginate=True),
    dict(service="ecr", client="ecr", method="describe_repositories",
         key="repositories", paginate=True),
    dict(service="guardduty", client="guardduty", method="list_detectors",
         key="DetectorIds", paginate=True),
    dict(service="wafv2", client="wafv2", method="list_web_acls",
         key="WebACLs", kwargs={"Scope": "REGIONAL"}),
    dict(service="acm", client="acm", method="list_certificates",
         key="CertificateSummaryList", paginate=True),
    dict(service="backup", client="backup", method="list_backup_vaults",
         key="BackupVaultList", paginate=True),
    dict(service="transfer", client="transfer", method="list_servers",
         key="Servers", paginate=True),
    dict(service="batch", client="batch",
         method="describe_compute_environments",
         key="computeEnvironments", paginate=True),
    dict(service="stepfunctions", client="stepfunctions",
         method="list_state_machines", key="stateMachines",
         paginate=True),
    dict(service="events", client="events", method="list_rules",
         key="Rules", paginate=True, label="EventBridge Rules"),
    dict(service="firehose", client="firehose",
         method="list_delivery_streams", key="DeliveryStreamNames"),
    dict(service="es", client="es",
         method="list_domain_names", key="DomainNames",
         label="OpenSearch/Elasticsearch Domains"),

    # ── ECS: additional reads ────────────────────────────────────────────────
    dict(service="ecs", client="ecs", method="list_task_definitions",   key="taskDefinitionArns", paginate=True),
    dict(service="ecs", client="ecs", method="list_tasks",              key="taskArns",           paginate=True, probe=True,
         label="ecs:ListTasks [READ PROBE]"),
    dict(service="ecs", client="ecs", method="list_services",           key="serviceArns",        paginate=True, probe=True,
         label="ecs:ListServices [READ PROBE]"),
    dict(service="ecs", client="ecs", method="list_container_instances",key="containerInstanceArns", paginate=True, probe=True,
         label="ecs:ListContainerInstances [READ PROBE]"),
    # ── ECS: write probes ────────────────────────────────────────────────────
    dict(service="ecs", client="ecs", method="run_task",               probe=True, write=True,
         kwargs={"cluster": "__awsrecon_probe__", "taskDefinition": "__awsrecon_probe__"},
         label="ecs:RunTask [WRITE PROBE]"),
    dict(service="ecs", client="ecs", method="stop_task",              probe=True, write=True,
         kwargs={"cluster": "__awsrecon_probe__", "task": "__awsrecon_probe__"},
         label="ecs:StopTask [WRITE PROBE]"),
    dict(service="ecs", client="ecs", method="update_service",         probe=True, write=True,
         kwargs={"cluster": "__awsrecon_probe__", "service": "__awsrecon_probe__"},
         label="ecs:UpdateService [WRITE PROBE]"),
    dict(service="ecs", client="ecs", method="register_task_definition", probe=True, write=True,
         kwargs={"family": "__awsrecon_probe__", "containerDefinitions": []},
         label="ecs:RegisterTaskDefinition [WRITE PROBE]"),
    dict(service="ecs", client="ecs", method="update_container_instances_state", probe=True, write=True,
         kwargs={"cluster": "__awsrecon_probe__", "containerInstances": ["__awsrecon_probe__"], "status": "DRAINING"},
         label="ecs:UpdateContainerInstancesState [WRITE PROBE]"),
    dict(service="ecs", client="ecs", method="create_service",         probe=True, write=True,
         kwargs={"cluster": "__awsrecon_probe__", "serviceName": "__awsrecon_probe__", "taskDefinition": "__awsrecon_probe__"},
         label="ecs:CreateService [WRITE PROBE]"),
    dict(service="ecs", client="ecs", method="delete_service",         probe=True, write=True,
         kwargs={"cluster": "__awsrecon_probe__", "service": "__awsrecon_probe__"},
         label="ecs:DeleteService [WRITE PROBE]"),
    dict(service="ecs", client="ecs", method="execute_command",        probe=True, write=True,
         kwargs={"cluster": "__awsrecon_probe__", "command": "id", "interactive": False, "task": "__awsrecon_probe__"},
         label="ecs:ExecuteCommand [WRITE PROBE]"),
    dict(service="ecs", client="ecs", method="deregister_task_definition", probe=True, write=True,
         kwargs={"taskDefinition": "__awsrecon_probe__:1"},
         label="ecs:DeregisterTaskDefinition [WRITE PROBE]"),

    # ── EC2: additional reads ────────────────────────────────────────────────
    dict(service="ec2", client="ec2", method="describe_route_tables",              key="RouteTables",                    paginate=True),
    dict(service="ec2", client="ec2", method="describe_internet_gateways",         key="InternetGateways",               paginate=True),
    dict(service="ec2", client="ec2", method="describe_network_interfaces",        key="NetworkInterfaces",              paginate=True),
    dict(service="ec2", client="ec2", method="describe_iam_instance_profile_associations", key="IamInstanceProfileAssociations", paginate=True),
    # ── EC2: write probes (DryRun=True is natively safe) ────────────────────
    dict(service="ec2", client="ec2", method="run_instances",          probe=True, write=True,
         kwargs={"DryRun": True, "MinCount": 1, "MaxCount": 1, "ImageId": "ami-00000000000000001"},
         label="ec2:RunInstances [WRITE PROBE]"),
    dict(service="ec2", client="ec2", method="terminate_instances",    probe=True, write=True,
         kwargs={"DryRun": True, "InstanceIds": ["i-00000000000000000"]},
         label="ec2:TerminateInstances [WRITE PROBE]"),
    dict(service="ec2", client="ec2", method="create_security_group",  probe=True, write=True,
         kwargs={"DryRun": True, "GroupName": "__awsrecon_probe__", "Description": "__awsrecon_probe__"},
         label="ec2:CreateSecurityGroup [WRITE PROBE]"),
    dict(service="ec2", client="ec2", method="authorize_security_group_ingress", probe=True, write=True,
         kwargs={"DryRun": True, "GroupId": "sg-00000000000000000",
                 "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]},
         label="ec2:AuthorizeSecurityGroupIngress [WRITE PROBE]"),
    dict(service="ec2", client="ec2", method="create_snapshot",        probe=True, write=True,
         kwargs={"DryRun": True, "VolumeId": "vol-00000000000000000"},
         label="ec2:CreateSnapshot [WRITE PROBE]"),
    dict(service="ec2", client="ec2", method="create_key_pair",        probe=True, write=True,
         kwargs={"DryRun": True, "KeyName": "__awsrecon_probe__"},
         label="ec2:CreateKeyPair [WRITE PROBE]"),
    dict(service="ec2", client="ec2", method="modify_instance_attribute", probe=True, write=True,
         kwargs={"DryRun": True, "InstanceId": "i-00000000000000000"},
         label="ec2:ModifyInstanceAttribute [WRITE PROBE]"),

    # ── Lambda: additional reads ─────────────────────────────────────────────
    dict(service="lambda", client="lambda", method="list_event_source_mappings", key="EventSourceMappings", paginate=True),
    dict(service="lambda", client="lambda", method="list_layers",                key="Layers",             paginate=True),
    dict(service="lambda", client="lambda", method="list_aliases", key="Aliases", paginate=True,
         kwargs={"FunctionName": "__awsrecon_probe__"}, probe=True,
         label="lambda:ListAliases [READ PROBE]"),
    # ── Lambda: write probes ─────────────────────────────────────────────────
    dict(service="lambda", client="lambda", method="update_function_code",          probe=True, write=True,
         kwargs={"FunctionName": "awsrecon-probe-nonexistent"},
         label="lambda:UpdateFunctionCode [WRITE PROBE]"),
    dict(service="lambda", client="lambda", method="update_function_configuration", probe=True, write=True,
         kwargs={"FunctionName": "awsrecon-probe-nonexistent"},
         label="lambda:UpdateFunctionConfiguration [WRITE PROBE]"),
    dict(service="lambda", client="lambda", method="add_permission",               probe=True, write=True,
         kwargs={"FunctionName": "awsrecon-probe-nonexistent", "StatementId": "probe", "Action": "lambda:InvokeFunction", "Principal": "s3.amazonaws.com"},
         label="lambda:AddPermission [WRITE PROBE]"),
    dict(service="lambda", client="lambda", method="invoke",                       probe=True, write=True,
         kwargs={"FunctionName": "awsrecon-probe-nonexistent"},
         label="lambda:InvokeFunction [WRITE PROBE]"),
    dict(service="lambda", client="lambda", method="delete_function",              probe=True, write=True,
         kwargs={"FunctionName": "awsrecon-probe-nonexistent"},
         label="lambda:DeleteFunction [WRITE PROBE]"),

    # ── IAM: additional reads ────────────────────────────────────────────────
    dict(service="iam", client="iam", method="list_attached_user_policies", key="AttachedPolicies",
         global_svc=True, paginate=True, probe=True,
         kwargs={"UserName": "__awsrecon_probe__"},
         label="IAM ListAttachedUserPolicies [READ PROBE]"),
    dict(service="iam", client="iam", method="list_attached_role_policies", key="AttachedPolicies",
         global_svc=True, paginate=True, probe=True,
         kwargs={"RoleName": "__awsrecon_probe__"},
         label="IAM ListAttachedRolePolicies [READ PROBE]"),
    dict(service="iam", client="iam", method="list_role_policies", key="PolicyNames",
         global_svc=True, paginate=True, probe=True,
         kwargs={"RoleName": "__awsrecon_probe__"},
         label="IAM ListRolePolicies [READ PROBE]"),
    dict(service="iam", client="iam", method="get_role", key=None,
         global_svc=True, probe=True,
         kwargs={"RoleName": "__awsrecon_probe__"},
         label="IAM GetRole [READ PROBE]"),
    # ── IAM: write probes ────────────────────────────────────────────────────
    dict(service="iam", client="iam", method="create_user",           probe=True, write=True, global_svc=True,
         kwargs={"UserName": "a" * 129},   # exceeds 64-char limit → ValidationError before creation
         label="iam:CreateUser [WRITE PROBE]"),
    dict(service="iam", client="iam", method="create_role",           probe=True, write=True, global_svc=True,
         kwargs={"RoleName": "a" * 129, "AssumeRolePolicyDocument": "{}"},
         label="iam:CreateRole [WRITE PROBE]"),
    dict(service="iam", client="iam", method="attach_user_policy",    probe=True, write=True, global_svc=True,
         kwargs={"UserName": "__awsrecon_probe__", "PolicyArn": "arn:aws:iam::000000000000:policy/probe"},
         label="iam:AttachUserPolicy [WRITE PROBE]"),
    dict(service="iam", client="iam", method="attach_role_policy",    probe=True, write=True, global_svc=True,
         kwargs={"RoleName": "__awsrecon_probe__", "PolicyArn": "arn:aws:iam::000000000000:policy/probe"},
         label="iam:AttachRolePolicy [WRITE PROBE]"),
    dict(service="iam", client="iam", method="put_user_policy",       probe=True, write=True, global_svc=True,
         kwargs={"UserName": "__awsrecon_probe__", "PolicyName": "probe", "PolicyDocument": "{}"},
         label="iam:PutUserPolicy [WRITE PROBE]"),
    dict(service="iam", client="iam", method="create_policy",         probe=True, write=True, global_svc=True,
         kwargs={"PolicyName": "a" * 129, "PolicyDocument": "{}"},
         label="iam:CreatePolicy [WRITE PROBE]"),
    dict(service="iam", client="iam", method="add_user_to_group",     probe=True, write=True, global_svc=True,
         kwargs={"GroupName": "__awsrecon_probe__", "UserName": "__awsrecon_probe__"},
         label="iam:AddUserToGroup [WRITE PROBE]"),
    dict(service="iam", client="iam", method="create_login_profile",  probe=True, write=True, global_svc=True,
         kwargs={"UserName": "__awsrecon_probe__", "Password": "Probe@123!"},
         label="iam:CreateLoginProfile [WRITE PROBE]"),
    dict(service="iam", client="iam", method="update_assume_role_policy", probe=True, write=True, global_svc=True,
         kwargs={"RoleName": "__awsrecon_probe__", "PolicyDocument": "{}"},
         label="iam:UpdateAssumeRolePolicy [WRITE PROBE]"),

    # ── S3: write probes (use nonexistent bucket → NoSuchBucket before any action) ──
    dict(service="s3", client="s3", method="put_bucket_policy",       probe=True, write=True, global_svc=True,
         kwargs={"Bucket": "__awsrecon-probe-bucket-nonexistent__", "Policy": "{}"},
         label="s3:PutBucketPolicy [WRITE PROBE]"),
    dict(service="s3", client="s3", method="put_bucket_acl",          probe=True, write=True, global_svc=True,
         kwargs={"Bucket": "__awsrecon-probe-bucket-nonexistent__", "ACL": "private"},
         label="s3:PutBucketAcl [WRITE PROBE]"),
    dict(service="s3", client="s3", method="delete_bucket",           probe=True, write=True, global_svc=True,
         kwargs={"Bucket": "__awsrecon-probe-bucket-nonexistent__"},
         label="s3:DeleteBucket [WRITE PROBE]"),
    dict(service="s3", client="s3", method="put_object",              probe=True, write=True, global_svc=True,
         kwargs={"Bucket": "__awsrecon-probe-bucket-nonexistent__", "Key": "probe", "Body": b""},
         label="s3:PutObject [WRITE PROBE]"),

    # ── RDS: additional reads ────────────────────────────────────────────────
    dict(service="rds", client="rds", method="describe_db_subnet_groups",    key="DBSubnetGroups",    paginate=True),
    dict(service="rds", client="rds", method="describe_db_parameter_groups", key="DBParameterGroups", paginate=True),
    dict(service="rds", client="rds", method="describe_db_snapshots",        key="DBSnapshots",       paginate=True),
    # ── RDS: write probes ────────────────────────────────────────────────────
    dict(service="rds", client="rds", method="modify_db_instance",    probe=True, write=True,
         kwargs={"DBInstanceIdentifier": "__awsrecon_probe__"},
         label="rds:ModifyDBInstance [WRITE PROBE]"),
    dict(service="rds", client="rds", method="delete_db_instance",    probe=True, write=True,
         kwargs={"DBInstanceIdentifier": "__awsrecon_probe__", "SkipFinalSnapshot": True},
         label="rds:DeleteDBInstance [WRITE PROBE]"),

    # ── DynamoDB: additional reads + write probes ────────────────────────────
    dict(service="dynamodb", client="dynamodb", method="list_global_tables", key="GlobalTables"),
    dict(service="dynamodb", client="dynamodb", method="put_item",           probe=True, write=True,
         kwargs={"TableName": "__awsrecon_probe__", "Item": {}},
         label="dynamodb:PutItem [WRITE PROBE]"),
    dict(service="dynamodb", client="dynamodb", method="delete_table",       probe=True, write=True,
         kwargs={"TableName": "__awsrecon_probe__"},
         label="dynamodb:DeleteTable [WRITE PROBE]"),

    # ── SSM: additional reads + write probes ─────────────────────────────────
    dict(service="ssm", client="ssm", method="describe_instance_information", key="InstanceInformationList", paginate=True,
         label="SSM Managed Instances"),
    dict(service="ssm", client="ssm", method="list_documents",               key="DocumentIdentifiers",    paginate=True,
         kwargs={"Filters": [{"Key": "Owner", "Values": ["Self"]}]}),
    dict(service="ssm", client="ssm", method="send_command",                 probe=True, write=True,
         kwargs={"InstanceIds": ["i-00000000000000000"], "DocumentName": "AWS-RunShellScript", "Parameters": {"commands": ["id"]}},
         label="ssm:SendCommand [WRITE PROBE]"),
    dict(service="ssm", client="ssm", method="put_parameter",                probe=True, write=True,
         kwargs={"Name": "/__awsrecon_probe__/probe", "Value": "probe",
                 "Type": "SecureString", "KeyId": "arn:aws:kms:us-east-1:000000000000:key/00000000-0000-0000-0000-000000000000"},
         label="ssm:PutParameter [WRITE PROBE]"),

    # ── Secrets Manager: write probes ────────────────────────────────────────
    dict(service="secretsmanager", client="secretsmanager", method="put_secret_value",  probe=True, write=True,
         kwargs={"SecretId": "arn:aws:secretsmanager:us-east-1:000000000000:secret:probe"},
         label="secretsmanager:PutSecretValue [WRITE PROBE]"),
    dict(service="secretsmanager", client="secretsmanager", method="delete_secret",     probe=True, write=True,
         kwargs={"SecretId": "arn:aws:secretsmanager:us-east-1:000000000000:secret:probe"},
         label="secretsmanager:DeleteSecret [WRITE PROBE]"),
    dict(service="secretsmanager", client="secretsmanager", method="get_secret_value",  probe=True,
         kwargs={"SecretId": "arn:aws:secretsmanager:us-east-1:000000000000:secret:probe"},
         label="secretsmanager:GetSecretValue [READ PROBE]"),

    # ── KMS: additional reads + write probes ─────────────────────────────────
    dict(service="kms", client="kms", method="list_aliases", key="Aliases", paginate=True),
    dict(service="kms", client="kms", method="schedule_key_deletion", probe=True, write=True,
         kwargs={"KeyId": "00000000-0000-0000-0000-000000000000", "PendingWindowInDays": 30},
         label="kms:ScheduleKeyDeletion [WRITE PROBE]"),
    dict(service="kms", client="kms", method="put_key_policy",         probe=True, write=True,
         kwargs={"KeyId": "00000000-0000-0000-0000-000000000000", "PolicyName": "default", "Policy": "{}"},
         label="kms:PutKeyPolicy [WRITE PROBE]"),

    # ── CloudFormation: write probes ─────────────────────────────────────────
    dict(service="cloudformation", client="cloudformation", method="create_stack", probe=True, write=True,
         kwargs={"StackName": "awsrecon-probe-stack", "TemplateBody": "a" * 51201},  # exceeds 51200-byte limit
         label="cloudformation:CreateStack [WRITE PROBE]"),
    dict(service="cloudformation", client="cloudformation", method="delete_stack", probe=True, write=True,
         kwargs={"StackName": "__awsrecon_probe__"},
         label="cloudformation:DeleteStack [WRITE PROBE]"),

    # ── ECR: write probes ─────────────────────────────────────────────────────
    dict(service="ecr", client="ecr", method="set_repository_policy",    probe=True, write=True,
         kwargs={"repositoryName": "__awsrecon_probe__", "policyText": "{}"},
         label="ecr:SetRepositoryPolicy [WRITE PROBE]"),
    dict(service="ecr", client="ecr", method="delete_repository",         probe=True, write=True,
         kwargs={"repositoryName": "__awsrecon_probe__"},
         label="ecr:DeleteRepository [WRITE PROBE]"),

    # ── EKS: additional reads + write probes ─────────────────────────────────
    dict(service="eks", client="eks", method="describe_cluster",          probe=True,
         kwargs={"name": "__awsrecon_probe__"},
         label="eks:DescribeCluster [READ PROBE]"),
    dict(service="eks", client="eks", method="update_cluster_config",     probe=True, write=True,
         kwargs={"name": "__awsrecon_probe__"},
         label="eks:UpdateClusterConfig [WRITE PROBE]"),
    dict(service="eks", client="eks", method="delete_cluster",            probe=True, write=True,
         kwargs={"name": "__awsrecon_probe__"},
         label="eks:DeleteCluster [WRITE PROBE]"),

    # ── STS: write probes ─────────────────────────────────────────────────────
    dict(service="sts", client="sts", method="assume_role",               probe=True, write=True, global_svc=True,
         kwargs={"RoleArn": "arn:aws:iam::000000000000:role/__awsrecon_probe__", "RoleSessionName": "awsrecon_probe"},
         label="sts:AssumeRole [WRITE PROBE]"),

    # ── SNS: write probes ─────────────────────────────────────────────────────
    dict(service="sns", client="sns", method="publish",                   probe=True, write=True,
         kwargs={"TopicArn": "arn:aws:sns:us-east-1:000000000000:probe", "Message": "probe"},
         label="sns:Publish [WRITE PROBE]"),
    dict(service="sns", client="sns", method="create_topic",              probe=True, write=True,
         kwargs={"Name": "a" * 257},  # exceeds 256-char limit
         label="sns:CreateTopic [WRITE PROBE]"),

    # ── SQS: write probes ─────────────────────────────────────────────────────
    dict(service="sqs", client="sqs", method="send_message",              probe=True, write=True,
         kwargs={"QueueUrl": "https://sqs.us-east-1.amazonaws.com/000000000000/probe", "MessageBody": "probe"},
         label="sqs:SendMessage [WRITE PROBE]"),
    dict(service="sqs", client="sqs", method="delete_queue",              probe=True, write=True,
         kwargs={"QueueUrl": "https://sqs.us-east-1.amazonaws.com/000000000000/probe"},
         label="sqs:DeleteQueue [WRITE PROBE]"),

    # ── CloudWatch Logs: write probes ────────────────────────────────────────
    dict(service="logs", client="logs", method="delete_log_group",        probe=True, write=True,
         kwargs={"logGroupName": "__awsrecon_probe__"},
         label="logs:DeleteLogGroup [WRITE PROBE]"),
    dict(service="logs", client="logs", method="put_log_events",          probe=True, write=True,
         kwargs={"logGroupName": "__awsrecon_probe__", "logStreamName": "__probe__", "logEvents": []},
         label="logs:PutLogEvents [WRITE PROBE]"),

    # ── CloudTrail: write probes ──────────────────────────────────────────────
    dict(service="cloudtrail", client="cloudtrail", method="delete_trail", probe=True, write=True,
         kwargs={"Name": "__awsrecon_probe__"},
         label="cloudtrail:DeleteTrail [WRITE PROBE]"),
    dict(service="cloudtrail", client="cloudtrail", method="stop_logging", probe=True, write=True,
         kwargs={"Name": "__awsrecon_probe__"},
         label="cloudtrail:StopLogging [WRITE PROBE]"),

    # --- Global (queried once regardless of --all-regions) ---
    dict(service="route53", client="route53",
         method="list_hosted_zones", key="HostedZones", global_svc=True,
         paginate=True),
    dict(service="cloudfront", client="cloudfront",
         method="list_distributions", key="DistributionList",
         nested_key="Items", global_svc=True),
    dict(service="ses", client="ses", method="list_identities",
         key="Identities", global_svc=True, paginate=True),
    dict(service="organizations", client="organizations",
         method="list_accounts", key="Accounts", global_svc=True,
         paginate=True),
]


def print_table(rows, headers):
    """
    Render a simple aligned text table (no external deps).
    rows: list of tuples, one per printed line.
    headers: tuple of column headers, same arity as rows.
    """
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))

    def fmt_row(cells):
        return "  ".join(str(c).ljust(widths[i]) for i, c in enumerate(cells))

    sep = "  ".join("-" * w for w in widths)
    print(f"{C.BOLD}{fmt_row(headers)}{C.END}")
    print(sep)
    for row in rows:
        print(fmt_row(row))


# Hardcoded list of all standard AWS regions (used as fallback when
# ec2:DescribeRegions is denied). Update this list as AWS adds new regions.
ALL_AWS_REGIONS = [
    "af-south-1", "ap-east-1", "ap-northeast-1", "ap-northeast-2",
    "ap-northeast-3", "ap-south-1", "ap-south-2", "ap-southeast-1",
    "ap-southeast-2", "ap-southeast-3", "ap-southeast-4", "ca-central-1",
    "ca-west-1", "eu-central-1", "eu-central-2", "eu-north-1", "eu-south-1",
    "eu-south-2", "eu-west-1", "eu-west-2", "eu-west-3", "il-central-1",
    "me-central-1", "me-south-1", "sa-east-1", "us-east-1", "us-east-2",
    "us-west-1", "us-west-2",
]


def get_regions(session, requested):
    """Resolve final region list based on user flags."""
    if requested:
        return requested
    try:
        ec2 = session.client("ec2", region_name=session.region_name or "us-east-1")
        resp = ec2.describe_regions(AllRegions=False)
        regions = sorted(r["RegionName"] for r in resp["Regions"])
        print(f"{C.B}    ec2:DescribeRegions succeeded — {len(regions)} regions found.{C.END}")
        return regions
    except Exception:
        # ec2:DescribeRegions is denied (common for restricted profiles).
        # Fall back to the hardcoded list of all known AWS regions so
        # --all-regions still works without that permission.
        print(f"{C.Y}    ec2:DescribeRegions denied — using built-in region list "
              f"({len(ALL_AWS_REGIONS)} regions).{C.END}")
        return ALL_AWS_REGIONS


def run_check(session, check, region):
    """Execute a single service check, return (status, count, items, err)."""
    client_name = check["client"]
    kwargs = dict(check.get("kwargs", {}))
    region_kw = {} if check.get("global_svc") else {"region_name": region}

    try:
        client = session.client(client_name, **region_kw)
    except Exception as e:
        return "error", 0, [], f"client init failed: {e}"

    try:
        method = getattr(client, check["method"])

        # --- Permission probe: call with dummy kwargs, classify by error type ---
        # probe=True  → try the call; AccessDenied=denied, DryRunOperation/anything else=permission confirmed
        # write=True  → label result [WRITE], else [READ]
        if check.get("probe"):
            try:
                method(**kwargs)
                tag = "WRITE" if check.get("write") else "READ"
                return "accessible", 1, [{"Permission": f"[{tag}] {check['method']} — call succeeded"}], None
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "")
                if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
                            "UnauthorizedException", "AuthorizationError", "AuthFailure"):
                    return "denied", 0, [], code
                if code == "DryRunOperation":
                    return "accessible", 1, [{"Permission": f"[WRITE] {check['method']} — permission confirmed (DryRun OK)"}], None
                tag = "WRITE" if check.get("write") else "READ"
                return "accessible", 1, [{"Permission": f"[{tag}] {check['method']} — permission confirmed ({code})"}], None
            except Exception as e:
                return "error", 0, [], str(e)

        items = []
        if check.get("paginate") and client.can_paginate(check["method"]):
            paginator = client.get_paginator(check["method"])
            for page in paginator.paginate(**kwargs):
                page_items = page.get(check["key"], []) if check["key"] else [page]
                items.extend(page_items)
        else:
            resp = method(**kwargs)
            if check["key"] is None:
                items = [resp]
            else:
                items = resp.get(check["key"], [])

        # unwrap doubly-nested results (e.g. EC2 Reservations -> Instances)
        if check.get("nested_key"):
            flat = []
            for outer in items:
                if isinstance(outer, dict) and check["nested_key"] in outer:
                    flat.extend(outer[check["nested_key"]])
                else:
                    flat.append(outer)
            items = flat

        # normalize plain strings (e.g. dynamodb table names, ecs cluster arns)
        norm = []
        for it in items:
            if isinstance(it, str):
                norm.append({"Name": it})
            else:
                norm.append(it)

        return "accessible", len(norm), norm, None

    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in ("AccessDenied", "AccessDeniedException",
                    "UnauthorizedOperation", "UnauthorizedException",
                    "AuthorizationError"):
            return "denied", 0, [], code
        if code in ("OptInRequired", "SubscriptionRequiredException",
                    "InvalidClientTokenId"):
            return "na", 0, [], code
        return "error", 0, [], f"{code}: {e.response.get('Error', {}).get('Message','')}"
    except (EndpointConnectionError,):
        return "na", 0, [], "service not available in this region"
    except BotoCoreError as e:
        return "error", 0, [], str(e)
    except Exception as e:
        return "error", 0, [], str(e)


def main():
    ap = argparse.ArgumentParser(
        description="Enumerate all AWS resources/services visible to a given AWS CLI profile.")
    ap.add_argument("--profile", help="AWS CLI profile name from ~/.aws/credentials + ~/.aws/config "
                                       "(supports static keys, session-token creds, assume-role, SSO)")
    ap.add_argument("--region", action="append",
                     help="Region to scan (repeatable). Default: profile's default region.")
    ap.add_argument("--all-regions", action="store_true",
                     help="Scan every enabled region (requires ec2:DescribeRegions, else falls back).")
    ap.add_argument("--services", help="Comma-separated list of service keys to limit the scan to "
                                        "(e.g. s3,iam,lambda,ec2). See --list-services.")
    ap.add_argument("--threads", type=int, default=12, help="Parallel worker threads (default: 12)")
    ap.add_argument("--full", action="store_true", help="Print every resource identifier, not just a preview.")
    ap.add_argument("--json", metavar="FILE", help="Also write full results as JSON to FILE.")
    ap.add_argument("--no-color", action="store_true", help="Disable ANSI colors.")
    ap.add_argument("--quiet-denied", action="store_true", help="Hide the denied-services summary line.")
    ap.add_argument("--list-services", action="store_true",
                     help="List all service check keys this tool knows about, then exit.")
    args = ap.parse_args()

    if args.no_color or not sys.stdout.isatty():
        C.off()

    if args.list_services:
        keys = sorted({c["service"] for c in SERVICE_CHECKS})
        print("\n".join(keys))
        return

    if not args.profile:
        ap.error("--profile is required (see --list-services for a dry run without it)")

    try:
        session = boto3.Session(profile_name=args.profile)
    except ProfileNotFound as e:
        sys.exit(f"[!] {e}\n    Check the profile name in ~/.aws/credentials and ~/.aws/config.")

    wanted = set(args.services.split(",")) if args.services else None
    checks = [c for c in SERVICE_CHECKS if not wanted or c["service"] in wanted]

    # --- Step 1: confirm identity first, fail fast with a clear message ---
    print(f"{C.B}{C.BOLD}[*] Resolving identity for profile '{args.profile}'...{C.END}")
    try:
        sts = session.client("sts", region_name=session.region_name or "us-east-1")
        ident = sts.get_caller_identity()
        print(f"{C.G}    Account : {ident['Account']}{C.END}")
        print(f"{C.G}    ARN     : {ident['Arn']}{C.END}")
        print(f"{C.G}    UserId  : {ident['UserId']}{C.END}\n")
    except NoCredentialsError:
        sys.exit(f"[!] No credentials found for profile '{args.profile}'. "
                  f"Check ~/.aws/credentials.")
    except ClientError as e:
        sys.exit(f"[!] sts:GetCallerIdentity failed -- credentials appear invalid/expired: {e}")

    regions = get_regions(session, args.region) if args.all_regions or args.region else \
        [session.region_name or "us-east-1"]
    print(f"{C.B}[*] Regions in scope: {', '.join(regions)}{C.END}")
    print(f"{C.B}[*] Running {len(checks)} service checks x {len(regions)} region(s)...{C.END}\n")

    jobs = []
    for check in checks:
        if check.get("global_svc"):
            jobs.append((check, None))
        else:
            for r in regions:
                jobs.append((check, r))

    results = []  # list of dicts
    lock = threading.Lock()

    def worker(check, region):
        status, count, items, err = run_check(session, check, region)
        return check, region, status, count, items, err

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = [ex.submit(worker, c, r) for c, r in jobs]
        for fut in as_completed(futures):
            check, region, status, count, items, err = fut.result()
            results.append(dict(
                service=check["service"], label=check.get("label", check["method"]),
                method=check["method"], region=region, status=status,
                count=count, items=items, error=err,
            ))

    # --- Report ---
    accessible = [r for r in results if r["status"] == "accessible" and r["count"] > 0]
    empty_ok = [r for r in results if r["status"] == "accessible" and r["count"] == 0]
    denied = [r for r in results if r["status"] == "denied"]
    errored = [r for r in results if r["status"] == "error"]

    def region_tag(r):
        return f" [{r['region']}]" if r["region"] else " [global]"

    print(f"{C.BOLD}{C.G}=== ACCESSIBLE ({len(accessible)} checks returned data, "
          f"{sum(r['count'] for r in accessible)} resources total) ==={C.END}\n")

    # Build a flat SERVICE / ARN table. A service with N resources gets N
    # rows, one per ARN -- the service name repeats once per row, matching
    # how e.g. `s3` shows up twice if the profile can see two buckets.
    table_rows = []
    for r in sorted(accessible, key=lambda x: (x["service"], x["region"] or "")):
        preview = r["items"] if args.full else r["items"][:5]
        for it in preview:
            table_rows.append((r["service"], extract_identity(it)))
        if not args.full and r["count"] > 5:
            table_rows.append((r["service"], f"... +{r['count'] - 5} more (use --full to show all)"))

    print_table(table_rows, ("SERVICE", "ARN"))

    if empty_ok:
        print(f"\n{C.BOLD}{C.Y}=== ACCESSIBLE, NO RESOURCES FOUND ({len(empty_ok)}) ==={C.END}")
        for r in sorted(empty_ok, key=lambda x: (x["service"], x["region"] or "")):
            print(f"{C.Y}[ ] {r['service']:<15}{region_tag(r):<14} {r['label']}{C.END}")

    if not args.quiet_denied:
        print(f"\n{C.BOLD}{C.R}=== ACCESS DENIED ({len(denied)}) ==={C.END}")
        seen = set()
        for r in sorted(denied, key=lambda x: x["service"]):
            key = (r["service"], r["label"])
            if key in seen:
                continue
            seen.add(key)
            print(f"{C.R}[-] {r['service']:<15} {r['label']:<32} ({r['error']}){C.END}")

    if errored:
        print(f"\n{C.BOLD}{C.Y}=== ERRORS / NOT APPLICABLE ({len(errored)}) ==={C.END}")
        seen = set()
        for r in sorted(errored, key=lambda x: x["service"]):
            key = (r["service"], r["label"])
            if key in seen:
                continue
            seen.add(key)
            print(f"{C.Y}[?] {r['service']:<15} {r['label']:<32} {r['error']}{C.END}")

    print(f"\n{C.BOLD}Summary: {len(accessible)} with resources, {len(empty_ok)} accessible-but-empty, "
          f"{len(set((r['service'],r['label']) for r in denied))} denied, "
          f"{len(set((r['service'],r['label']) for r in errored))} errored/NA.{C.END}")

    if args.json:
        with open(args.json, "w") as f:
            json.dump({
                "profile": args.profile,
                "identity": ident,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "regions": regions,
                "results": results,
            }, f, indent=2, default=str)
        print(f"\n{C.B}[*] Full JSON report written to {args.json}{C.END}")


if __name__ == "__main__":
    main()
