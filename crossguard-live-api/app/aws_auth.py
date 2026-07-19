"""
Credential handling for the AWS side of a scan.

Hard rule for this app: we never accept, log, or persist raw AWS
access keys. The only supported path is STS AssumeRole against a
role ARN the user configures in their own account, scoped to:

  - Read-only IAM (List*/Get*) for ingestion
  - The specific write actions your remediation engine issues
    (e.g. iam:DeleteRolePolicy / iam:UpdateAssumeRolePolicy) if
    "apply fix" is going to be used against this target

The trust policy on that role should restrict AssumeRole to this
app's own AWS account/role, and ideally require an ExternalId, to
prevent the "confused deputy" problem where a third party tricks the
app into assuming a role it wasn't meant to.

Credentials returned by assume_role() live in memory for the
duration of a single scan/apply and are never written to disk or a
database. If a scan_id needs to be re-used later (e.g. to apply a
remediation minutes after the scan ran), re-assume the role rather
than caching the temporary keys.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger("crossguard_live.aws_auth")


class AssumeRoleError(Exception):
    pass


@dataclass
class TemporaryAWSCredentials:
    access_key_id: str
    secret_access_key: str
    session_token: str
    region: str
    endpoint_url_override: str | None = None

    def boto3_client(self, service_name: str):
        return boto3.client(
            service_name,
            aws_access_key_id=self.access_key_id,
            aws_secret_access_key=self.secret_access_key,
            aws_session_token=self.session_token,
            region_name=self.region,
            endpoint_url=self.endpoint_url_override,
        )


def assume_role(
    role_arn: str,
    region: str,
    external_id: str | None = None,
    endpoint_url_override: str | None = None,
    session_name: str = "crossguard-live-scan",
) -> TemporaryAWSCredentials:
    """
    Assumes role_arn and returns short-lived credentials.

    endpoint_url_override is only meant for pointing STS itself at
    LocalStack during local/demo runs -- leave it unset for real AWS.
    """
    sts_kwargs = {}
    if endpoint_url_override:
        sts_kwargs["endpoint_url"] = endpoint_url_override

    sts = boto3.client("sts", region_name=region, **sts_kwargs)

    assume_kwargs = {"RoleArn": role_arn, "RoleSessionName": session_name}
    if external_id:
        assume_kwargs["ExternalId"] = external_id

    try:
        resp = sts.assume_role(**assume_kwargs)
    except ClientError as exc:
        logger.warning("AssumeRole failed for %s: %s", role_arn, exc)
        raise AssumeRoleError(
            f"Could not assume {role_arn}. Check the trust policy allows this app's "
            f"identity, and that the external ID (if configured) matches."
        ) from exc

    creds = resp["Credentials"]
    return TemporaryAWSCredentials(
        access_key_id=creds["AccessKeyId"],
        secret_access_key=creds["SecretAccessKey"],
        session_token=creds["SessionToken"],
        region=region,
        endpoint_url_override=endpoint_url_override,
    )
