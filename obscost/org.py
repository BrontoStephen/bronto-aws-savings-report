"""AWS Organization discovery + cross-account assume-role."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Iterable, Optional

import boto3
from botocore.exceptions import ClientError

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Account:
    id: str
    name: str
    email: str
    status: str


class OrgClient:
    """List accounts from the management/payer account and hand out
    boto3 sessions for each member account."""

    def __init__(self, profile: Optional[str], role_name: str):
        self._mgmt_session = boto3.Session(profile_name=profile)
        self._role_name = role_name
        self._sts = self._mgmt_session.client("sts")
        self._mgmt_account_id: Optional[str] = None

    @property
    def mgmt_account_id(self) -> str:
        if self._mgmt_account_id is None:
            self._mgmt_account_id = self._sts.get_caller_identity()["Account"]
        return self._mgmt_account_id

    def list_accounts(self, filter_ids: Optional[Iterable[str]] = None) -> list[Account]:
        org = self._mgmt_session.client("organizations")
        accounts: list[Account] = []
        try:
            paginator = org.get_paginator("list_accounts")
            for page in paginator.paginate():
                for a in page["Accounts"]:
                    if a.get("Status") != "ACTIVE":
                        continue
                    accounts.append(
                        Account(
                            id=a["Id"],
                            name=a.get("Name", ""),
                            email=a.get("Email", ""),
                            status=a["Status"],
                        )
                    )
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            if code in ("AWSOrganizationsNotInUseException", "AccessDeniedException"):
                log.warning(
                    "Organizations API unavailable (%s). Falling back to current account only.",
                    code,
                )
                ident = self._sts.get_caller_identity()
                accounts.append(
                    Account(id=ident["Account"], name="(current)", email="", status="ACTIVE")
                )
            else:
                raise

        if filter_ids:
            wanted = set(filter_ids)
            accounts = [a for a in accounts if a.id in wanted]
        return accounts

    def session_for(self, account: Account) -> Optional[boto3.Session]:
        """Return a boto3 Session in the target account, or None if assume-role fails.

        If the target account *is* the management account, return the management session
        directly — no assume-role needed.
        """
        if account.id == self.mgmt_account_id:
            return self._mgmt_session

        role_arn = f"arn:aws:iam::{account.id}:role/{self._role_name}"
        try:
            resp = self._sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName="aws-obs-cost-audit",
                DurationSeconds=3600,
            )
        except ClientError as e:
            log.warning("AssumeRole failed for %s (%s): %s", account.id, role_arn, e)
            return None

        creds = resp["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
