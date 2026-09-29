import json
import os
import sys
from datetime import datetime, timedelta, timezone

import boto3
import pytest
from moto import mock_aws

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.update(AWS_DEFAULT_REGION="us-east-1", AWS_ACCESS_KEY_ID="testing",
                  AWS_SECRET_ACCESS_KEY="testing", AWS_SECURITY_TOKEN="testing",
                  MOTO_IAM_LOAD_MANAGED_POLICIES="true")

from ir_automation import config  # noqa: E402
from ir_automation.handler import make_clients  # noqa: E402

BASE = datetime(2026, 9, 28, 3, 0, tzinfo=timezone.utc)   # a 3:00 a.m. attack


def ct_event(name, user="jdoe", ip="198.51.100.23", minute=0, second=0, **extra):
    ev = {"eventVersion": "1.08", "eventName": name,
          "eventTime": (BASE + timedelta(minutes=minute, seconds=second)).isoformat().replace("+00:00", "Z"),
          "sourceIPAddress": ip, "awsRegion": "us-east-1",
          "userIdentity": {"type": "IAMUser", "userName": user,
                           "arn": f"arn:aws:iam::123456789012:user/{user}"}}
    ev.update(extra)
    return ev


@pytest.fixture
def aws():
    with mock_aws():
        clients = make_clients(boto3.session.Session(region_name="us-east-1"))
        clients["s3"].create_bucket(Bucket=config.EVIDENCE_BUCKET)
        sqs = boto3.client("sqs", region_name="us-east-1")
        q = sqs.create_queue(QueueName="soc-inbox")["QueueUrl"]
        q_arn = sqs.get_queue_attributes(QueueUrl=q, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            arn = clients["sns"].create_topic(Name=f"ir-{sev.lower()}")["TopicArn"]
            clients["sns"].subscribe(TopicArn=arn, Protocol="sqs", Endpoint=q_arn)
            config.SNS_TOPICS[sev] = arn
        clients["sqs"], clients["queue_url"] = sqs, q
        yield clients


def read_alerts(clients):
    msgs = clients["sqs"].receive_message(QueueUrl=clients["queue_url"], MaxNumberOfMessages=10)
    return [json.loads(m["Body"]) for m in msgs.get("Messages", [])]
