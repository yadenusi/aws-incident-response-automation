"""Create three SAFE, low cost test incidents in a lab AWS account.

  1. Privilege escalation: a throwaway IAM user that grants itself a new
     inline policy using its own access key.
  2. Open security group: SSH (22) open to 0.0.0.0/0 in the default VPC,
     with no instances attached.
  3. Public S3 bucket: an empty bucket with a public read policy. If
     account level Block Public Access is on (the AWS default), AWS refuses
     the change and this step is skipped, which is the correct outcome.

Run cleanup.py afterwards. Everything created is tagged ir:test=true.
Usage:  python scripts/simulate.py
"""
import json
import time
import uuid

import boto3

TAG = [{"Key": "ir:test", "Value": "true"}]
USER = "ir-test-user"
SG_NAME = "ir-test-open-ssh"


def priv_esc(iam, sts):
    print("[1] Privilege escalation test user")
    try:
        iam.create_user(UserName=USER, Tags=TAG)
    except iam.exceptions.EntityAlreadyExistsException:
        pass
    acct = sts.get_caller_identity()["Account"]
    iam.put_user_policy(UserName=USER, PolicyName="self-manage", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["iam:PutUserPolicy"],
            "Resource": f"arn:aws:iam::{acct}:user/{USER}"}]}))
    key = iam.create_access_key(UserName=USER)["AccessKey"]
    print("    waiting 15 s for the new key to become active...")
    time.sleep(15)
    attacker = boto3.client("iam", aws_access_key_id=key["AccessKeyId"],
                            aws_secret_access_key=key["SecretAccessKey"])
    attacker.put_user_policy(UserName=USER, PolicyName="escalated", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"}]}))
    print("    done: ir-test-user called PutUserPolicy on itself")


def open_sg(ec2):
    print("[2] Security group with SSH open to the internet")
    vpc = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])["Vpcs"]
    if not vpc:
        print("    skipped: no default VPC in this region")
        return
    try:
        gid = ec2.create_security_group(GroupName=SG_NAME, Description="IR lab test",
                                        VpcId=vpc[0]["VpcId"])["GroupId"]
    except ec2.exceptions.ClientError as exc:
        if "Duplicate" not in str(exc):
            raise
        gid = ec2.describe_security_groups(Filters=[{"Name": "group-name", "Values": [SG_NAME]}]
                                           )["SecurityGroups"][0]["GroupId"]
    ec2.create_tags(Resources=[gid], Tags=TAG)
    try:
        ec2.authorize_security_group_ingress(GroupId=gid, IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "IR lab test"}]}])
    except ec2.exceptions.ClientError as exc:
        if "Duplicate" not in str(exc):
            raise
    print(f"    done: {gid}")


def public_bucket(s3, region):
    print("[3] Public S3 bucket")
    name = f"ir-test-public-{uuid.uuid4().hex[:8]}"
    kw = {} if region == "us-east-1" else {"CreateBucketConfiguration": {"LocationConstraint": region}}
    s3.create_bucket(Bucket=name, **kw)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": TAG + [
        {"Key": "Owner", "Value": "lab"}, {"Key": "DataClassification", "Value": "Confidential"}]})
    try:
        s3.delete_public_access_block(Bucket=name)
        s3.put_bucket_policy(Bucket=name, Policy=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{name}/*"}]}))
        print(f"    done: {name} (empty, public read policy)")
    except s3.exceptions.ClientError as exc:
        print(f"    skipped: account level Block Public Access stopped it ({exc.response['Error']['Code']})")


if __name__ == "__main__":
    session = boto3.session.Session()
    region = session.region_name or "us-east-1"
    print(f"Region: {region}   Account: {session.client('sts').get_caller_identity()['Account']}\n")
    priv_esc(session.client("iam"), session.client("sts"))
    open_sg(session.client("ec2"))
    public_bucket(session.client("s3"), region)
    print("\nNext: wait ~10 minutes for CloudTrail, then invoke the responder (see README).")
