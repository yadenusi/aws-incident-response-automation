"""Remove everything simulate.py created (all tagged ir:test=true).
Usage:  python scripts/cleanup.py
"""
import boto3

session = boto3.session.Session()
iam, ec2, s3 = session.client("iam"), session.client("ec2"), session.client("s3")
USER = "ir-test-user"

print("IAM test user")
try:
    for p in iam.list_user_policies(UserName=USER)["PolicyNames"]:
        iam.delete_user_policy(UserName=USER, PolicyName=p)
    for k in iam.list_access_keys(UserName=USER)["AccessKeyMetadata"]:
        iam.delete_access_key(UserName=USER, AccessKeyId=k["AccessKeyId"])
    iam.delete_user(UserName=USER)
    print("    deleted")
except iam.exceptions.NoSuchEntityException:
    print("    not found")

print("Test security groups")
for sg in ec2.describe_security_groups(Filters=[{"Name": "tag:ir:test", "Values": ["true"]}])["SecurityGroups"]:
    ec2.delete_security_group(GroupId=sg["GroupId"])
    print(f"    deleted {sg['GroupId']}")

print("Test VPCs")
for v in ec2.describe_vpcs(Filters=[{"Name": "tag:ir:test", "Values": ["true"]}])["Vpcs"]:
    for sg in ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [v["VpcId"]]}])["SecurityGroups"]:
        if sg["GroupName"] != "default":
            ec2.delete_security_group(GroupId=sg["GroupId"])
    ec2.delete_vpc(VpcId=v["VpcId"])
    print(f"    deleted {v['VpcId']}")

print("Test buckets")
for b in s3.list_buckets()["Buckets"]:
    if b["Name"].startswith("ir-test-public-"):
        for o in s3.list_objects_v2(Bucket=b["Name"]).get("Contents", []):
            s3.delete_object(Bucket=b["Name"], Key=o["Key"])
        s3.delete_bucket(Bucket=b["Name"])
        print(f"    deleted {b['Name']}")
print("Done. The ir-quarantine-sg (if created) and the evidence bucket are removed by 'aws cloudformation delete-stack'.")
