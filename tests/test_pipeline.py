"""Test suite: unit tests per component plus an end to end scenario.
Runs entirely against moto's in-memory AWS, so no real account is touched."""
import json
import time

import pytest

from conftest import ct_event, read_alerts
from ir_automation import config, detectors, investigator
from ir_automation.containment import Containment
from ir_automation.handler import run_pipeline
from ir_automation.notifier import escalation_target, notify

FAIL = {"responseElements": {"ConsoleLogin": "Failure"}, "errorMessage": "Failed authentication"}
OK = {"responseElements": {"ConsoleLogin": "Success"}, "additionalEventData": {"MFAUsed": "No"}}


def make_user(iam, name="jdoe", admin=False):
    iam.create_user(UserName=name)
    iam.create_access_key(UserName=name)
    if admin:
        iam.attach_user_policy(UserName=name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")


def make_instance_behind(ec2, sg_id):
    ami = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    return ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, SecurityGroupIds=[sg_id],
                             SubnetId=ec2.describe_subnets()["Subnets"][0]["SubnetId"]
                             )["Instances"][0]["InstanceId"]


def open_sg(ec2, name, proto="tcp", port=22, cidr="0.0.0.0/0"):
    vpc = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    gid = ec2.create_security_group(GroupName=name, Description=name, VpcId=vpc)["GroupId"]
    perm = {"IpProtocol": proto, "IpRanges": [{"CidrIp": cidr}]}
    if proto != "-1":
        perm.update(FromPort=port, ToPort=port)
    ec2.authorize_security_group_ingress(GroupId=gid, IpPermissions=[perm])
    return gid


# =============================================================== DETECTION
class TestUnauthorizedAccess:
    def test_five_failures_in_window_is_brute_force(self):
        evs = [ct_event("ConsoleLogin", minute=i, **FAIL) for i in range(5)]
        inc = detectors.detect_unauthorized_access(evs)
        assert [i.incident_type for i in inc] == ["BRUTE_FORCE_LOGIN"] and inc[0].severity == "HIGH"

    def test_four_failures_below_threshold(self):
        evs = [ct_event("ConsoleLogin", minute=i, **FAIL) for i in range(4)]
        assert detectors.detect_unauthorized_access(evs) == []

    def test_failures_spread_outside_window(self):
        evs = [ct_event("ConsoleLogin", minute=i * 6, **FAIL) for i in range(5)]  # 24 min span
        assert detectors.detect_unauthorized_access(evs) == []

    def test_burst_then_success_is_critical(self):
        evs = [ct_event("ConsoleLogin", minute=i, **FAIL) for i in range(6)] + \
              [ct_event("ConsoleLogin", minute=7, **OK)]
        types = {i.incident_type: i.severity for i in detectors.detect_unauthorized_access(evs)}
        assert types == {"BRUTE_FORCE_LOGIN": "CRITICAL", "UNUSUAL_LOCATION_LOGIN": "HIGH"}

    def test_success_from_corporate_ip_ignored(self):
        assert detectors.detect_unauthorized_access([ct_event("ConsoleLogin", ip="10.2.3.4", **OK)]) == []


class TestMassDeletion:
    def test_burst_of_deletes(self):
        evs = [ct_event("DeleteObject", second=i * 5) for i in range(25)]
        inc = detectors.detect_mass_deletion(evs)
        assert len(inc) == 1 and inc[0].severity == "CRITICAL"

    def test_normal_cleanup_not_flagged(self):
        assert detectors.detect_mass_deletion([ct_event("DeleteObject", minute=i) for i in range(10)]) == []

    def test_denied_deletes_not_counted(self):
        evs = [ct_event("DeleteBucket", second=i, errorCode="AccessDenied") for i in range(30)]
        assert detectors.detect_mass_deletion(evs) == []


class TestPrivilegeEscalation:
    def test_self_grant_admin(self):
        ev = ct_event("AttachUserPolicy", requestParameters={
            "userName": "jdoe", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"})
        inc = detectors.detect_privilege_escalation([ev])
        assert inc[0].severity == "CRITICAL" and inc[0].details["admin_grant"]

    def test_allowlisted_pipeline_ignored(self):
        ev = ct_event("AttachUserPolicy", user="iac-pipeline", requestParameters={
            "userName": "svc", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"})
        assert detectors.detect_privilege_escalation([ev]) == []

    def test_inline_self_policy_high(self):
        ev = ct_event("PutUserPolicy", requestParameters={"userName": "jdoe", "policyName": "x",
                      "policyDocument": '{"Statement":[{"Action":"s3:*"}]}'})
        assert detectors.detect_privilege_escalation([ev])[0].severity == "HIGH"

    def test_access_key_for_other_user_not_flagged(self):
        ev = ct_event("CreateAccessKey", requestParameters={"userName": "other"})
        assert detectors.detect_privilege_escalation([ev]) == []


class TestMisconfiguration:
    def test_public_acl_bucket(self, aws):
        aws["s3"].create_bucket(Bucket="marketing-assets", ACL="public-read")
        inc = detectors.detect_public_buckets(aws["s3"])
        assert inc[0].resource_id == "marketing-assets" and "AllUsers" in inc[0].details["reasons"][0]

    def test_public_policy_bucket(self, aws):
        aws["s3"].create_bucket(Bucket="statements")
        aws["s3"].put_bucket_policy(Bucket="statements", Policy=json.dumps({"Statement": [
            {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
             "Resource": "arn:aws:s3:::statements/*"}]}))
        assert detectors.detect_public_buckets(aws["s3"])[0].resource_id == "statements"

    def test_private_and_blocked_buckets_clean(self, aws):
        aws["s3"].create_bucket(Bucket="private")
        aws["s3"].create_bucket(Bucket="blocked", ACL="public-read")
        aws["s3"].put_public_access_block(Bucket="blocked", PublicAccessBlockConfiguration={
            k: True for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy",
                              "RestrictPublicBuckets")})
        assert detectors.detect_public_buckets(aws["s3"]) == []

    def test_ssh_open_to_world(self, aws):
        gid = open_sg(aws["ec2"], "web")
        inc = detectors.detect_open_security_groups(aws["ec2"])
        assert inc[0].resource_id == gid and inc[0].severity == "HIGH"

    def test_all_traffic_open_is_critical(self, aws):
        open_sg(aws["ec2"], "any", proto="-1")
        assert detectors.detect_open_security_groups(aws["ec2"])[0].severity == "CRITICAL"

    def test_https_and_internal_ssh_clean(self, aws):
        open_sg(aws["ec2"], "https", port=443)
        open_sg(aws["ec2"], "bastion", port=22, cidr="10.0.0.0/8")
        assert detectors.detect_open_security_groups(aws["ec2"]) == []


# =============================================================== INVESTIGATION
class TestInvestigation:
    def test_user_context(self, aws):
        make_user(aws["iam"], admin=True)
        ctx = investigator.user_context(aws["iam"], aws["cloudtrail"], "jdoe")
        assert ctx["is_admin"] and ctx["mfa_devices"] == 0 and ctx["access_keys"][0]["status"] == "Active"

    def test_bucket_context_reads_owner_tags(self, aws):
        aws["s3"].create_bucket(Bucket="statements")
        aws["s3"].put_bucket_tagging(Bucket="statements", Tagging={"TagSet": [
            {"Key": "Owner", "Value": "payments-team"}, {"Key": "DataClassification", "Value": "PCI"}]})
        ctx = investigator.bucket_context(aws["s3"], aws["config"], "statements")
        assert ctx["owner"] == "payments-team" and ctx["data_classification"] == "PCI"

    def test_sg_context_finds_instances(self, aws):
        gid = open_sg(aws["ec2"], "web")
        iid = make_instance_behind(aws["ec2"], gid)
        ctx = investigator.security_group_context(aws["ec2"], aws["config"], aws["logs"], gid)
        assert ctx["attached_instances"][0]["id"] == iid

    def test_missing_source_degrades_gracefully(self, aws):
        ctx = investigator.user_context(aws["iam"], aws["cloudtrail"], "ghost")
        assert "lookup_error" in ctx


# =============================================================== CONTAINMENT
class TestContainment:
    def _inc(self, aws, events, detector=detectors.detect_privilege_escalation):
        inc = detector(events)[0]
        return investigator.investigate(inc, aws)

    def test_quarantine_user(self, aws):
        make_user(aws["iam"])
        inc = self._inc(aws, [ct_event("AttachUserPolicy", requestParameters={
            "userName": "jdoe", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"})])
        Containment(aws, dry_run=False).contain(inc)
        iam = aws["iam"]
        assert config.QUARANTINE_POLICY_NAME in iam.list_user_policies(UserName="jdoe")["PolicyNames"]
        assert iam.list_access_keys(UserName="jdoe")["AccessKeyMetadata"][0]["Status"] == "Inactive"
        assert inc.status == "CONTAINED"

    def test_evidence_integrity(self, aws):
        import hashlib
        make_user(aws["iam"])
        inc = self._inc(aws, [ct_event("PutUserPolicy", requestParameters={"userName": "jdoe"})])
        Containment(aws, dry_run=False).contain(inc)
        keys = [o["Key"] for o in aws["s3"].list_objects_v2(Bucket=config.EVIDENCE_BUCKET)["Contents"]]
        assert {f"{inc.incident_id}/{n}.json" for n in
                ("cloudtrail_events", "identity_snapshot", "audit_trail")} <= set(keys)
        obj = aws["s3"].get_object(Bucket=config.EVIDENCE_BUCKET, Key=keys[0])
        assert hashlib.sha256(obj["Body"].read()).hexdigest() == obj["Metadata"]["sha256"]

    def test_lock_public_bucket(self, aws):
        aws["s3"].create_bucket(Bucket="marketing-assets", ACL="public-read")
        inc = self._inc(aws, None, lambda _: detectors.detect_public_buckets(aws["s3"]))
        Containment(aws, dry_run=False).contain(inc)
        assert detectors.detect_public_buckets(aws["s3"]) == []      # regression check

    def test_critical_sg_isolates_instance(self, aws):
        gid = open_sg(aws["ec2"], "legacy", proto="-1")
        iid = make_instance_behind(aws["ec2"], gid)
        inc = self._inc(aws, None, lambda _: detectors.detect_open_security_groups(aws["ec2"]))
        Containment(aws, dry_run=False).contain(inc)
        ec2 = aws["ec2"]
        inst = ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]
        qsg = ec2.describe_security_groups(GroupIds=[inst["SecurityGroups"][0]["GroupId"]])["SecurityGroups"][0]
        assert qsg["GroupName"] == config.QUARANTINE_SG_NAME and qsg["IpPermissionsEgress"] == []
        snaps = ec2.describe_snapshots(Filters=[{"Name": "tag:ir:incident", "Values": [inc.incident_id]}])
        assert len(snaps["Snapshots"]) >= 1
        assert inst["State"]["Name"] == "running"                     # memory preserved
        assert detectors.detect_open_security_groups(ec2) == []

    def test_brute_force_without_success_monitors_only(self, aws):
        make_user(aws["iam"])
        inc = self._inc(aws, [ct_event("ConsoleLogin", minute=i, **FAIL) for i in range(5)],
                        detectors.detect_unauthorized_access)
        Containment(aws, dry_run=False).contain(inc)
        assert aws["iam"].list_user_policies(UserName="jdoe")["PolicyNames"] == []
        assert any(a["action"] == "MONITOR_ONLY" for a in inc.containment)

    def test_dry_run_changes_nothing(self, aws):
        make_user(aws["iam"])
        inc = self._inc(aws, [ct_event("PutUserPolicy", requestParameters={"userName": "jdoe"})])
        Containment(aws, dry_run=True).contain(inc)
        assert aws["iam"].list_user_policies(UserName="jdoe")["PolicyNames"] == []
        assert all(a["result"] == "DRY_RUN" for a in inc.containment)

    def test_failure_is_recorded_not_raised(self, aws):
        inc = self._inc(aws, [ct_event("PutUserPolicy", user="ghost",
                                       requestParameters={"userName": "ghost"})])
        Containment(aws, dry_run=False).contain(inc)
        assert inc.status == "CONTAINMENT_FAILED"


# =============================================================== NOTIFICATION
class TestNotification:
    def test_alert_delivered_with_required_fields(self, aws):
        make_user(aws["iam"])
        inc = detectors.detect_privilege_escalation([ct_event("AttachUserPolicy", requestParameters={
            "userName": "jdoe", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"})])[0]
        investigator.investigate(inc, aws)
        Containment(aws, dry_run=False).contain(inc)
        notify(aws["sns"], inc)
        alert = read_alerts(aws)[0]
        body = json.loads(alert["Message"])
        assert alert["Subject"].startswith("[CRITICAL] PRIVILEGE_ESCALATION")
        for f in ("findings", "containment_status", "containment_actions", "suggested_remediation",
                  "evidence_locations", "routed_to"):
            assert body[f]
        assert "On call incident commander (page)" in body["routed_to"]

    @pytest.mark.parametrize("sev,mins,expected", [
        ("HIGH", 5, "HIGH"), ("HIGH", 25, "CRITICAL"), ("MEDIUM", 130, "HIGH"), ("LOW", 3000, "HIGH")])
    def test_escalation(self, sev, mins, expected):
        assert escalation_target(sev, mins) == expected


# =============================================================== END TO END
def test_end_to_end_scenario(aws, capsys):
    """Simulates the 3 a.m. scenario: credential stuffing that succeeds, the
    attacker escalating to admin and deleting data, plus two pre-existing
    misconfigurations. Asserts every stage runs and the total is < 30 min."""
    make_user(aws["iam"], "jdoe")
    make_user(aws["iam"], "svc-reports")
    aws["s3"].create_bucket(Bucket="customer-statements", ACL="public-read")
    gid = open_sg(aws["ec2"], "legacy-db", port=3306)
    make_instance_behind(aws["ec2"], gid)
    events = [ct_event("ConsoleLogin", minute=0, second=i * 20, **FAIL) for i in range(8)]
    events += [ct_event("ConsoleLogin", minute=3, **OK)]
    events += [ct_event("AttachUserPolicy", minute=4, requestParameters={
        "userName": "jdoe", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"})]
    events += [ct_event("DeleteObject", user="svc-reports", ip="198.51.100.77", minute=6, second=i * 3)
               for i in range(40)]
    events += [ct_event("DescribeInstances", user="alice", ip="10.1.1.1", minute=i) for i in range(50)]
    summary, incidents = run_pipeline(aws, events, posture=True, dry_run=False)
    types = sorted(i["type"] for i in summary["incidents"])
    assert types == sorted(["BRUTE_FORCE_LOGIN", "UNUSUAL_LOCATION_LOGIN", "PRIVILEGE_ESCALATION",
                            "MASS_DELETION", "PUBLIC_S3_BUCKET", "OPEN_SECURITY_GROUP"])
    assert all("CONTAINED" in i["status"] and i["status"].endswith("NOTIFIED")
               for i in summary["incidents"])
    assert summary["total_seconds"] < 1800
    # rerun: posture findings must be gone (remediation is persistent)
    again, _ = run_pipeline(aws, [], posture=True, dry_run=False)
    assert again["incidents"] == []
    with open("/tmp/e2e_summary.json", "w") as fh:
        json.dump({"summary": summary, "incidents": [i.to_dict() for i in incidents]}, fh,
                  default=str, indent=2)


def test_detection_throughput():
    """10,000 mixed CloudTrail records must be analysed well inside a Lambda run."""
    evs = [ct_event("GetObject", user=f"u{i % 200}", ip="10.0.0.1", minute=i % 15) for i in range(9900)]
    evs += [ct_event("ConsoleLogin", minute=i, **FAIL) for i in range(100)]
    t = time.perf_counter()
    inc = detectors.run_event_detectors(evs)
    elapsed = time.perf_counter() - t
    with open("/tmp/throughput.json", "w") as fh:
        json.dump({"events": len(evs), "seconds": elapsed, "incidents": len(inc)}, fh)
    assert elapsed < 5 and any(i.incident_type == "BRUTE_FORCE_LOGIN" for i in inc)


def test_sso_identity_is_monitored_not_quarantined(aws):
    ev = ct_event("ConsoleLogin", user="student@example.edu", **OK)
    ev["userIdentity"] = {"type": "AssumedRole", "arn": "arn:aws:sts::1:assumed-role/SSO/student@example.edu"}
    inc = detectors.run_event_detectors([ev])[0]
    investigator.investigate(inc, aws)
    Containment(aws, dry_run=False).contain(inc)
    assert inc.status == "CONTAINED" and inc.containment[-2]["action"] == "MONITOR_ONLY"


def test_bucket_with_acls_disabled_and_tags_preserved(aws):
    s3 = aws["s3"]
    s3.create_bucket(Bucket="modern-bucket", ObjectOwnership="BucketOwnerEnforced")
    s3.put_bucket_tagging(Bucket="modern-bucket", Tagging={"TagSet": [{"Key": "Owner", "Value": "lab"}]})
    s3.put_bucket_policy(Bucket="modern-bucket", Policy=json.dumps({"Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
         "Resource": "arn:aws:s3:::modern-bucket/*"}]}))
    inc = investigator.investigate(detectors.detect_public_buckets(s3)[0], aws)
    Containment(aws, dry_run=False).contain(inc)
    assert inc.status == "CONTAINED"
    assert any(a["action"] == "RESET_ACL_PRIVATE" and a["result"] == "SKIPPED" for a in inc.containment)
    keys = {t["Key"] for t in s3.get_bucket_tagging(Bucket="modern-bucket")["TagSet"]}
    assert keys == {"Owner", "ir:quarantined"}
