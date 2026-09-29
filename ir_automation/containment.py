"""Containment and evidence preservation.

Order of operations for every playbook:
  1. preserve evidence (config snapshot, EBS snapshot, CloudTrail records)
  2. apply a reversible containment control
  3. tag the resource and write an audit entry
Controls are deliberately reversible (deny policy, key deactivation, SG swap)
so a false positive can be rolled back in minutes. Nothing is deleted."""
import hashlib
import json

from . import config
from .models import utcnow

DENY_ALL = json.dumps({"Version": "2012-10-17", "Statement": [{
    "Sid": "IRQuarantine", "Effect": "Deny", "Action": "*", "Resource": "*"}]})


class Containment:
    def __init__(self, clients, dry_run=None):
        self.c = clients
        self.dry_run = config.DRY_RUN if dry_run is None else dry_run

    # ------------------------------------------------------------ audit + evidence
    def _audit(self, inc, action, target, result="SUCCESS", detail=None):
        entry = {"time": utcnow().isoformat(), "incident": inc.incident_id, "action": action,
                 "target": target, "result": "DRY_RUN" if self.dry_run else result,
                 "detail": detail or {}}
        inc.containment.append(entry)
        print(json.dumps({"ir_audit": entry}))          # also lands in CloudWatch Logs
        return entry

    def preserve(self, inc, name, payload):
        """Write evidence to the locked evidence bucket with a SHA-256 digest."""
        key = f"{inc.incident_id}/{name}.json"
        body = json.dumps(payload, default=str, indent=2).encode()
        digest = hashlib.sha256(body).hexdigest()
        if not self.dry_run:
            self.c["s3"].put_object(Bucket=config.EVIDENCE_BUCKET, Key=key, Body=body,
                                    ServerSideEncryption="AES256", ChecksumAlgorithm="SHA256",
                                    Metadata={"sha256": digest, "incident": inc.incident_id})
        self._audit(inc, "PRESERVE_EVIDENCE", f"s3://{config.EVIDENCE_BUCKET}/{key}",
                    detail={"sha256": digest, "bytes": len(body)})
        return key

    # ------------------------------------------------------------ IAM principal
    def quarantine_user(self, inc):
        iam, user = self.c["iam"], inc.principal
        if inc.details.get("identity_type") not in (None, "IAMUser"):
            # SSO / assumed role sessions have no IAM user to lock; hand off to a human
            self.preserve(inc, "cloudtrail_events", inc.evidence_events)
            self._audit(inc, "MONITOR_ONLY", user, detail={
                "reason": f"{inc.details['identity_type']} identity: revoke the session in "
                          "IAM Identity Center or the role's trust policy"})
            return
        self.preserve(inc, "cloudtrail_events", inc.evidence_events)
        self.preserve(inc, "identity_snapshot", inc.investigation.get("identity", {}))
        if not self.dry_run:
            iam.put_user_policy(UserName=user, PolicyName=config.QUARANTINE_POLICY_NAME,
                                PolicyDocument=DENY_ALL)
        self._audit(inc, "ATTACH_DENY_ALL_POLICY", user)
        for k in iam.list_access_keys(UserName=user)["AccessKeyMetadata"]:
            if k["Status"] == "Active":
                if not self.dry_run:
                    iam.update_access_key(UserName=user, AccessKeyId=k["AccessKeyId"], Status="Inactive")
                self._audit(inc, "DEACTIVATE_ACCESS_KEY", k["AccessKeyId"])
        if not self.dry_run:
            iam.tag_user(UserName=user, Tags=[{"Key": "ir:quarantined", "Value": inc.incident_id}])
        self._audit(inc, "TAG_RESOURCE", user)

    # ------------------------------------------------------------ S3
    def lock_bucket(self, inc):
        s3, b = self.c["s3"], inc.resource_id
        self.preserve(inc, "bucket_config_before", inc.investigation.get("resource", {}))
        if not self.dry_run:
            s3.put_public_access_block(Bucket=b, PublicAccessBlockConfiguration={
                "BlockPublicAcls": True, "IgnorePublicAcls": True,
                "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
        self._audit(inc, "ENABLE_PUBLIC_ACCESS_BLOCK", b)
        if not self.dry_run:
            s3.put_bucket_acl(Bucket=b, ACL="private")
        self._audit(inc, "RESET_ACL_PRIVATE", b)
        if not self.dry_run:
            s3.put_bucket_tagging(Bucket=b, Tagging={"TagSet": [
                {"Key": "ir:quarantined", "Value": inc.incident_id}]})
        self._audit(inc, "TAG_RESOURCE", b)

    # ------------------------------------------------------------ security groups / EC2
    def revoke_open_rules(self, inc):
        ec2, sg = self.c["ec2"], inc.resource_id
        self.preserve(inc, "security_group_before", inc.investigation.get("resource", {})
                      or ec2.describe_security_groups(GroupIds=[sg])["SecurityGroups"][0])
        for rule in inc.details["offending_rules"]:
            perm = {"IpProtocol": rule["protocol"]}
            if rule["protocol"] != "-1":
                perm.update(FromPort=rule["from"], ToPort=rule["to"])
            v4 = [c for c in rule["cidrs"] if ":" not in c]
            v6 = [c for c in rule["cidrs"] if ":" in c]
            if v4:
                perm["IpRanges"] = [{"CidrIp": c} for c in v4]
            if v6:
                perm["Ipv6Ranges"] = [{"CidrIpv6": c} for c in v6]
            if not self.dry_run:
                ec2.revoke_security_group_ingress(GroupId=sg, IpPermissions=[perm])
            self._audit(inc, "REVOKE_INGRESS", sg, detail=rule)
        if not self.dry_run:
            ec2.create_tags(Resources=[sg], Tags=[{"Key": "ir:remediated", "Value": inc.incident_id}])
        self._audit(inc, "TAG_RESOURCE", sg)
        # if the exposure was CRITICAL, isolate every instance that sat behind it
        if inc.severity == "CRITICAL":
            for i in inc.investigation.get("resource", {}).get("attached_instances", []):
                self.isolate_instance(inc, i["id"], inc.details.get("vpc_id"))

    def _quarantine_sg(self, vpc_id):
        ec2 = self.c["ec2"]
        found = ec2.describe_security_groups(Filters=[
            {"Name": "group-name", "Values": [config.QUARANTINE_SG_NAME]},
            {"Name": "vpc-id", "Values": [vpc_id]}])["SecurityGroups"]
        if found:
            return found[0]["GroupId"]
        gid = ec2.create_security_group(GroupName=config.QUARANTINE_SG_NAME, VpcId=vpc_id,
                                        Description="IR quarantine: no ingress, no egress")["GroupId"]
        ec2.revoke_security_group_egress(GroupId=gid, IpPermissions=[
            {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
        return gid

    def isolate_instance(self, inc, instance_id, vpc_id):
        ec2 = self.c["ec2"]
        inst = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
        vpc_id = vpc_id or inst["VpcId"]
        self.preserve(inc, f"instance_{instance_id}_metadata", inst)
        # 1. snapshot every EBS volume BEFORE touching the host
        for m in inst.get("BlockDeviceMappings", []):
            vol = m["Ebs"]["VolumeId"]
            snap = "dry-run" if self.dry_run else ec2.create_snapshot(
                VolumeId=vol, Description=f"Forensic copy {inc.incident_id}",
                TagSpecifications=[{"ResourceType": "snapshot", "Tags": [
                    {"Key": "ir:incident", "Value": inc.incident_id},
                    {"Key": "ir:evidence", "Value": "true"}]}])["SnapshotId"]
            self._audit(inc, "EBS_FORENSIC_SNAPSHOT", vol, detail={"snapshot": snap})
        # 2. swap to isolation SG (keeps the host running so memory is preserved)
        if not self.dry_run:
            qsg = self._quarantine_sg(vpc_id)
            ec2.modify_instance_attribute(InstanceId=instance_id, Groups=[qsg])
            ec2.create_tags(Resources=[instance_id], Tags=[{"Key": "ir:quarantined",
                                                            "Value": inc.incident_id}])
        else:
            qsg = "dry-run"
        self._audit(inc, "ISOLATE_INSTANCE", instance_id, detail={"quarantine_sg": qsg,
                    "previous_sgs": [g["GroupId"] for g in inst.get("SecurityGroups", [])]})

    # ------------------------------------------------------------ dispatcher
    PLAYBOOK = {
        "BRUTE_FORCE_LOGIN": "quarantine_user_if_critical",
        "UNUSUAL_LOCATION_LOGIN": "quarantine_user",
        "MASS_DELETION": "quarantine_user",
        "PRIVILEGE_ESCALATION": "quarantine_user",
        "PUBLIC_S3_BUCKET": "lock_bucket",
        "OPEN_SECURITY_GROUP": "revoke_open_rules",
    }

    def quarantine_user_if_critical(self, inc):
        # Failed logins alone do not prove compromise; lock only if a login succeeded.
        if inc.severity == "CRITICAL":
            return self.quarantine_user(inc)
        self.preserve(inc, "cloudtrail_events", inc.evidence_events)
        self._audit(inc, "MONITOR_ONLY", inc.principal,
                    detail={"reason": "no successful login observed; account left active"})

    def contain(self, inc):
        method = getattr(self, self.PLAYBOOK[inc.incident_type])
        try:
            method(inc)
            inc.status = "DRY_RUN (no changes made)" if self.dry_run else "CONTAINED"
        except Exception as exc:  # noqa: BLE001
            self._audit(inc, "CONTAINMENT_FAILED", inc.resource_id, result="FAILED",
                        detail={"error": str(exc)})
            inc.status = "CONTAINMENT_FAILED"
        self.preserve(inc, "audit_trail", inc.containment)
        return inc
