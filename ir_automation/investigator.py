"""Automated investigation. Enriches an incident with the context an analyst
would otherwise gather by hand: identity and permissions, resource metadata
and configuration history, related network activity, and a merged timeline.
Every lookup is wrapped so a missing data source degrades the report rather
than aborting the response."""
import json
from datetime import datetime, timedelta, timezone

from .detectors import normalize_event


def _safe(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except Exception as exc:  # noqa: BLE001  record the gap, keep going
        return {"error": f"{type(exc).__name__}: {exc}"}


# --------------------------------------------------------------- identity
def user_context(iam, cloudtrail, user_name, hours=24):
    ctx = {"user": user_name}
    u = _safe(iam.get_user, UserName=user_name)
    if "error" in u:
        ctx["lookup_error"] = u["error"]
        return ctx
    ctx["arn"] = u["User"]["Arn"]
    ctx["created"] = str(u["User"]["CreateDate"])
    ctx["password_last_used"] = str(u["User"].get("PasswordLastUsed", "never"))
    ctx["attached_policies"] = [p["PolicyName"] for p in
                                _safe(iam.list_attached_user_policies, UserName=user_name).get("AttachedPolicies", [])]
    ctx["inline_policies"] = _safe(iam.list_user_policies, UserName=user_name).get("PolicyNames", [])
    ctx["groups"] = [g["GroupName"] for g in
                     _safe(iam.list_groups_for_user, UserName=user_name).get("Groups", [])]
    ctx["access_keys"] = [{"id": k["AccessKeyId"], "status": k["Status"]} for k in
                          _safe(iam.list_access_keys, UserName=user_name).get("AccessKeyMetadata", [])]
    ctx["mfa_devices"] = len(_safe(iam.list_mfa_devices, UserName=user_name).get("MFADevices", []))
    ctx["is_admin"] = any("Administrator" in p for p in ctx["attached_policies"])
    start = datetime.now(timezone.utc) - timedelta(hours=hours)
    recent = _safe(cloudtrail.lookup_events,
                   LookupAttributes=[{"AttributeKey": "Username", "AttributeValue": user_name}],
                   StartTime=start, MaxResults=50)
    ctx["recent_activity"] = [
        {"time": e.get("eventTime"), "event": e.get("eventName"), "ip": e.get("sourceIPAddress")}
        for e in map(normalize_event, recent.get("Events", []))]
    return ctx


# --------------------------------------------------------------- resources
def bucket_context(s3, config_svc, bucket):
    ctx = {"bucket": bucket}
    created = next((b["CreationDate"] for b in s3.list_buckets()["Buckets"] if b["Name"] == bucket), None)
    ctx["created"] = str(created)
    ctx["region"] = _safe(s3.get_bucket_location, Bucket=bucket).get("LocationConstraint") or "us-east-1"
    ctx["tags"] = {t["Key"]: t["Value"] for t in _safe(s3.get_bucket_tagging, Bucket=bucket).get("TagSet", [])}
    ctx["owner"] = ctx["tags"].get("Owner", "untagged")
    ctx["data_classification"] = ctx["tags"].get("DataClassification", "unknown")
    ctx["acl"] = _safe(s3.get_bucket_acl, Bucket=bucket).get("Grants", [])
    ctx["policy"] = _safe(s3.get_bucket_policy, Bucket=bucket).get("Policy")
    ctx["encryption"] = _safe(s3.get_bucket_encryption, Bucket=bucket).get(
        "ServerSideEncryptionConfiguration", "none")
    ctx["logging"] = _safe(s3.get_bucket_logging, Bucket=bucket).get("LoggingEnabled", "disabled")
    ctx["object_count_sample"] = _safe(s3.list_objects_v2, Bucket=bucket, MaxKeys=1000).get("KeyCount", 0)
    ctx["config_history"] = _config_history(config_svc, "AWS::S3::Bucket", bucket)
    return ctx


def security_group_context(ec2, config_svc, logs, sg_id, flow_log_group=None):
    ctx = {"group_id": sg_id}
    sg = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
    ctx.update(name=sg.get("GroupName"), vpc=sg.get("VpcId"),
               tags={t["Key"]: t["Value"] for t in sg.get("Tags", [])})
    res = ec2.describe_instances(Filters=[{"Name": "instance.group-id", "Values": [sg_id]}])
    ctx["attached_instances"] = [
        {"id": i["InstanceId"], "state": i["State"]["Name"],
         "public_ip": i.get("PublicIpAddress"),
         "volumes": [m["Ebs"]["VolumeId"] for m in i.get("BlockDeviceMappings", []) if "Ebs" in m]}
        for r in res["Reservations"] for i in r["Instances"]]
    ctx["config_history"] = _config_history(config_svc, "AWS::EC2::SecurityGroup", sg_id)
    if flow_log_group:
        ctx["network"] = network_activity(logs, flow_log_group,
                                          [i["id"] for i in ctx["attached_instances"]])
    return ctx


def _config_history(config_svc, rtype, rid, limit=5):
    hist = _safe(config_svc.get_resource_config_history, resourceType=rtype,
                 resourceId=rid, limit=limit)
    if "error" in hist:
        return hist
    return [{"captured": str(c.get("configurationItemCaptureTime")),
             "status": c.get("configurationItemStatus"),
             "change_by_event": (c.get("relatedEvents") or [None])[0]}
            for c in hist.get("configurationItems", [])]


# --------------------------------------------------------------- network
def network_activity(logs, log_group, terms, minutes=60):
    """Search VPC Flow Logs for traffic involving an IP or ENI and summarise
    accepted vs rejected flows and top talkers."""
    start = int((datetime.now(timezone.utc) - timedelta(minutes=minutes)).timestamp() * 1000)
    summary = {"accepted": 0, "rejected": 0, "bytes": 0, "top_peers": {}}
    for term in filter(None, terms):
        out = _safe(logs.filter_log_events, logGroupName=log_group,
                    filterPattern=f'"{term}"', startTime=start, limit=500)
        if "error" in out:
            summary["error"] = out["error"]
            continue
        for e in out.get("events", []):
            f = e["message"].split()
            # v2 format: ver acct eni src dst sport dport proto pkts bytes start end action status
            if len(f) < 14:
                continue
            summary["accepted" if f[12] == "ACCEPT" else "rejected"] += 1
            summary["bytes"] += int(f[9]) if f[9].isdigit() else 0
            peer = f[4] if f[3] == term else f[3]
            summary["top_peers"][peer] = summary["top_peers"].get(peer, 0) + 1
    summary["top_peers"] = dict(sorted(summary["top_peers"].items(), key=lambda kv: -kv[1])[:5])
    return summary


# --------------------------------------------------------------- orchestrator
def build_timeline(incident, extra_events=()):
    rows = []
    for ev in list(incident.evidence_events) + list(extra_events):
        rows.append({"time": ev.get("eventTime") or ev.get("time"),
                     "event": ev.get("eventName") or ev.get("event"),
                     "ip": ev.get("sourceIPAddress") or ev.get("ip"),
                     "error": ev.get("errorMessage")})
    rows.append({"time": incident.detected_at, "event": f"DETECTED:{incident.incident_type}", "ip": None})
    seen, uniq = set(), []
    for r in sorted(rows, key=lambda r: str(r["time"])):
        k = json.dumps(r, sort_keys=True, default=str)
        if k not in seen:
            seen.add(k)
            uniq.append(r)
    return uniq


def investigate(incident, clients, flow_log_group=None):
    rt = incident.resource_type
    if rt == "IAMUser":
        incident.investigation["identity"] = user_context(clients["iam"], clients["cloudtrail"],
                                                          incident.principal)
        if incident.source_ip and flow_log_group:
            incident.investigation["network"] = network_activity(clients["logs"], flow_log_group,
                                                                 [incident.source_ip])
        recent = incident.investigation["identity"].get("recent_activity", [])
    elif rt == "S3Bucket":
        incident.investigation["resource"] = bucket_context(clients["s3"], clients["config"],
                                                            incident.resource_id)
        recent = []
    elif rt == "SecurityGroup":
        incident.investigation["resource"] = security_group_context(
            clients["ec2"], clients["config"], clients["logs"], incident.resource_id, flow_log_group)
        recent = []
    else:
        recent = []
    incident.investigation["timeline"] = build_timeline(incident, recent)
    incident.investigation["risk_notes"] = _risk_notes(incident)
    incident.status = "INVESTIGATED"
    return incident


def _risk_notes(inc):
    notes = []
    ident = inc.investigation.get("identity", {})
    res = inc.investigation.get("resource", {})
    if ident.get("is_admin"):
        notes.append("Principal holds administrator permissions: blast radius is the whole account.")
    if ident and ident.get("mfa_devices") == 0:
        notes.append("No MFA device registered for this user.")
    if any(k["status"] == "Active" for k in ident.get("access_keys", [])):
        notes.append("User has active programmatic access keys.")
    if res.get("data_classification") in ("Confidential", "PCI", "Restricted"):
        notes.append(f"Bucket holds {res['data_classification']} data: possible regulatory notification.")
    if res.get("encryption") == "none":
        notes.append("Default encryption is not enabled on this bucket.")
    if any(i.get("public_ip") for i in res.get("attached_instances", [])):
        notes.append("Instances behind this group have public IPs and were directly reachable.")
    return notes
