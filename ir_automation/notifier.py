"""Notification layer: severity based routing, structured message, escalation."""
import json

from . import config

REMEDIATION = {
    "BRUTE_FORCE_LOGIN": [
        "Confirm with the user whether they were locked out or traveling.",
        "Force a password reset and require MFA enrolment before re-enabling.",
        "Add the source IP to the WAF / IP deny list if it is not a corporate address.",
        "If CRITICAL: review every API call the session made after the successful login."],
    "UNUSUAL_LOCATION_LOGIN": [
        "Contact the user out of band (phone, not email) to confirm the login.",
        "If unconfirmed: rotate password and keys, revoke active sessions, keep quarantine.",
        "If confirmed travel: remove the deny policy and add a time bound IP exception."],
    "MASS_DELETION": [
        "Keep the principal quarantined and identify the credential that was used.",
        "Restore deleted objects from versioning or AWS Backup; check S3 delete markers.",
        "Review whether deletion protection and MFA delete are enabled on critical resources."],
    "PRIVILEGE_ESCALATION": [
        "Detach the newly granted policy and delete any access keys created in the window.",
        "Determine how the actor obtained iam:* rights and remove that path.",
        "Add an SCP or permission boundary that blocks self escalation."],
    "PUBLIC_S3_BUCKET": [
        "Confirm with the owner whether any public access is a business requirement.",
        "Review S3 server access logs / CloudTrail data events for anonymous GetObject calls.",
        "If regulated data was exposed, open a privacy / breach assessment ticket.",
        "Enable account level S3 Block Public Access to stop recurrence."],
    "OPEN_SECURITY_GROUP": [
        "Replace the removed rule with a scoped CIDR or AWS Systems Manager Session Manager.",
        "Inspect forensic snapshots and flow logs for successful connections from the internet.",
        "Rebuild isolated instances from a known good AMI rather than cleaning them in place."],
}

ROUTING = {  # who gets paged, by severity
    "CRITICAL": ["On call incident commander (page)", "SOC channel", "CISO (email)"],
    "HIGH": ["SOC channel", "On call analyst"],
    "MEDIUM": ["SOC ticket queue"],
    "LOW": ["Daily digest"],
}


def build_message(inc):
    ident = inc.investigation.get("identity", {})
    res = inc.investigation.get("resource", {})
    actions = [a for a in inc.containment if a["action"] != "PRESERVE_EVIDENCE"]
    evidence = [a["target"] for a in inc.containment if a["action"] == "PRESERVE_EVIDENCE"]
    subject = f"[{inc.severity}] {inc.incident_type} | {inc.resource_id} | {inc.incident_id}"[:100]
    body = {
        "incident_id": inc.incident_id, "severity": inc.severity, "type": inc.incident_type,
        "detected_at": inc.detected_at, "summary": inc.summary,
        "resource": {"type": inc.resource_type, "id": inc.resource_id,
                     "owner": res.get("owner") or ident.get("arn")},
        "actor": {"principal": inc.principal, "source_ip": inc.source_ip,
                  "is_admin": ident.get("is_admin"), "mfa_devices": ident.get("mfa_devices")},
        "findings": inc.investigation.get("risk_notes", []),
        "containment_status": inc.status,
        "containment_actions": [f"{a['action']} -> {a['target']} ({a['result']})" for a in actions],
        "evidence_locations": evidence,
        "suggested_remediation": REMEDIATION.get(inc.incident_type, []),
        "routed_to": ROUTING[inc.severity],
        "ack_sla_minutes": config.ACK_SLA_MIN[inc.severity],
        "runbook": f"https://wiki.example.internal/ir/playbooks/{inc.incident_type.lower()}",
    }
    return subject, body


def render_text(subject, body):
    lines = [subject, "=" * len(subject), body["summary"], "",
             f"Severity: {body['severity']}   Status: {body['containment_status']}",
             f"Actor: {body['actor']['principal'] or 'n/a'} from {body['actor']['source_ip'] or 'n/a'}",
             "", "Findings:"] + [f"  - {f}" for f in body["findings"] or ["none"]]
    lines += ["", "Containment actions:"] + [f"  - {a}" for a in body["containment_actions"]]
    lines += ["", "Suggested remediation:"] + [f"  {i}. {s}" for i, s in
                                                enumerate(body["suggested_remediation"], 1)]
    lines += ["", f"Acknowledge within {body['ack_sla_minutes']} min. Runbook: {body['runbook']}"]
    return "\n".join(lines)


def notify(sns, inc):
    subject, body = build_message(inc)
    topic = config.SNS_TOPICS.get(inc.severity)
    if topic:
        # JSON for machine consumers (SOAR / ticketing), text for email and chat
        sns.publish(TopicArn=topic, Subject=subject, MessageStructure="json",
                    Message=json.dumps({"default": json.dumps(body, default=str),
                                        "email": render_text(subject, body)}),
                    MessageAttributes={
                        "severity": {"DataType": "String", "StringValue": inc.severity},
                        "incident_type": {"DataType": "String", "StringValue": inc.incident_type}})
    inc.status = inc.status + "+NOTIFIED"
    return subject, body


def escalation_target(severity, minutes_unacked):
    """Escalate one tier for every SLA period an alert sits unacknowledged."""
    tiers = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    idx = tiers.index(severity)
    steps = minutes_unacked // config.ACK_SLA_MIN[severity]
    return tiers[min(idx + steps, 3)]
