# Automated Security Incident Response (AWS)

Detect, investigate, contain and notify for six incident types:
brute force login, unusual location login, mass deletion, privilege escalation,
public S3 bucket, and internet exposed security group.

## Layout
```
ir_automation/
  config.py        thresholds and routing (all overridable by env vars)
  models.py        Incident record + SHA-256 fingerprint
  detectors.py     event detectors (CloudTrail) and posture detectors (S3, EC2)
  investigator.py  identity, resource, config history, flow log, timeline enrichment
  containment.py   evidence preservation and reversible containment playbooks
  notifier.py      severity routing, structured SNS message, escalation
  handler.py       Lambda entry point and pipeline
tests/             36 pytest cases against moto (mocked AWS)
deploy/template.yaml  SAM template: Lambda, EventBridge rules, SNS, locked evidence bucket
```

## Run the tests
```
pip install boto3 "moto[all]" pytest
python -m pytest -v tests
```

## Deploy
1. Enable an organization CloudTrail trail, AWS Config recorder and VPC Flow Logs to CloudWatch Logs.
2. `sam build -t deploy/template.yaml && sam deploy --guided`
   (supply SocEmail, PagerEndpoint, FlowLogGroup; leave DryRun=true for the first two weeks).
3. Confirm the SNS email subscriptions.
4. Review audit entries in CloudWatch Logs (`ir_audit`) and the evidence bucket, tune
   thresholds with env vars, then redeploy with DryRun=false.

## Rollback of a containment action
* IAM user: `aws iam delete-user-policy --user-name X --policy-name IR-Quarantine-DenyAll`, reactivate keys.
* Instance: `aws ec2 modify-instance-attribute --instance-id I --groups <previous_sgs from audit entry>`.
* Security group / bucket: reapply the configuration stored in the evidence bucket if the exposure was intended.
