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
scripts/           simulate.py and cleanup.py for a live lab test
deploy/template.yaml  SAM template: Lambda, EventBridge rules, SNS, locked evidence bucket
```

## Run the tests
```
pip install boto3 "moto[all]" pytest
python -m pytest -v tests
```

## Deploy
1. Optional but recommended: a CloudTrail trail (needed for the real time EventBridge rule; the
   5 minute sweep works from CloudTrail Event history without one), AWS Config, VPC Flow Logs.
2. `sam build -t deploy/template.yaml && sam deploy --guided`
   (supply SocEmail and a stack name; leave DryRun=true at first).
3. Confirm the SNS email subscriptions.
4. Review audit entries in CloudWatch Logs (`ir_audit`) and the evidence bucket, tune
   thresholds with env vars, then redeploy with DryRun=false.

## Rollback of a containment action
* IAM user: `aws iam delete-user-policy --user-name X --policy-name IR-Quarantine-DenyAll`, reactivate keys.
* Instance: `aws ec2 modify-instance-attribute --instance-id I --groups <previous_sgs from audit entry>`.
* Security group / bucket: reapply the configuration stored in the evidence bucket if the exposure was intended.

## Live lab test (real AWS account)
Use a lab or sandbox account. With DryRun=false the responder WILL lock down any public bucket or
internet exposed security group it finds in the region, not only the test ones.

```
python3 scripts/simulate.py                 # creates 3 tagged test incidents
# wait about 10 minutes for CloudTrail
aws lambda invoke --function-name <FunctionName output> \
    --cli-binary-format raw-in-base64-out \
    --payload '{"source":"aws.events","lookback_min":60,"dry_run":true}' out.json && cat out.json
# review what it WOULD do, then run again with "dry_run":false
aws s3 ls s3://<EvidenceBucketName output> --recursive   # evidence written per incident
python3 scripts/cleanup.py                  # remove the test resources
sam delete                                  # remove the stack (after evidence retention expires)
```
