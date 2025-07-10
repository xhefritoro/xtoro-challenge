# Sentra Scanner - Operational Runbook
## Production Operations & Troubleshooting Guide

### Table of Contents
1. [System Overview](#system-overview)
2. [Monitoring & Alerting](#monitoring--alerting)
3. [Common Issues & Resolution](#common-issues--resolution)
4. [Performance Tuning](#performance-tuning)
5. [Security Incident Response](#security-incident-response)
6. [Disaster Recovery](#disaster-recovery)

---

## System Overview

### Architecture Components
- **Lambda Function**: Core email scanning engine
- **S3 Event Triggers**: File upload notifications
- **SQS Queue**: Cross-account message delivery to Sentra
- **CloudWatch**: Monitoring, logging, and alerting
- **IAM Roles**: Least-privilege access control

### Key Metrics to Monitor
| Metric | Normal Range | Alert Threshold | Critical Threshold |
|--------|--------------|-----------------|-------------------|
| Processing Duration | < 30s | > 60s | > 240s |
| Error Rate | < 1% | > 5% | > 10% |
| Memory Utilization | < 80% | > 90% | > 95% |
| SQS Message Failures | 0 | > 1 | > 5 |
| File Processing Rate | Variable | N/A | 0 files/hour |

---

## Monitoring & Alerting

### CloudWatch Dashboards

#### Primary Dashboard Widgets
```bash
# CPU and Memory Utilization
aws cloudwatch get-dashboard \
  --dashboard-name "SentraScanner-Production" \
  --region us-east-1

# Custom Metrics
aws cloudwatch get-metric-statistics \
  --namespace "Sentra/EmailScanner" \
  --metric-name "EmailsFound" \
  --start-time 2025-07-08T00:00:00Z \
  --end-time 2025-07-08T23:59:59Z \
  --period 3600 \
  --statistics Sum
```

#### Key Alarms
1. **Lambda Errors Alarm**
   - Metric: `AWS/Lambda/Errors`
   - Threshold: > 5 errors in 5 minutes
   - Action: SNS notification to on-call team

2. **Lambda Duration Alarm**
   - Metric: `AWS/Lambda/Duration`
   - Threshold: > 240,000ms (4 minutes)
   - Action: Auto-scaling trigger

3. **SQS Message Failures**
   - Metric: `Sentra/EmailScanner/ProcessingErrors`
   - Threshold: > 1 failure in 5 minutes
   - Action: Escalation to engineering team

### Log Analysis Queries

#### Find Processing Errors
```bash
# CloudWatch Insights query
aws logs start-query \
  --log-group-name "/aws/lambda/customer-sentra-scanner" \
  --start-time 1688774400 \
  --end-time 1688860800 \
  --query-string '
    fields @timestamp, @message
    | filter @message like /ERROR/
    | sort @timestamp desc
    | limit 100
  '
```

#### Analyze Processing Performance
```bash
# Performance analysis query
aws logs start-query \
  --log-group-name "/aws/lambda/customer-sentra-scanner" \
  --start-time 1688774400 \
  --end-time 1688860800 \
  --query-string '
    fields @timestamp, @duration, @message
    | filter @message like /Successfully processed/
    | stats avg(@duration), max(@duration), min(@duration) by bin(5m)
  '
```

---

## Common Issues & Resolution

### Issue 1: Lambda Timeout Errors

#### Symptoms
- CloudWatch logs show "Task timed out after X seconds"
- Files not being processed completely
- SQS messages not being sent

#### Diagnosis
```bash
# Check average processing duration
aws cloudwatch get-metric-statistics \
  --namespace "AWS/Lambda" \
  --metric-name "Duration" \
  --dimensions Name=FunctionName,Value=customer-sentra-scanner \
  --start-time $(date -d '1 hour ago' -u +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Average,Maximum
```

#### Resolution
1. **Immediate**: Increase Lambda timeout
   ```bash
   aws lambda update-function-configuration \
     --function-name customer-sentra-scanner \
     --timeout 600  # 10 minutes
   ```

2. **Long-term**: Optimize processing
   - Implement file size pre-filtering
   - Add parallel processing for large files
   - Consider batch processing architecture

### Issue 2: SQS Message Delivery Failures

#### Symptoms
- Error logs: "Failed to send results"
- Messages not appearing in Sentra queue
- Retry exhaustion errors

#### Diagnosis
```bash
# Check SQS queue access
aws sqs get-queue-attributes \
  --queue-url $SENTRA_SQS_QUEUE_URL \
  --attribute-names ApproximateNumberOfMessages,LastModifiedTimestamp

# Test message sending
aws sqs send-message \
  --queue-url $SENTRA_SQS_QUEUE_URL \
  --message-body "Test message from $(hostname)"
```

#### Resolution
1. **Check IAM permissions**
   ```bash
   aws iam simulate-principal-policy \
     --policy-source-arn arn:aws:iam::ACCOUNT:role/lambda-execution-role \
     --action-names sqs:SendMessage \
     --resource-arns $SENTRA_SQS_QUEUE_ARN
   ```

2. **Verify cross-account access**
   - Confirm external ID matches
   - Check SQS queue policy allows cross-account access
   - Validate Sentra account ID

3. **Enable dead letter queue**
   ```bash
   aws sqs set-queue-attributes \
     --queue-url $SENTRA_SQS_QUEUE_URL \
     --attributes RedrivePolicy='{"deadLetterTargetArn":"arn:aws:sqs:region:account:dlq","maxReceiveCount":"3"}'
   ```

### Issue 3: High Memory Usage

#### Symptoms
- Lambda memory utilization > 90%
- Out of memory errors
- Slow processing of large files

#### Diagnosis
```bash
# Memory utilization analysis
aws logs start-query \
  --log-group-name "/aws/lambda/customer-sentra-scanner" \
  --start-time $(date -d '1 hour ago' +%s) \
  --end-time $(date +%s) \
  --query-string '
    fields @timestamp, @maxMemoryUsed, @memorySize
    | filter @type = "REPORT"
    | stats max(@maxMemoryUsed), avg(@maxMemoryUsed) by bin(5m)
  '
```

#### Resolution
1. **Immediate**: Increase memory allocation
   ```bash
   aws lambda update-function-configuration \
     --function-name customer-sentra-scanner \
     --memory-size 1024  # Increase to 1GB
   ```

2. **Optimization**:
   - Implement streaming file processing
   - Add garbage collection hints
   - Process files in chunks

### Issue 4: S3 Access Denied Errors

#### Symptoms
- Error logs: "AccessDenied" or "NoSuchKey"
- Files not being processed despite S3 events
- Inconsistent processing behavior

#### Diagnosis
```bash
# Test S3 access
aws s3api head-object \
  --bucket $BUCKET_NAME \
  --key $OBJECT_KEY

# Check IAM permissions
aws iam get-role-policy \
  --role-name lambda-execution-role \
  --policy-name lambda-s3-policy
```

#### Resolution
1. **Verify bucket permissions**
   ```bash
   aws s3api get-bucket-policy --bucket $BUCKET_NAME
   ```

2. **Check object-level permissions**
   ```bash
   aws s3api get-object-acl --bucket $BUCKET_NAME --key $OBJECT_KEY
   ```

3. **Update IAM policy if needed**
   - Ensure `s3:GetObject` and `s3:GetObjectVersion` permissions
   - Verify resource ARN matches bucket pattern

---

## Performance Tuning

### Lambda Optimization

#### Memory vs Performance Analysis
```bash
# Test different memory configurations
for memory in 512 1024 1536 2048; do
  aws lambda update-function-configuration \
    --function-name customer-sentra-scanner \
    --memory-size $memory
  
  # Run test and measure performance
  echo "Testing with ${memory}MB memory"
  # Add your test commands here
done
```

#### Concurrency Management
```bash
# Set reserved concurrency to prevent throttling
aws lambda put-reserved-concurrency \
  --function-name customer-sentra-scanner \
  --reserved-concurrent-executions 100

# Monitor concurrency usage
aws cloudwatch get-metric-statistics \
  --namespace "AWS/Lambda" \
  --metric-name "ConcurrentExecutions" \
  --dimensions Name=FunctionName,Value=customer-sentra-scanner \
  --start-time $(date -d '1 hour ago' -u +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Maximum,Average
```

### Cost Optimization

#### Analyze Processing Costs
```bash
# Get Lambda invocation metrics
aws cloudwatch get-metric-statistics \
  --namespace "AWS/Lambda" \
  --metric-name "Invocations" \
  --dimensions Name=FunctionName,Value=customer-sentra-scanner \
  --start-time $(date -d '30 days ago' -u +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 86400 \
  --statistics Sum

# Calculate monthly costs
# Formula: Invocations × Duration × Memory × $0.0000166667 per GB-second
```

---

## Security Incident Response

### Incident Types & Response

#### 1. Unauthorized Access Attempt
**Detection**: CloudTrail logs show failed authentication
**Response**:
```bash
# Check recent access attempts
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time $(date -d '24 hours ago' -u +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S)

# Rotate IAM credentials if compromised
aws iam update-access-key \
  --access-key-id $ACCESS_KEY_ID \
  --status Inactive
```

#### 2. Data Exfiltration Concern
**Detection**: Unusual SQS message patterns or large data transfers
**Response**:
```bash
# Check SQS message sizes
aws sqs get-queue-attributes \
  --queue-url $SENTRA_SQS_QUEUE_URL \
  --attribute-names ApproximateNumberOfMessages

# Review recent Lambda executions
aws logs filter-log-events \
  --log-group-name "/aws/lambda/customer-sentra-scanner" \
  --start-time $(date -d '24 hours ago' +%s)000 \
  --filter-pattern "ERROR"
```

#### 3. Service Compromise
**Response**:
1. **Immediate isolation**
   ```bash
   # Disable Lambda function
   aws lambda update-function-configuration \
     --function-name customer-sentra-scanner \
     --environment Variables='{DISABLED=true}'
   ```

2. **Forensic analysis**
   ```bash
   # Export CloudWatch logs
   aws logs create-export-task \
     --log-group-name "/aws/lambda/customer-sentra-scanner" \
     --from $(date -d '7 days ago' +%s)000 \
     --to $(date +%s)000 \
     --destination s3-bucket-for-forensics
   ```

---

## Disaster Recovery

### Backup Procedures

#### Infrastructure Backup
```bash
# Export Terraform state
terraform state pull > backup-$(date +%Y%m%d).tfstate

# Backup Lambda function code
aws lambda get-function \
  --function-name customer-sentra-scanner \
  --query 'Code.Location' \
  --output text | xargs wget -O lambda-backup-$(date +%Y%m%d).zip
```

#### Configuration Backup
```bash
# Export Lambda configuration
aws lambda get-function-configuration \
  --function-name customer-sentra-scanner > lambda-config-backup.json

# Export IAM policies
aws iam get-role-policy \
  --role-name lambda-execution-role \
  --policy-name lambda-s3-policy > iam-policy-backup.json
```

### Recovery Procedures

#### Complete Environment Recovery
```bash
# 1. Restore infrastructure
cd terraform
terraform init
terraform plan
terraform apply

# 2. Restore Lambda function
aws lambda update-function-code \
  --function-name customer-sentra-scanner \
  --zip-file fileb://lambda-backup-YYYYMMDD.zip

# 3. Restore configuration
aws lambda update-function-configuration \
  --function-name customer-sentra-scanner \
  --cli-input-json file://lambda-config-backup.json

# 4. Verify functionality
echo "Test email: recovery-test@example.com" > recovery-test.txt
aws s3 cp recovery-test.txt s3://$BUCKET_NAME/
```

### RTO/RPO Targets
- **Recovery Time Objective (RTO)**: 4 hours
- **Recovery Point Objective (RPO)**: 1 hour
- **Maximum Tolerable Downtime**: 8 hours

---

## Emergency Contacts

| Role | Primary | Secondary | Escalation |
|------|---------|-----------|------------|
| On-Call Engineer | +1-555-0101 | +1-555-0102 | Engineering Manager |
| Security Team | security@company.com | CISO | Legal/Compliance |
| Sentra Support | support@sentra.com | Account Manager | Technical Lead |

## Runbook Maintenance

This runbook should be:
- Reviewed monthly by the operations team
- Updated after each incident
- Tested quarterly through disaster recovery drills
- Version controlled with infrastructure code

