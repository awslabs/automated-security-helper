# ASH Security Scan Report

- **Report generated**: 2026-01-15T12:00:42+00:00
- **Time since scan**: 0 minutes

## Scan Metadata

- **Project**: ASH
- **Scan executed**: 2026-01-15T12:00:00+00:00
- **ASH version**: <ASH_VERSION>

## Summary

### Scanner Results

The table below shows findings by scanner, with status based on severity thresholds and dependencies:

- **Severity levels**:
  - **Suppressed (S)**: Findings that have been explicitly suppressed and don't affect scanner status
  - **Critical (C)**: Highest severity findings that require immediate attention
  - **High (H)**: Serious findings that should be addressed soon
  - **Medium (M)**: Moderate risk findings
  - **Low (L)**: Lower risk findings
  - **Info (I)**: Informational findings with minimal risk
- **Actionable**: Number of findings at or above the threshold severity level that require attention
- **Result**:
  - **PASSED** = No findings at or above threshold
  - **FAILED** = Findings at or above threshold
  - **MISSING** = Required dependencies not available
  - **SKIPPED** = Scanner explicitly disabled
  - **ERROR** = Scanner execution error
- **Threshold**: The minimum severity level that will cause a scanner to fail
  - Thresholds: ALL, LOW, MEDIUM, HIGH, CRITICAL
  - Source: Values in parentheses indicate where the threshold is set:
    - `global` (global_settings section in the ASH_CONFIG used)
    - `config` (scanner config section in the ASH_CONFIG used)
    - `scanner` (default configuration in the plugin, if explicitly set)
- **Statistics calculation**:
  - All statistics are calculated from the final aggregated SARIF report
  - Suppressed findings are counted separately and do not contribute to actionable findings
  - Scanner status is determined by comparing actionable findings to the threshold

| Scanner | Suppressed | Critical | High | Medium | Low | Info | Actionable | Result | Threshold |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| cfn-guard | 0 | 0 | 24 | 0 | 0 | 0 | 24 | FAILED | MEDIUM (global) |
| cfn-lint | 0 | 0 | 0 | 2 | 1 | 0 | 2 | FAILED | MEDIUM (global) |

### Top 1 Hotspots

Files with the highest number of security findings:

| Finding Count | File Location |
| ---: | --- |
| 26 | templates/insecure.yaml |

<h2>Detailed Findings</h2>

<details>
<summary>Show 20 of 26 actionable findings</summary>

### Finding 1: LAMBDA_INSIDE_VPC

- **Severity**: HIGH
- **Scanner**: cfn-guard
- **Rule ID**: LAMBDA_INSIDE_VPC
- **Location**: templates/insecure.yaml:13

**Description**:
Check was not compliant as property [VpcConfig.SecurityGroupIds] is missing. Value traversed to [Path=/Resources/LegacyFunction/Properties[L:13,C:6] Value={"Runtime":"python2.7","Handler":"index.handler","Role":"arn:aws:iam::123456789012:role/example","Code":{"ZipFile":"def handler(event, context): return None"}}].

---

### Finding 2: LAMBDA_INSIDE_VPC

- **Severity**: HIGH
- **Scanner**: cfn-guard
- **Rule ID**: LAMBDA_INSIDE_VPC
- **Location**: templates/insecure.yaml:13

**Description**:
Check was not compliant as property [VpcConfig.SubnetIds] is missing. Value traversed to [Path=/Resources/LegacyFunction/Properties[L:13,C:6] Value={"Runtime":"python2.7","Handler":"index.handler","Role":"arn:aws:iam::123456789012:role/example","Code":{"ZipFile":"def handler(event, context): return None"}}].
    Guard Rule Set: wa-Security-Pillar
    Controls: SEC-3.7,SEC-5.2,SEC-5.3
    Violation:  All AWS Lambda Functions must be configured with access to a VPC
    Fix: set the VpcConfig.SecurityGroupIds and VpcConfig.SubnetIds parameters with a list of security groups and subnets.
    Lambda creates an elastic network interface for each combination of security group and subnet in the function's VPC configuration.

---

### Finding 3: S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED

- **Severity**: HIGH
- **Scanner**: cfn-guard
- **Rule ID**: S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED
- **Location**: templates/insecure.yaml:9

**Description**:
Check was not compliant as property [PublicAccessBlockConfiguration] is missing. Value traversed to [Path=/Resources/OpenBucket/Properties[L:9,C:6] Value={"BucketNam":"misspelled-on-purpose"}].

---

### Finding 4: S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED

- **Severity**: HIGH
- **Scanner**: cfn-guard
- **Rule ID**: S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED
- **Location**: templates/insecure.yaml:9

**Description**:
Check was not compliant as property [PublicAccessBlockConfiguration.BlockPublicAcls] to compare from is missing. Value traversed to [Path=/Resources/OpenBucket/Properties[L:9,C:6] Value={"BucketNam":"misspelled-on-purpose"}].

---

### Finding 5: S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED

- **Severity**: HIGH
- **Scanner**: cfn-guard
- **Rule ID**: S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED
- **Location**: templates/insecure.yaml:9

**Description**:
Check was not compliant as property [PublicAccessBlockConfiguration.BlockPublicPolicy] to compare from is missing. Value traversed to [Path=/Resources/OpenBucket/Properties[L:9,C:6] Value={"BucketNam":"misspelled-on-purpose"}].

---

### Finding 6: S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED

- **Severity**: HIGH
- **Scanner**: cfn-guard
- **Rule ID**: S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED
- **Location**: templates/insecure.yaml:9

**Description**:
Check was not compliant as property [PublicAccessBlockConfiguration.IgnorePublicAcls] to compare from is missing. Value traversed to [Path=/Resources/OpenBucket/Properties[L:9,C:6] Value={"BucketNam":"misspelled-on-purpose"}].

---

### Finding 7: S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED

- **Severity**: HIGH
- **Scanner**: cfn-guard
- **Rule ID**: S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED
- **Location**: templates/insecure.yaml:9

**Description**:
Check was not compliant as property [PublicAccessBlockConfiguration.RestrictPublicBuckets] to compare from is missing. Value traversed to [Path=/Resources/OpenBucket/Properties[L:9,C:6] Value={"BucketNam":"misspelled-on-purpose"}].
    Guard Rule Set: wa-Security-Pillar
    Controls: SEC-3.7,SEC-5.3,SEC-8.4
    Violation: S3 Bucket Public Access controls need to be restricted.
    Fix: Set S3 Bucket PublicAccessBlockConfiguration properties for BlockPublicAcls, BlockPublicPolicy, IgnorePublicAcls, RestrictPublicBuckets parameters to true.

---

### Finding 8: S3_BUCKET_PUBLIC_READ_PROHIBITED

- **Severity**: HIGH
- **Scanner**: cfn-guard
- **Rule ID**: S3_BUCKET_PUBLIC_READ_PROHIBITED
- **Location**: templates/insecure.yaml:9

**Description**:
Check was not compliant as property [PublicAccessBlockConfiguration] is missing. Value traversed to [Path=/Resources/OpenBucket/Properties[L:9,C:6] Value={"BucketNam":"misspelled-on-purpose"}].

---

### Finding 9: S3_BUCKET_PUBLIC_READ_PROHIBITED

- **Severity**: HIGH
- **Scanner**: cfn-guard
- **Rule ID**: S3_BUCKET_PUBLIC_READ_PROHIBITED
- **Location**: templates/insecure.yaml:9

**Description**:
Check was not compliant as property [PublicAccessBlockConfiguration.BlockPublicAcls] to compare from is missing. Value traversed to [Path=/Resources/OpenBucket/Properties[L:9,C:6] Value={"BucketNam":"misspelled-on-purpose"}].

---

### Finding 10: S3_BUCKET_PUBLIC_READ_PROHIBITED

- **Severity**: HIGH
- **Scanner**: cfn-guard
- **Rule ID**: S3_BUCKET_PUBLIC_READ_PROHIBITED
- **Location**: templates/insecure.yaml:9

**Description**:
Check was not compliant as property [PublicAccessBlockConfiguration.BlockPublicPolicy] to compare from is missing. Value traversed to [Path=/Resources/OpenBucket/Properties[L:9,C:6] Value={"BucketNam":"misspelled-on-purpose"}].

---

### Finding 11: S3_BUCKET_PUBLIC_READ_PROHIBITED

- **Severity**: HIGH
- **Scanner**: cfn-guard
- **Rule ID**: S3_BUCKET_PUBLIC_READ_PROHIBITED
- **Location**: templates/insecure.yaml:9

**Description**:
Check was not compliant as property [PublicAccessBlockConfiguration.IgnorePublicAcls] to compare from is missing. Value traversed to [Path=/Resources/OpenBucket/Properties[L:9,C:6] Value={"BucketNam":"misspelled-on-purpose"}].

---

### Finding 12: S3_BUCKET_PUBLIC_READ_PROHIBITED

- **Severity**: HIGH
- **Scanner**: cfn-guard
- **Rule ID**: S3_BUCKET_PUBLIC_READ_PROHIBITED
- **Location**: templates/insecure.yaml:9

**Description**:
Check was not compliant as property [PublicAccessBlockConfiguration.RestrictPublicBuckets] to compare from is missing. Value traversed to [Path=/Resources/OpenBucket/Properties[L:9,C:6] Value={"BucketNam":"misspelled-on-purpose"}].
    Guard Rule Set: wa-Security-Pillar
    Controls: SEC-3.7,SEC-5.3,SEC-8.4
    Violation: S3 Bucket Public Write Access controls need to be restricted.
    Fix: Set S3 Bucket PublicAccessBlockConfiguration properties for BlockPublicAcls, BlockPublicPolicy, IgnorePublicAcls, RestrictPublicBuckets parameters to true.

---

### Finding 13: S3_BUCKET_PUBLIC_WRITE_PROHIBITED

- **Severity**: HIGH
- **Scanner**: cfn-guard
- **Rule ID**: S3_BUCKET_PUBLIC_WRITE_PROHIBITED
- **Location**: templates/insecure.yaml:9

**Description**:
Check was not compliant as property [PublicAccessBlockConfiguration] is missing. Value traversed to [Path=/Resources/OpenBucket/Properties[L:9,C:6] Value={"BucketNam":"misspelled-on-purpose"}].

---

### Finding 14: S3_BUCKET_PUBLIC_WRITE_PROHIBITED

- **Severity**: HIGH
- **Scanner**: cfn-guard
- **Rule ID**: S3_BUCKET_PUBLIC_WRITE_PROHIBITED
- **Location**: templates/insecure.yaml:9

**Description**:
Check was not compliant as property [PublicAccessBlockConfiguration.BlockPublicAcls] to compare from is missing. Value traversed to [Path=/Resources/OpenBucket/Properties[L:9,C:6] Value={"BucketNam":"misspelled-on-purpose"}].

---

### Finding 15: S3_BUCKET_PUBLIC_WRITE_PROHIBITED

- **Severity**: HIGH
- **Scanner**: cfn-guard
- **Rule ID**: S3_BUCKET_PUBLIC_WRITE_PROHIBITED
- **Location**: templates/insecure.yaml:9

**Description**:
Check was not compliant as property [PublicAccessBlockConfiguration.BlockPublicPolicy] to compare from is missing. Value traversed to [Path=/Resources/OpenBucket/Properties[L:9,C:6] Value={"BucketNam":"misspelled-on-purpose"}].

---

### Finding 16: S3_BUCKET_PUBLIC_WRITE_PROHIBITED

- **Severity**: HIGH
- **Scanner**: cfn-guard
- **Rule ID**: S3_BUCKET_PUBLIC_WRITE_PROHIBITED
- **Location**: templates/insecure.yaml:9

**Description**:
Check was not compliant as property [PublicAccessBlockConfiguration.IgnorePublicAcls] to compare from is missing. Value traversed to [Path=/Resources/OpenBucket/Properties[L:9,C:6] Value={"BucketNam":"misspelled-on-purpose"}].

---

### Finding 17: S3_BUCKET_PUBLIC_WRITE_PROHIBITED

- **Severity**: HIGH
- **Scanner**: cfn-guard
- **Rule ID**: S3_BUCKET_PUBLIC_WRITE_PROHIBITED
- **Location**: templates/insecure.yaml:9

**Description**:
Check was not compliant as property [PublicAccessBlockConfiguration.RestrictPublicBuckets] to compare from is missing. Value traversed to [Path=/Resources/OpenBucket/Properties[L:9,C:6] Value={"BucketNam":"misspelled-on-purpose"}].
    Guard Rule Set: wa-Security-Pillar
    Controls: SEC-3.7,SEC-5.3,SEC-8.4
    Violation: S3 Bucket Public Write Access controls need to be restricted.
    Fix: Set S3 Bucket PublicAccessBlockConfiguration properties for BlockPublicAcls, BlockPublicPolicy, IgnorePublicAcls, RestrictPublicBuckets parameters to true.

---

### Finding 18: S3_BUCKET_LOGGING_ENABLED

- **Severity**: HIGH
- **Scanner**: cfn-guard
- **Rule ID**: S3_BUCKET_LOGGING_ENABLED
- **Location**: templates/insecure.yaml:9

**Description**:
Check was not compliant as property [LoggingConfiguration] is missing. Value traversed to [Path=/Resources/OpenBucket/Properties[L:9,C:6] Value={"BucketNam":"misspelled-on-purpose"}].
    Guard Rule Set: wa-Security-Pillar
    Controls: SEC-4.2
    Violation: S3 Bucket Logging needs to be configured to enable logging.
    Fix: Set the S3 Bucket property LoggingConfiguration to start logging into S3 bucket.

---

### Finding 19: S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED

- **Severity**: HIGH
- **Scanner**: cfn-guard
- **Rule ID**: S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED
- **Location**: templates/insecure.yaml:9

**Description**:
Check was not compliant as property [BucketEncryption] is missing. Value traversed to [Path=/Resources/OpenBucket/Properties[L:9,C:6] Value={"BucketNam":"misspelled-on-purpose"}].

---

### Finding 20: S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED

- **Severity**: HIGH
- **Scanner**: cfn-guard
- **Rule ID**: S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED
- **Location**: templates/insecure.yaml:9

**Description**:
Check was not compliant as property [BucketEncryption.ServerSideEncryptionConfiguration[*].ServerSideEncryptionByDefault.SSEAlgorithm] to compare from is missing. Value traversed to [Path=/Resources/OpenBucket/Properties[L:9,C:6] Value={"BucketNam":"misspelled-on-purpose"}].
    Guard Rule Set: wa-Security-Pillar
    Controls: SEC-8.3
    Violation: S3 Bucket must enable server-side encryption.
    Fix: Set the S3 Bucket property BucketEncryption.ServerSideEncryptionConfiguration.ServerSideEncryptionByDefault.SSEAlgorithm to either "aws:kms" or "AES256"


> Note: Showing 20 of 26 total actionable findings. Configure `max_detailed_findings` to adjust this limit.

</details>

---

*Report generated by [Automated Security Helper (ASH)](https://github.com/awslabs/automated-security-helper) at 2026-01-15T12:00:42+00:00*
