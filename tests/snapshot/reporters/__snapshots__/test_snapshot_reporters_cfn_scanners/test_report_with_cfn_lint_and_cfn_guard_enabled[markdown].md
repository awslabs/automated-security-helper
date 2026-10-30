# ASH security scan report

> [!CAUTION]
> **Review required**
>
> 26 findings at or above the configured scanner thresholds.
>
> **26 actionable** · 1 below threshold · 0 suppressed · 2/2 scanners completed
>
> Next action: Review findings by severity, then inspect the source.

Project: ASH · Scan executed: 2026-01-15T12:00:00+00:00

## Summary

### Scanner results

| Scanner | Suppressed | Critical | High | Medium | Low | Info | Actionable | Result | Threshold |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| cfn-guard | 0 | 0 | 24 | 0 | 0 | 0 | 24 | FAILED | MEDIUM (global) |
| cfn-lint | 0 | 0 | 0 | 2 | 1 | 0 | 2 | FAILED | MEDIUM (global) |

<details>
<summary>How to read scanner results</summary>

**Severity levels:** Critical, High, Medium, Low, Info. Suppressed findings are counted separately.

**Actionable** counts findings at or above each scanner's threshold.

**Result:** PASSED = no actionable findings; FAILED = threshold exceeded; MISSING = dependencies unavailable; SKIPPED = did not run (disabled, or nothing to scan); ERROR = execution error.

**Threshold** shows the minimum severity and its source: `global`, `config`, or `scanner`.

**Statistics calculation:** final aggregated SARIF, with suppressed findings excluded from actionable counts.

</details>


### Top 1 hotspots

Files with the most actionable findings.

| Finding count | File location |
| ---: | --- |
| 26 | templates/insecure.yaml |

## Detailed findings

Showing 20 of 26 actionable findings, highest severity first.

<details>
<summary>1. HIGH · S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED · templates/insecure.yaml:9</summary>

### Finding 1: S3\_BUCKET\_LEVEL\_PUBLIC\_ACCESS\_PROHIBITED

- Severity: HIGH
- Scanner: cfn-guard
- Rule ID: S3\_BUCKET\_LEVEL\_PUBLIC\_ACCESS\_PROHIBITED
- Location: templates/insecure.yaml:9

Check was not compliant as property \[PublicAccessBlockConfiguration\] is missing. Value traversed to \[Path=/Resources/OpenBucket/Properties\[L:9,C:6\] Value=\{"BucketNam":"misspelled-on-purpose"\}\].

</details>

<details>
<summary>2. HIGH · S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED · templates/insecure.yaml:9</summary>

### Finding 2: S3\_BUCKET\_LEVEL\_PUBLIC\_ACCESS\_PROHIBITED

- Severity: HIGH
- Scanner: cfn-guard
- Rule ID: S3\_BUCKET\_LEVEL\_PUBLIC\_ACCESS\_PROHIBITED
- Location: templates/insecure.yaml:9

Check was not compliant as property \[PublicAccessBlockConfiguration.BlockPublicAcls\] to compare from is missing. Value traversed to \[Path=/Resources/OpenBucket/Properties\[L:9,C:6\] Value=\{"BucketNam":"misspelled-on-purpose"\}\].

</details>

<details>
<summary>3. HIGH · S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED · templates/insecure.yaml:9</summary>

### Finding 3: S3\_BUCKET\_LEVEL\_PUBLIC\_ACCESS\_PROHIBITED

- Severity: HIGH
- Scanner: cfn-guard
- Rule ID: S3\_BUCKET\_LEVEL\_PUBLIC\_ACCESS\_PROHIBITED
- Location: templates/insecure.yaml:9

Check was not compliant as property \[PublicAccessBlockConfiguration.BlockPublicPolicy\] to compare from is missing. Value traversed to \[Path=/Resources/OpenBucket/Properties\[L:9,C:6\] Value=\{"BucketNam":"misspelled-on-purpose"\}\].

</details>

<details>
<summary>4. HIGH · S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED · templates/insecure.yaml:9</summary>

### Finding 4: S3\_BUCKET\_LEVEL\_PUBLIC\_ACCESS\_PROHIBITED

- Severity: HIGH
- Scanner: cfn-guard
- Rule ID: S3\_BUCKET\_LEVEL\_PUBLIC\_ACCESS\_PROHIBITED
- Location: templates/insecure.yaml:9

Check was not compliant as property \[PublicAccessBlockConfiguration.IgnorePublicAcls\] to compare from is missing. Value traversed to \[Path=/Resources/OpenBucket/Properties\[L:9,C:6\] Value=\{"BucketNam":"misspelled-on-purpose"\}\].

</details>

<details>
<summary>5. HIGH · S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED · templates/insecure.yaml:9</summary>

### Finding 5: S3\_BUCKET\_LEVEL\_PUBLIC\_ACCESS\_PROHIBITED

- Severity: HIGH
- Scanner: cfn-guard
- Rule ID: S3\_BUCKET\_LEVEL\_PUBLIC\_ACCESS\_PROHIBITED
- Location: templates/insecure.yaml:9

Check was not compliant as property \[PublicAccessBlockConfiguration.RestrictPublicBuckets\] to compare from is missing. Value traversed to \[Path=/Resources/OpenBucket/Properties\[L:9,C:6\] Value=\{"BucketNam":"misspelled-on-purpose"\}\].
&nbsp;&nbsp;&nbsp;&nbsp;Guard Rule Set: wa-Security-Pillar
&nbsp;&nbsp;&nbsp;&nbsp;Controls: SEC-3.7,SEC-5.3,SEC-8.4
&nbsp;&nbsp;&nbsp;&nbsp;Violation: S3 Bucket Public Access controls need to be restricted.
&nbsp;&nbsp;&nbsp;&nbsp;Fix: Set S3 Bucket PublicAccessBlockConfiguration properties for BlockPublicAcls, BlockPublicPolicy, IgnorePublicAcls, RestrictPublicBuckets parameters to true.

</details>

<details>
<summary>6. HIGH · S3_BUCKET_LOGGING_ENABLED · templates/insecure.yaml:9</summary>

### Finding 6: S3\_BUCKET\_LOGGING\_ENABLED

- Severity: HIGH
- Scanner: cfn-guard
- Rule ID: S3\_BUCKET\_LOGGING\_ENABLED
- Location: templates/insecure.yaml:9

Check was not compliant as property \[LoggingConfiguration\] is missing. Value traversed to \[Path=/Resources/OpenBucket/Properties\[L:9,C:6\] Value=\{"BucketNam":"misspelled-on-purpose"\}\].
&nbsp;&nbsp;&nbsp;&nbsp;Guard Rule Set: wa-Security-Pillar
&nbsp;&nbsp;&nbsp;&nbsp;Controls: SEC-4.2
&nbsp;&nbsp;&nbsp;&nbsp;Violation: S3 Bucket Logging needs to be configured to enable logging.
&nbsp;&nbsp;&nbsp;&nbsp;Fix: Set the S3 Bucket property LoggingConfiguration to start logging into S3 bucket.

</details>

<details>
<summary>7. HIGH · S3_BUCKET_PUBLIC_READ_PROHIBITED · templates/insecure.yaml:9</summary>

### Finding 7: S3\_BUCKET\_PUBLIC\_READ\_PROHIBITED

- Severity: HIGH
- Scanner: cfn-guard
- Rule ID: S3\_BUCKET\_PUBLIC\_READ\_PROHIBITED
- Location: templates/insecure.yaml:9

Check was not compliant as property \[PublicAccessBlockConfiguration\] is missing. Value traversed to \[Path=/Resources/OpenBucket/Properties\[L:9,C:6\] Value=\{"BucketNam":"misspelled-on-purpose"\}\].

</details>

<details>
<summary>8. HIGH · S3_BUCKET_PUBLIC_READ_PROHIBITED · templates/insecure.yaml:9</summary>

### Finding 8: S3\_BUCKET\_PUBLIC\_READ\_PROHIBITED

- Severity: HIGH
- Scanner: cfn-guard
- Rule ID: S3\_BUCKET\_PUBLIC\_READ\_PROHIBITED
- Location: templates/insecure.yaml:9

Check was not compliant as property \[PublicAccessBlockConfiguration.BlockPublicAcls\] to compare from is missing. Value traversed to \[Path=/Resources/OpenBucket/Properties\[L:9,C:6\] Value=\{"BucketNam":"misspelled-on-purpose"\}\].

</details>

<details>
<summary>9. HIGH · S3_BUCKET_PUBLIC_READ_PROHIBITED · templates/insecure.yaml:9</summary>

### Finding 9: S3\_BUCKET\_PUBLIC\_READ\_PROHIBITED

- Severity: HIGH
- Scanner: cfn-guard
- Rule ID: S3\_BUCKET\_PUBLIC\_READ\_PROHIBITED
- Location: templates/insecure.yaml:9

Check was not compliant as property \[PublicAccessBlockConfiguration.BlockPublicPolicy\] to compare from is missing. Value traversed to \[Path=/Resources/OpenBucket/Properties\[L:9,C:6\] Value=\{"BucketNam":"misspelled-on-purpose"\}\].

</details>

<details>
<summary>10. HIGH · S3_BUCKET_PUBLIC_READ_PROHIBITED · templates/insecure.yaml:9</summary>

### Finding 10: S3\_BUCKET\_PUBLIC\_READ\_PROHIBITED

- Severity: HIGH
- Scanner: cfn-guard
- Rule ID: S3\_BUCKET\_PUBLIC\_READ\_PROHIBITED
- Location: templates/insecure.yaml:9

Check was not compliant as property \[PublicAccessBlockConfiguration.IgnorePublicAcls\] to compare from is missing. Value traversed to \[Path=/Resources/OpenBucket/Properties\[L:9,C:6\] Value=\{"BucketNam":"misspelled-on-purpose"\}\].

</details>

<details>
<summary>11. HIGH · S3_BUCKET_PUBLIC_READ_PROHIBITED · templates/insecure.yaml:9</summary>

### Finding 11: S3\_BUCKET\_PUBLIC\_READ\_PROHIBITED

- Severity: HIGH
- Scanner: cfn-guard
- Rule ID: S3\_BUCKET\_PUBLIC\_READ\_PROHIBITED
- Location: templates/insecure.yaml:9

Check was not compliant as property \[PublicAccessBlockConfiguration.RestrictPublicBuckets\] to compare from is missing. Value traversed to \[Path=/Resources/OpenBucket/Properties\[L:9,C:6\] Value=\{"BucketNam":"misspelled-on-purpose"\}\].
&nbsp;&nbsp;&nbsp;&nbsp;Guard Rule Set: wa-Security-Pillar
&nbsp;&nbsp;&nbsp;&nbsp;Controls: SEC-3.7,SEC-5.3,SEC-8.4
&nbsp;&nbsp;&nbsp;&nbsp;Violation: S3 Bucket Public Write Access controls need to be restricted.
&nbsp;&nbsp;&nbsp;&nbsp;Fix: Set S3 Bucket PublicAccessBlockConfiguration properties for BlockPublicAcls, BlockPublicPolicy, IgnorePublicAcls, RestrictPublicBuckets parameters to true.

</details>

<details>
<summary>12. HIGH · S3_BUCKET_PUBLIC_WRITE_PROHIBITED · templates/insecure.yaml:9</summary>

### Finding 12: S3\_BUCKET\_PUBLIC\_WRITE\_PROHIBITED

- Severity: HIGH
- Scanner: cfn-guard
- Rule ID: S3\_BUCKET\_PUBLIC\_WRITE\_PROHIBITED
- Location: templates/insecure.yaml:9

Check was not compliant as property \[PublicAccessBlockConfiguration\] is missing. Value traversed to \[Path=/Resources/OpenBucket/Properties\[L:9,C:6\] Value=\{"BucketNam":"misspelled-on-purpose"\}\].

</details>

<details>
<summary>13. HIGH · S3_BUCKET_PUBLIC_WRITE_PROHIBITED · templates/insecure.yaml:9</summary>

### Finding 13: S3\_BUCKET\_PUBLIC\_WRITE\_PROHIBITED

- Severity: HIGH
- Scanner: cfn-guard
- Rule ID: S3\_BUCKET\_PUBLIC\_WRITE\_PROHIBITED
- Location: templates/insecure.yaml:9

Check was not compliant as property \[PublicAccessBlockConfiguration.BlockPublicAcls\] to compare from is missing. Value traversed to \[Path=/Resources/OpenBucket/Properties\[L:9,C:6\] Value=\{"BucketNam":"misspelled-on-purpose"\}\].

</details>

<details>
<summary>14. HIGH · S3_BUCKET_PUBLIC_WRITE_PROHIBITED · templates/insecure.yaml:9</summary>

### Finding 14: S3\_BUCKET\_PUBLIC\_WRITE\_PROHIBITED

- Severity: HIGH
- Scanner: cfn-guard
- Rule ID: S3\_BUCKET\_PUBLIC\_WRITE\_PROHIBITED
- Location: templates/insecure.yaml:9

Check was not compliant as property \[PublicAccessBlockConfiguration.BlockPublicPolicy\] to compare from is missing. Value traversed to \[Path=/Resources/OpenBucket/Properties\[L:9,C:6\] Value=\{"BucketNam":"misspelled-on-purpose"\}\].

</details>

<details>
<summary>15. HIGH · S3_BUCKET_PUBLIC_WRITE_PROHIBITED · templates/insecure.yaml:9</summary>

### Finding 15: S3\_BUCKET\_PUBLIC\_WRITE\_PROHIBITED

- Severity: HIGH
- Scanner: cfn-guard
- Rule ID: S3\_BUCKET\_PUBLIC\_WRITE\_PROHIBITED
- Location: templates/insecure.yaml:9

Check was not compliant as property \[PublicAccessBlockConfiguration.IgnorePublicAcls\] to compare from is missing. Value traversed to \[Path=/Resources/OpenBucket/Properties\[L:9,C:6\] Value=\{"BucketNam":"misspelled-on-purpose"\}\].

</details>

<details>
<summary>16. HIGH · S3_BUCKET_PUBLIC_WRITE_PROHIBITED · templates/insecure.yaml:9</summary>

### Finding 16: S3\_BUCKET\_PUBLIC\_WRITE\_PROHIBITED

- Severity: HIGH
- Scanner: cfn-guard
- Rule ID: S3\_BUCKET\_PUBLIC\_WRITE\_PROHIBITED
- Location: templates/insecure.yaml:9

Check was not compliant as property \[PublicAccessBlockConfiguration.RestrictPublicBuckets\] to compare from is missing. Value traversed to \[Path=/Resources/OpenBucket/Properties\[L:9,C:6\] Value=\{"BucketNam":"misspelled-on-purpose"\}\].
&nbsp;&nbsp;&nbsp;&nbsp;Guard Rule Set: wa-Security-Pillar
&nbsp;&nbsp;&nbsp;&nbsp;Controls: SEC-3.7,SEC-5.3,SEC-8.4
&nbsp;&nbsp;&nbsp;&nbsp;Violation: S3 Bucket Public Write Access controls need to be restricted.
&nbsp;&nbsp;&nbsp;&nbsp;Fix: Set S3 Bucket PublicAccessBlockConfiguration properties for BlockPublicAcls, BlockPublicPolicy, IgnorePublicAcls, RestrictPublicBuckets parameters to true.

</details>

<details>
<summary>17. HIGH · S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED · templates/insecure.yaml:9</summary>

### Finding 17: S3\_BUCKET\_SERVER\_SIDE\_ENCRYPTION\_ENABLED

- Severity: HIGH
- Scanner: cfn-guard
- Rule ID: S3\_BUCKET\_SERVER\_SIDE\_ENCRYPTION\_ENABLED
- Location: templates/insecure.yaml:9

Check was not compliant as property \[BucketEncryption\] is missing. Value traversed to \[Path=/Resources/OpenBucket/Properties\[L:9,C:6\] Value=\{"BucketNam":"misspelled-on-purpose"\}\].

</details>

<details>
<summary>18. HIGH · S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED · templates/insecure.yaml:9</summary>

### Finding 18: S3\_BUCKET\_SERVER\_SIDE\_ENCRYPTION\_ENABLED

- Severity: HIGH
- Scanner: cfn-guard
- Rule ID: S3\_BUCKET\_SERVER\_SIDE\_ENCRYPTION\_ENABLED
- Location: templates/insecure.yaml:9

Check was not compliant as property \[BucketEncryption.ServerSideEncryptionConfiguration\[\*\].ServerSideEncryptionByDefault.SSEAlgorithm\] to compare from is missing. Value traversed to \[Path=/Resources/OpenBucket/Properties\[L:9,C:6\] Value=\{"BucketNam":"misspelled-on-purpose"\}\].
&nbsp;&nbsp;&nbsp;&nbsp;Guard Rule Set: wa-Security-Pillar
&nbsp;&nbsp;&nbsp;&nbsp;Controls: SEC-8.3
&nbsp;&nbsp;&nbsp;&nbsp;Violation: S3 Bucket must enable server-side encryption.
&nbsp;&nbsp;&nbsp;&nbsp;Fix: Set the S3 Bucket property BucketEncryption.ServerSideEncryptionConfiguration.ServerSideEncryptionByDefault.SSEAlgorithm to either "aws:kms" or "AES256"

</details>

<details>
<summary>19. HIGH · S3_BUCKET_VERSIONING_ENABLED · templates/insecure.yaml:9</summary>

### Finding 19: S3\_BUCKET\_VERSIONING\_ENABLED

- Severity: HIGH
- Scanner: cfn-guard
- Rule ID: S3\_BUCKET\_VERSIONING\_ENABLED
- Location: templates/insecure.yaml:9

Check was not compliant as property \[VersioningConfiguration\] is missing. Value traversed to \[Path=/Resources/OpenBucket/Properties\[L:9,C:6\] Value=\{"BucketNam":"misspelled-on-purpose"\}\].

</details>

<details>
<summary>20. HIGH · S3_BUCKET_VERSIONING_ENABLED · templates/insecure.yaml:9</summary>

### Finding 20: S3\_BUCKET\_VERSIONING\_ENABLED

- Severity: HIGH
- Scanner: cfn-guard
- Rule ID: S3\_BUCKET\_VERSIONING\_ENABLED
- Location: templates/insecure.yaml:9

Check was not compliant as property \[VersioningConfiguration.Status\] to compare from is missing. Value traversed to \[Path=/Resources/OpenBucket/Properties\[L:9,C:6\] Value=\{"BucketNam":"misspelled-on-purpose"\}\].
&nbsp;&nbsp;&nbsp;&nbsp;Guard Rule Set: wa-Security-Pillar
&nbsp;&nbsp;&nbsp;&nbsp;Controls: SEC-8.4
&nbsp;&nbsp;&nbsp;&nbsp;Violation: S3 Bucket Versioning must be enabled.
&nbsp;&nbsp;&nbsp;&nbsp;Fix: Set the S3 Bucket property VersioningConfiguration.Status to 'Enabled' .

</details>

> Showing 20 of 26 total actionable findings. Open the HTML report or use `ash inspect findings` to review the full set. Configure `max_detailed_findings` to adjust this limit.

<details>
<summary>Scan metadata</summary>

## Scan metadata

- Project: ASH
- Scan executed: 2026-01-15T12:00:00+00:00
- Report generated: 2026-01-15T12:00:42+00:00
- ASH version: <ASH_VERSION>

</details>

*Report generated by [Automated Security Helper (ASH)](https://github.com/awslabs/automated-security-helper) at 2026-01-15T12:00:42+00:00*

Build with <3 at Amazon Web Services
