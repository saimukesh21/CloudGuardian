\# CloudGuardian



\## AWS Cloud Security \& Governance Platform



CloudGuardian is a serverless AWS security scanning and governance platform built using \*\*AWS managed services, Python, and Terraform\*\*.



It scans AWS resources for common security and configuration issues, stores findings, generates security reports, sends alerts for high-severity findings, performs scheduled scans, and provides CloudWatch monitoring.



\---



\## Architecture



```text

&#x20;                        User

&#x20;                          |

&#x20;                          | POST /scan

&#x20;                          v

&#x20;                   +---------------+

&#x20;                   | API Gateway   |

&#x20;                   +-------+-------+

&#x20;                           |

&#x20;                           v

&#x20;                   +---------------+

&#x20;                   | AWS Lambda    |

&#x20;                   | Security      |

&#x20;                   | Scanner       |

&#x20;                   +-------+-------+

&#x20;                           |

&#x20;             +-------------+-------------+

&#x20;             |             |             |

&#x20;             v             v             v

&#x20;          IAM Checks    S3 Checks     EC2 Checks

&#x20;             |             |             |

&#x20;             +-------------+-------------+

&#x20;                           |

&#x20;                           v

&#x20;                   +---------------+

&#x20;                   |   DynamoDB    |

&#x20;                   |   Findings    |

&#x20;                   +-------+-------+

&#x20;                           |

&#x20;                           v

&#x20;                   +---------------+

&#x20;                   | S3 Security   |

&#x20;                   |    Report     |

&#x20;                   +---------------+



&#x20;EventBridge Scheduler

&#x20;         |

&#x20;         v

&#x20;  Lambda Scanner



&#x20;HIGH Findings

&#x20;         |

&#x20;         v

&#x20;        SNS

&#x20;         |

&#x20;         v

&#x20;  Security Alert



&#x20;Lambda Metrics

&#x20;         |

&#x20;         v

&#x20;     CloudWatch

&#x20;         |

&#x20;         v

&#x20;CloudWatch Dashboard



&#x20;AWS API Activity

&#x20;         |

&#x20;         v

&#x20;     CloudTrail

```



\---



\## AWS Services Used



| AWS Service                      | Purpose                            |

| -------------------------------- | ---------------------------------- |

| \*\*AWS Lambda\*\*                   | Serverless security scanning       |

| \*\*Amazon API Gateway\*\*           | On-demand security scan API        |

| \*\*Amazon DynamoDB\*\*              | Stores security findings           |

| \*\*Amazon S3\*\*                    | Audit storage and security reports |

| \*\*AWS IAM\*\*                      | IAM security checks                |

| \*\*Amazon EC2\*\*                   | EC2, EBS, and Elastic IP checks    |

| \*\*Amazon SNS\*\*                   | HIGH-severity security alerts      |

| \*\*Amazon EventBridge Scheduler\*\* | Scheduled security scans           |

| \*\*AWS CloudTrail\*\*               | AWS API activity auditing          |

| \*\*Amazon CloudWatch\*\*            | Metrics, alarms, and dashboard     |

| \*\*Terraform\*\*                    | Infrastructure as Code             |

| \*\*Amazon Bedrock\*\*               | Planned AI analysis enhancement    |



\---



\## Key Features



\### 1. IAM Security Checks



CloudGuardian checks for:



\* IAM users without MFA

\* Old access keys

\* IAM account security conditions



\### 2. S3 Security Checks



CloudGuardian checks for:



\* Public Access Block configuration

\* Default encryption

\* S3 bucket versioning



\### 3. EC2 Security Checks



CloudGuardian checks for:



\* Running EC2 instances

\* Unattached EBS volumes

\* Unassociated Elastic IP addresses



\### 4. Security Findings



Each finding contains:



\* Finding ID

\* AWS service

\* Severity

\* Title

\* Description

\* Status

\* Timestamp



Severity levels:



```text

HIGH

MEDIUM

LOW

```



\---



\## Security Score



CloudGuardian calculates a security score out of \*\*100\*\*.



\### Current Scoring Logic



```text

HIGH   = -20 points

MEDIUM = -10 points

LOW    = -5 points

```



\### Example



```text

Initial Score : 100

LOW Finding   : -5

Final Score   : 95/100

```



\---



\## Security Reports



After every scan, CloudGuardian generates a JSON security report containing:



\* Security score

\* Total findings

\* HIGH/MEDIUM/LOW counts

\* Findings by AWS service

\* Finding details

\* Timestamp



Reports are stored securely in Amazon S3.



\### Report Structure



```text

reports/

└── YYYY/

&#x20;   └── MM/

&#x20;       └── DD/

&#x20;           └── cloudguardian-report-YYYYMMDD-HHMMSS.json

```



\---



\## API-Based Scanning



CloudGuardian provides an HTTP API for on-demand security scans.



\### Endpoint



```http

POST /scan

```



\### Example Request



```bash

curl -X POST "https://<api-id>.execute-api.ap-south-2.amazonaws.com/scan"

```



\### Example Response



```json

{

&#x20; "message": "CloudGuardian security scan completed.",

&#x20; "findings\_count": 1,

&#x20; "ai\_analyzed\_count": 0,

&#x20; "report\_key": "reports/2026/09/28/cloudguardian-report-20260928-110854.json"

}

```



\---



\## Scheduled Scanning



CloudGuardian uses \*\*Amazon EventBridge Scheduler\*\* to automatically invoke the Lambda security scanner.



\### Current Schedule



```text

09:00 AM Asia/Kolkata

```



\### Flow



```text

EventBridge Scheduler

&#x20;       |

&#x20;       v

Lambda Security Scanner

&#x20;       |

&#x20;       v

AWS Security Scan

```



\---



\## Monitoring \& Alerting



CloudGuardian uses \*\*Amazon CloudWatch\*\* to monitor the Lambda security scanner.



\### Monitored Metrics



\* Lambda Invocations

\* Lambda Errors

\* Lambda Duration



\### CloudWatch Alarm



```text

Alarm Name : CloudGuardian-Lambda-Errors

Metric     : AWS/Lambda Errors

Threshold  : >= 1

Action     : SNS

Current    : OK

```



A CloudWatch dashboard provides a centralized monitoring view of the application.



\---



\## Security Alerts



CloudGuardian uses \*\*Amazon SNS\*\* to send security alerts for HIGH-severity findings.



```text

Security Finding

&#x20;      |

&#x20;      v

&#x20;  HIGH Severity

&#x20;      |

&#x20;      v

&#x20;     SNS

&#x20;      |

&#x20;      v

&#x20;Security Alert

```



\---



\## AWS Auditing



CloudGuardian uses \*\*AWS CloudTrail\*\* to record AWS API activity.



CloudTrail logs are stored in the CloudGuardian S3 audit bucket.



```text

AWS API Activity

&#x20;      |

&#x20;      v

&#x20;  CloudTrail

&#x20;      |

&#x20;      v

&#x20;  Amazon S3

&#x20;      |

&#x20;      v

&#x20;Audit Logs

```



This provides an audit trail for AWS activity associated with the environment.



\---



\## Infrastructure as Code



CloudGuardian infrastructure is managed using \*\*Terraform\*\*.



Terraform manages:



```text

AWS Lambda

API Gateway

IAM

S3

DynamoDB

SNS

EventBridge Scheduler

CloudTrail

CloudWatch Alarm

CloudWatch Dashboard

```



\### Terraform Commands



Initialize Terraform:



```bash

terraform init

```



Validate configuration:



```bash

terraform validate

```



Review changes:



```bash

terraform plan

```



Deploy infrastructure:



```bash

terraform apply

```



Destroy infrastructure when no longer required:



```bash

terraform destroy

```



> Always review the Terraform plan before applying or destroying resources.



\---



\## Testing



The application was tested through the API Gateway.



\### Verified Workflow



```text

API Gateway

&#x20;     |

&#x20;     v

Lambda Scanner

&#x20;     |

&#x20;     +----> IAM Checks

&#x20;     |

&#x20;     +----> S3 Checks

&#x20;     |

&#x20;     +----> EC2 Checks

&#x20;     |

&#x20;     v

DynamoDB Findings

&#x20;     |

&#x20;     v

S3 Security Report

&#x20;     |

&#x20;     v

CloudWatch Monitoring

```



\### Verified Test Result



```text

Total Findings : 1

HIGH           : 0

MEDIUM         : 0

LOW            : 1

Security Score : 95/100

```



\### Example Finding



```text

Service  : S3

Finding  : S3 versioning disabled

Bucket   : fita-aws-devops

Severity : LOW

Status   : OPEN

```



\---



\## Project Structure



```text

CloudGuardian/

│

├── README.md

│

├── architecture/

│   └── architecture.png

│

├── infra/

│   └── sandbox/

│       ├── api\_gateway.tf

│       ├── cloudtrail.tf

│       ├── dashboard.tf

│       ├── dynamodb.tf

│       ├── eventbridge.tf

│       ├── iam.tf

│       ├── lambda.tf

│       ├── main.tf

│       ├── monitoring.tf

│       ├── outputs.tf

│       ├── provider.tf

│       ├── sns.tf

│       ├── variable.tf

│       │

│       └── lambda/

│           └── lambda\_function.py

│

├── reports/

│   └── sample-report.json

│

└── screenshots/

&#x20;   ├── 01-api-test.png

&#x20;   ├── 02-dynamodb-findings.png

&#x20;   ├── 03-security-report.png

&#x20;   ├── 04-cloudwatch-dashboard.png

&#x20;   ├── 05-cloudwatch-alarm.png

&#x20;   ├── 06-eventbridge.png

&#x20;   ├── 07-cloudtrail.png

&#x20;   ├── 08-s3-report.png

&#x20;   └── 09-terraform.png

```



\---



\## Security



Sensitive information must \*\*not\*\* be committed to GitHub.



The following files and directories are excluded from the repository:



```text

terraform.tfstate

terraform.tfstate.backup

terraform.tfvars

.terraform/

lambda.zip

AWS credentials

AWS access keys

AWS secret keys

```



Never commit AWS credentials, access keys, secret keys, or other sensitive information to GitHub.



\---



\## Future Enhancements



\* Amazon Bedrock AI-powered finding analysis

\* Additional AWS security checks

\* Automated remediation

\* Additional governance and compliance checks

\* Expanded security dashboard

\* Additional AWS service integrations



\---



\## Technologies



```text

AWS

Terraform

Python

Boto3

AWS Lambda

API Gateway

DynamoDB

S3

IAM

EC2

SNS

EventBridge

CloudTrail

CloudWatch

```



\---



\## Project Objective



CloudGuardian demonstrates practical experience with:



\* AWS serverless architecture

\* AWS security and governance

\* Infrastructure as Code

\* Python and Boto3

\* Cloud monitoring

\* Event-driven automation

\* Security reporting

\* AWS API integration

\* Scheduled security scanning



