import os
import uuid
import json
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError


# ---------------------------------------------------------
# AWS CLIENTS
# ---------------------------------------------------------

iam = boto3.client("iam")
s3 = boto3.client("s3")
ec2 = boto3.client("ec2")
sns = boto3.client("sns")

bedrock_runtime = boto3.client(
    "bedrock-runtime",
    region_name="ap-south-2"
)

dynamodb = boto3.resource("dynamodb")


# ---------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------

TABLE_NAME = os.environ["FINDINGS_TABLE"]

SNS_TOPIC_ARN = os.environ.get(
    "SNS_TOPIC_ARN"
)
AUDIT_BUCKET = os.environ["AUDIT_BUCKET"]
BEDROCK_MODEL_ID = (
    "global.anthropic.claude-haiku-4-5-20251001-v1:0"
)

table = dynamodb.Table(TABLE_NAME)


# ---------------------------------------------------------
# FINDING CREATION
# ---------------------------------------------------------

def create_finding(
    service,
    severity,
    title,
    description
):
    return {
        "finding_id": str(uuid.uuid4()),
        "service": service,
        "severity": severity,
        "title": title,
        "description": description,
        "status": "OPEN",
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat()
    }


def save_finding(finding):
    table.put_item(
        Item=finding
    )


# ---------------------------------------------------------
# BEDROCK AI ANALYSIS
# ---------------------------------------------------------

def analyze_finding_with_bedrock(finding):

    prompt = f"""
You are an AWS security assistant.

Analyze this CloudGuardian security finding:

Service: {finding.get("service")}
Severity: {finding.get("severity")}
Title: {finding.get("title")}
Description: {finding.get("description")}

Provide a short response with exactly these sections:

Risk:
Recommendation:
AWS Action:

Keep the response practical and under 150 words.
"""

    request_body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 300,
        "temperature": 0,
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": prompt
                    }
                ]
            }
        ]
    }

    try:

        response = bedrock_runtime.invoke_model(
            modelId=BEDROCK_MODEL_ID,
            body=json.dumps(request_body),
            contentType="application/json",
            accept="application/json"
        )

        response_body = json.loads(
            response["body"].read()
        )

        content = response_body.get(
            "content",
            []
        )

        if content:
            return content[0].get(
                "text",
                "AI analysis unavailable."
            )

        return "AI analysis unavailable."

    except Exception as e:

        print(
            f"Bedrock analysis failed: {str(e)}"
        )

        return "AI analysis unavailable."


# ---------------------------------------------------------
# SNS ALERT
# ---------------------------------------------------------

def send_sns_alert(finding):

    if not SNS_TOPIC_ARN:
        print(
            "SNS_TOPIC_ARN is not configured."
        )
        return

    message = f"""
CloudGuardian Security Alert

Service: {finding.get("service")}
Severity: {finding.get("severity")}
Title: {finding.get("title")}

Description:
{finding.get("description")}
"""

    ai_analysis = finding.get(
        "ai_analysis"
    )

    if ai_analysis:

        message += f"""

AI Analysis:
{ai_analysis}
"""

    try:

        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject="CloudGuardian Security Alert",
            Message=message
        )

        print(
            "SNS alert sent successfully."
        )

    except Exception as e:

        print(
            f"SNS alert failed: {str(e)}"
        )


# ---------------------------------------------------------
# IAM SECURITY SCAN
# ---------------------------------------------------------

def scan_iam():

    print(
        "Starting IAM scan..."
    )

    findings = []

    try:

        users_response = iam.list_users()

        users = users_response.get(
            "Users",
            []
        )

        for user in users:

            username = user["UserName"]

            # Check MFA
            try:

                mfa_response = iam.list_mfa_devices(
                    UserName=username
                )

                mfa_devices = mfa_response.get(
                    "MFADevices",
                    []
                )

                if not mfa_devices:

                    finding = create_finding(
                        service="IAM",
                        severity="HIGH",
                        title=f"IAM user without MFA: {username}",
                        description=(
                            f"IAM user '{username}' "
                            "does not have MFA enabled."
                        )
                    )

                    findings.append(
                        finding
                    )

            except ClientError as e:

                print(
                    f"MFA check failed for {username}: {str(e)}"
                )

            # Check access keys
            try:

                keys_response = iam.list_access_keys(
                    UserName=username
                )

                access_keys = keys_response.get(
                    "AccessKeyMetadata",
                    []
                )

                for key in access_keys:

                    create_date = key.get(
                        "CreateDate"
                    )

                    if create_date:

                        age_days = (
                            datetime.now(
                                timezone.utc
                            ) - create_date
                        ).days

                        if age_days > 90:

                            finding = create_finding(
                                service="IAM",
                                severity="MEDIUM",
                                title=(
                                    f"Old IAM access key: {username}"
                                ),
                                description=(
                                    f"Access key "
                                    f"{key.get('AccessKeyId')} "
                                    f"for user '{username}' "
                                    f"is {age_days} days old."
                                )
                            )

                            findings.append(
                                finding
                            )

            except ClientError as e:

                print(
                    f"Access key check failed for {username}: {str(e)}"
                )

    except ClientError as e:

        print(
            f"IAM scan failed: {str(e)}"
        )

    print(
        f"IAM scan completed. Findings: {len(findings)}"
    )

    return findings


# ---------------------------------------------------------
# S3 SECURITY SCAN
# ---------------------------------------------------------

def scan_s3():

    print(
        "Starting S3 scan..."
    )

    findings = []

    try:

        buckets_response = s3.list_buckets()

        buckets = buckets_response.get(
            "Buckets",
            []
        )

        for bucket in buckets:

            bucket_name = bucket["Name"]

            # Public access block
            try:

                public_access = s3.get_public_access_block(
                    Bucket=bucket_name
                )

                config = public_access.get(
                    "PublicAccessBlockConfiguration",
                    {}
                )

                block_public_acls = config.get(
                    "BlockPublicAcls",
                    False
                )

                block_public_policy = config.get(
                    "BlockPublicPolicy",
                    False
                )

                ignore_public_acls = config.get(
                    "IgnorePublicAcls",
                    False
                )

                restrict_public_buckets = config.get(
                    "RestrictPublicBuckets",
                    False
                )

                if not all([
                    block_public_acls,
                    block_public_policy,
                    ignore_public_acls,
                    restrict_public_buckets
                ]):

                    finding = create_finding(
                        service="S3",
                        severity="HIGH",
                        title=(
                            f"S3 public access protection incomplete: "
                            f"{bucket_name}"
                        ),
                        description=(
                            f"S3 bucket '{bucket_name}' "
                            "does not have all four "
                            "Block Public Access settings enabled."
                        )
                    )

                    findings.append(
                        finding
                    )

            except ClientError as e:

                error_code = e.response.get(
                    "Error",
                    {}
                ).get(
                    "Code"
                )

                if error_code == "NoSuchPublicAccessBlockConfiguration":

                    finding = create_finding(
                        service="S3",
                        severity="HIGH",
                        title=(
                            f"S3 public access block missing: "
                            f"{bucket_name}"
                        ),
                        description=(
                            f"S3 bucket '{bucket_name}' "
                            "does not have a Public Access Block configuration."
                        )
                    )

                    findings.append(
                        finding
                    )

                else:

                    print(
                        f"S3 public access check failed for "
                        f"{bucket_name}: {str(e)}"
                    )

            # Encryption
            try:

                s3.get_bucket_encryption(
                    Bucket=bucket_name
                )

            except ClientError as e:

                error_code = e.response.get(
                    "Error",
                    {}
                ).get(
                    "Code"
                )

                if error_code in [
                    "ServerSideEncryptionConfigurationNotFoundError",
                    "NoSuchBucket"
                ]:

                    finding = create_finding(
                        service="S3",
                        severity="MEDIUM",
                        title=(
                            f"S3 bucket encryption missing: "
                            f"{bucket_name}"
                        ),
                        description=(
                            f"S3 bucket '{bucket_name}' "
                            "does not have default server-side encryption configured."
                        )
                    )

                    findings.append(
                        finding
                    )

                else:

                    print(
                        f"S3 encryption check failed for "
                        f"{bucket_name}: {str(e)}"
                    )

            # Versioning
            try:

                versioning_response = s3.get_bucket_versioning(
                    Bucket=bucket_name
                )

                status = versioning_response.get(
                    "Status"
                )

                if status != "Enabled":

                    finding = create_finding(
                        service="S3",
                        severity="LOW",
                        title=(
                            f"S3 versioning disabled: "
                            f"{bucket_name}"
                        ),
                        description=(
                            f"S3 bucket '{bucket_name}' "
                            "does not have versioning enabled."
                        )
                    )

                    findings.append(
                        finding
                    )

            except ClientError as e:

                print(
                    f"S3 versioning check failed for "
                    f"{bucket_name}: {str(e)}"
                )

    except ClientError as e:

        print(
            f"S3 scan failed: {str(e)}"
        )

    print(
        f"S3 scan completed. Findings: {len(findings)}"
    )

    return findings


# ---------------------------------------------------------
# EC2 SECURITY AND COST SCAN
# ---------------------------------------------------------

def scan_ec2():

    print(
        "Starting EC2 scan..."
    )

    findings = []

    try:

        # Running EC2 instances
        instances_response = ec2.describe_instances()

        reservations = instances_response.get(
            "Reservations",
            []
        )

        running_instances = []

        for reservation in reservations:

            for instance in reservation.get(
                "Instances",
                []
            ):

                state = instance.get(
                    "State",
                    {}
                ).get(
                    "Name"
                )

                if state == "running":

                    running_instances.append(
                        instance
                    )

        if running_instances:

            finding = create_finding(
                service="EC2",
                severity="LOW",
                title=(
                    "Running EC2 instances detected"
                ),
                description=(
                    f"CloudGuardian detected "
                    f"{len(running_instances)} running EC2 instance(s). "
                    "Review whether they are required to control costs."
                )
            )

            findings.append(
                finding
            )

        # Unattached EBS volumes
        volumes_response = ec2.describe_volumes(
            Filters=[
                {
                    "Name": "status",
                    "Values": ["available"]
                }
            ]
        )

        volumes = volumes_response.get(
            "Volumes",
            []
        )

        for volume in volumes:

            volume_id = volume.get(
                "VolumeId"
            )

            size = volume.get(
                "Size"
            )

            finding = create_finding(
                service="EC2",
                severity="MEDIUM",
                title=(
                    f"Unattached EBS volume: {volume_id}"
                ),
                description=(
                    f"EBS volume '{volume_id}' "
                    f"with size {size} GiB is currently unattached."
                )
            )

            findings.append(
                finding
            )

        # Elastic IP addresses
        addresses_response = ec2.describe_addresses()

        addresses = addresses_response.get(
            "Addresses",
            []
        )

        for address in addresses:

            association_id = address.get(
                "AssociationId"
            )

            allocation_id = address.get(
                "AllocationId"
            )

            public_ip = address.get(
                "PublicIp"
            )

            if not association_id:

                finding = create_finding(
                    service="EC2",
                    severity="MEDIUM",
                    title=(
                        f"Unassociated Elastic IP: {public_ip}"
                    ),
                    description=(
                        f"Elastic IP '{public_ip}' "
                        f"with allocation ID '{allocation_id}' "
                        "is not associated with an EC2 resource."
                    )
                )

                findings.append(
                    finding
                )

    except ClientError as e:

        print(
            f"EC2 scan failed: {str(e)}"
        )

    print(
        f"EC2 scan completed. Findings: {len(findings)}"
    )

    return findings

def calculate_security_score(findings):
    """Calculate CloudGuardian security score out of 100."""

    score = 100

    for finding in findings:

        severity = finding.get("severity")

        if severity == "HIGH":
            score -= 20

        elif severity == "MEDIUM":
            score -= 10

        elif severity == "LOW":
            score -= 5

    return max(score, 0)

def generate_security_report(findings):
    """Generate and upload a JSON security report to S3."""

    now = datetime.now(timezone.utc)
    security_score = calculate_security_score(findings)

    high_count = sum(
        1 for finding in findings
        if finding.get("severity") == "HIGH"
    )

    medium_count = sum(
        1 for finding in findings
        if finding.get("severity") == "MEDIUM"
    )

    low_count = sum(
        1 for finding in findings
        if finding.get("severity") == "LOW"
    )

    service_counts = {
        "IAM": sum(1 for f in findings if f.get("service") == "IAM"),
        "S3": sum(1 for f in findings if f.get("service") == "S3"),
        "EC2": sum(1 for f in findings if f.get("service") == "EC2")
    }

    report = {
        "project": "CloudGuardian",
        "report_type": "AWS Security Scan Report",
        "generated_at": now.isoformat(),
        "summary": {
           "security_score": security_score,
           "total_findings": len(findings),
           "high": high_count,
           "medium": medium_count,
           "low": low_count
        },
        "service_summary": service_counts,
        "findings": findings
    }

    report_key = (
        f"reports/{now.strftime('%Y/%m/%d')}/"
        f"cloudguardian-report-{now.strftime('%Y%m%d-%H%M%S')}.json"
    )

    s3.put_object(
        Bucket=AUDIT_BUCKET,
        Key=report_key,
        Body=json.dumps(report, default=str, indent=2),
        ContentType="application/json",
        ServerSideEncryption="AES256"
    )

    print(f"Security report uploaded: s3://{AUDIT_BUCKET}/{report_key}")

    return report_key
# ---------------------------------------------------------
# MAIN LAMBDA HANDLER
# ---------------------------------------------------------

def lambda_handler(event, context):

    print(
        "CloudGuardian security scan started."
    )

    findings = []

    # IAM scan
    iam_findings = scan_iam()
    findings.extend(
        iam_findings
    )

    # S3 scan
    s3_findings = scan_s3()
    findings.extend(
        s3_findings
    )

    # EC2 scan
    ec2_findings = scan_ec2()
    findings.extend(
        ec2_findings
    )

    # Save initial findings
    for finding in findings:

        try:

            save_finding(
                finding
            )

        except Exception as e:

            print(
                f"Failed to save finding: {str(e)}"
            )

    # Bedrock AI analysis
    ai_analyzed_count = 0

    for finding in findings:

        if finding.get(
            "severity"
        ) == "HIGH":

            ai_analysis = analyze_finding_with_bedrock(
                finding
            )

            finding["ai_analysis"] = (
                ai_analysis
            )

            try:

                table.put_item(
                    Item=finding
                )

            except Exception as e:

                print(
                    f"Failed to update finding with AI analysis: {str(e)}"
                )

            ai_analyzed_count += 1

    # Generate security report
    report_key = generate_security_report(
        findings
    )

    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "message": "CloudGuardian security scan completed.",
                "findings_count": len(findings),
                "ai_analyzed_count": ai_analyzed_count,
                "report_key": report_key,
                "findings": findings
            },
            default=str
        )
    }

    # SNS alerts
    for finding in findings:

        if finding.get(
            "severity"
        ) == "HIGH":

            send_sns_alert(
                finding
            )

    print(
        "CloudGuardian security scan completed."
    )

    print(
        f"Total findings: {len(findings)}"
    )

    print(
        f"AI analyzed findings: {ai_analyzed_count}"
    )

    return {
        "statusCode": 200,
        "body": json.dumps({
            "message": "CloudGuardian security scan completed.",
            "findings_count": len(findings),
            "ai_analyzed_count": ai_analyzed_count,
            "findings": findings
        }, default=str)
    }