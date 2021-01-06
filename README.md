# Automated ChatOps solution for remediating Amazon Macie findings

This solution establishes an automated event driven workflow for notifying and auto-remediating sensitive data findings from Amazon Macie. Human interaction is via *ChatOps* style integration with [Slack](https://slack.com/).

## **Solution Overview**

This solution allows for the configuration of the auto-remediation behaviour based on [finding type](https://docs.aws.amazon.com/macie/latest/user/findings-types.html#findings-sensitive-data-types) and finding [severity](https://docs.aws.amazon.com/macie/latest/APIReference/findings-describe.html#findings-describe-prop-finding-severity). For each finding type you can define if you want the offending S3 object to be automatically quarantined or if you want the finding details to be reviewed and approved by a human in Slack prior to being quarantined. In a similar manner you can define the minimum severity level (Low, Medium, High) that a finding must have before the solution will take action. Adjusting these parameters allows you to manage false positives and tune the volume and type of findings on which you wish to be notified and take action.

The solution architecture and eight step interaction sequence are detailed below in Figure 1.

![Solution Architecture](https://github.com/aws-samples/amazonmacie-chatops-remediation/raw/main/images/MacieBlogSolution.png)
*Figure 1 - Solution Overview*

1. Amazon Macie is configured with [sensitive data discovery jobs](https://docs.aws.amazon.com/macie/latest/user/discovery-jobs.html) (scheduled or adhoc) which detect sensitive data within [Amazon S3](https://docs.aws.amazon.com/AmazonS3/latest/dev/Welcome.html) buckets. See [here](https://docs.aws.amazon.com/macie/latest/user/managed-data-identifiers.html) for a full list of the categories of sensitive data Macie can detect.
2. For each sensitive data finding an event is sent to [Amazon EventBridge](https://docs.aws.amazon.com/eventbridge/latest/userguide/what-is-amazon-eventbridge.html) containing the finding details. An EventBridge [rule](https://docs.aws.amazon.com/eventbridge/latest/userguide/create-eventbridge-rule.html) triggers a [Lambda](https://docs.aws.amazon.com/lambda/latest/dg/welcome.html) function for processing.
3. The Finding Handler Lambda function parses the event, examines the [type](https://docs.aws.amazon.com/macie/latest/user/findings-types.html#findings-sensitive-data-types) of the finding, and based on auto-remediation configuration will either invoke the Finding Remediator function for immediate remediation, or send finding details for manual review and remediation approval via Slack.
4. Delegated security / compliance admins monitor the configured Slack channel for notifications. Notifications provide high level finding information, remediation status, and a deep link to the Amazon Macie console for the finding in question. For findings configured for manual review, users can choose to approve the remediation in Slack via an action button on the notification.
5. After a user clicks the “Remediate” button, Slack issues an API call to an [Amazon API Gateway](https://docs.aws.amazon.com/apigateway/latest/developerguide/welcome.html) endpoint supplying the unique identifier of the finding to be remediated and the Slack user. API Gateway proxies the request to a remediation handler Lambda function. 
6. The Remediation Handler Lambda function validates the request and request signature, extracts the offending object location from the finding, and makes an asynchronous call to the Finding Remediator Lambda function.
7. The Finding Remediator Lambda function moves the offending object from the source bucket to a designated S3 quarantine bucket with restricted access.
8. Finally, the Finding Remediator Lambda function will use a callback URL to update the original finding notification in Slack indicating that the offending object has now been quarantined.

## **Prerequisites**

Before proceeding to deploy the solution ensure your environment is setup with the following pre-requisites.

* You have access to an AWS account via an [AWS Identity and Access Management](https://aws.amazon.com/iam/) role or user with permissions to create the resources listed in the Solution Overview via [AWS CloudFormation](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/Welcome.html)
* The [AWS Command Line Interface (CLI)](https://aws.amazon.com/cli/) is installed and [configured for use](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html). Ensure your configured default region supports Amazon Macie by checking service availability [here](https://aws.amazon.com/about-aws/global-infrastructure/regional-product-services/)
* The [AWS Cloud Development Kit (CDK)](https://docs.aws.amazon.com/cdk/latest/guide/home.html) is installed and [configured](https://docs.aws.amazon.com/cdk/latest/guide/getting_started.html) for use
* You have a Slack account with permissions to add apps and integrations in your desired Workspace and Channel. If you are not already a Slack user its [free to sign up](https://slack.com/intl/en-au/get-started#/) and create a workspace and channel of your own

**Important:** this solution uses various AWS services, and there are costs associated with these resources after the Free Tier usage. Please see the [AWS pricing page](https://aws.amazon.com/pricing/) for details.

## **Deploying & Testing the Solution**

Full walkthrough instructions instructions for configuring Slack and deploying the solution via AWS CDK are available in a blog post [here](https://aws.amazon.com/blogs/security/deploy-an-automated-chatops-solution-for-remediating-amazon-macie-findings/).

## **Security**

See CONTRIBUTING for more information.

## **License**

This library is licensed under the MIT-0 License. See the LICENSE file.

