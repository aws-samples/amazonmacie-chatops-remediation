// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

import * as cdk from '@aws-cdk/core';
import * as lambda from '@aws-cdk/aws-lambda';
import { Bucket, BucketEncryption, BlockPublicAccess } from '@aws-cdk/aws-s3';
import { PolicyStatement, Effect } from '@aws-cdk/aws-iam';
import { LambdaRestApi } from '@aws-cdk/aws-apigateway';
import { Rule } from '@aws-cdk/aws-events';
import { LambdaFunction } from '@aws-cdk/aws-events-targets';


export class MacieAutoRemediationStack extends cdk.Stack {
  constructor(scope: cdk.Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const quarantineBucket = new Bucket(this, 'QuarantineBucket', {
      encryption: BucketEncryption.S3_MANAGED,
      blockPublicAccess: BlockPublicAccess.BLOCK_ALL
    });

    const macieFindingHandler = new lambda.Function(this, 'MacieFindingHandler', {
      functionName: 'macie-finding-handler',
      code: new lambda.AssetCode('src/macie-finding-handler'),
      runtime: lambda.Runtime.NODEJS_12_X,
      handler: 'macie-finding-handler.handler',
      environment: {
        autoRemediateConfig: JSON.stringify(this.node.tryGetContext('autoRemediateConfig')),
        minSeverityLevel: this.node.tryGetContext('minSeverityLevel'),
        quarantineBucket: quarantineBucket.bucketName,
        slackChannel: this.node.tryGetContext('slackChannel'),
        slackWebHookUrl: this.node.tryGetContext('slackWebHookUrl'),
      },
    });

    const macieRemediationHandler = new lambda.Function(this, 'MacieRemediationHandler', {
      functionName: 'macie-remediation-handler',
      code: new lambda.AssetCode('src/macie-remediation-handler'),
      runtime: lambda.Runtime.NODEJS_12_X,
      handler: 'macie-remediation-handler.handler',
      environment: {
        slackSigningSecret: this.node.tryGetContext('slackSigningSecret'),
      },
    });

    const macieRemediator = new lambda.Function(this, 'MacieRemediator', {
      functionName: 'macie-remediator',
      code: new lambda.AssetCode('src/macie-remediator'),
      runtime: lambda.Runtime.NODEJS_12_X,
      handler: 'macie-remediator.handler',
      environment: {
        quarantineBucket: quarantineBucket.bucketName,
        slackChannel: this.node.tryGetContext('slackChannel'),
        slackWebHookUrl: this.node.tryGetContext('slackWebHookUrl'),
      },
    });

    const lambdaRemediatorInvokePolicy = new PolicyStatement({
      effect: Effect.ALLOW,
      actions: [
        'lambda:InvokeFunction'
      ],
      resources: [macieRemediator.functionArn],
    });

    const macieReadPolicy= new PolicyStatement({
      effect: Effect.ALLOW,
      actions: [
        'macie2:GetFindings'
      ],
      resources: ['*'],
    });

    const remediatorPolicy = new PolicyStatement({
      effect: Effect.ALLOW,
      actions: [
        's3:GetObject',
        's3:PutObject',
        's3:ListBucket',
        's3:GetObjectTagging',
        's3:PutObjectTagging',
        's3:DeleteObject',
        's3:GetObjectAcl',
        'S3:PutObjectAcl',
      ],
      resources: ['*'],
    });

    macieFindingHandler.addToRolePolicy(lambdaRemediatorInvokePolicy);
    macieRemediationHandler.addToRolePolicy(macieReadPolicy);
    macieRemediationHandler.addToRolePolicy(lambdaRemediatorInvokePolicy);
    macieRemediator.addToRolePolicy(remediatorPolicy);

    const macieFindingRule = new Rule(this,'MacieFindingRule', {
      description: 'Handle Macie sensitive data findings',
      eventPattern: {
        source: [
          "aws.macie"
        ],
        detailType: [
          "Macie Finding"
        ],
        detail: {
          "type": [ { "prefix": "SensitiveData" } ]
        }
      }
    });

    macieFindingRule.addTarget(new LambdaFunction(macieFindingHandler));

    new LambdaRestApi(this, 'remediationApi', {
      restApiName: 'Macie Remediation API',
      description: 'API to handle Macie finding remediation authorisations from Slack',
      handler: macieRemediationHandler
    });

  }
}
