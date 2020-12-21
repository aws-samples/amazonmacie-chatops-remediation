// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

'use strict';

const { postSlackMessage, invokeRemediationLambda } = require('macie-rem-common');

const minSeverityLevel = process.env.minSeverityLevel;
const slackWebHookUrl = process.env.slackWebHookUrl;
const slackChannel = process.env.slackChannel;
const autoRemediateConfig = process.env.autoRemediateConfig;
const quarantineBucket = process.env.quarantineBucket;

//Lambda function triggered by EventBridge for Macie senstive data findings
exports.handler = async (event) => {
    try {
        const finding = event.detail;  

        // This particular handler only deals with data classification findings
        if (notRelevant(finding)) {
            return;
        }

        // Are we configured to auto remediate this particular type of classification finding
        const autoRemediate = finding.type && JSON.parse(autoRemediateConfig)[finding.type] === "AUTO";

        if (autoRemediate) {
            console.log("Auto-remediating finding");
            const lambdaPayload = {
                macieFinding: finding
            };
            //Async invoke of remediation Lambda function
            await invokeRemediationLambda(lambdaPayload);
            //Our work here is done
        } else {
            //Build up a nicely formatted slack message, requesting manual review and authorisation of remediation
            const slackMessage = buildSlackMessage(finding);

            //Deliver finding notification to Slack
            const slackResponse = await postSlackMessage(slackMessage, slackWebHookUrl);

            if (slackResponse.statusCode < 400) {
                console.info('Message posted successfully');
            } else if (slackResponse.statusCode < 500) {
                console.error(`Error posting message to Slack API: ${slackResponse.statusCode} - ${slackResponse.statusMessage} - ${slackResponse.body}`);
            } else {
                console.error(`Slack server error when processing message: ${slackResponse.statusCode} - ${slackResponse.statusMessage} - ${slackResponse.body}`);
            }
        }
    } catch (err) {
        console.error(err);
    }
};

function notRelevant(finding) {
    //Don't process if not a finding resulting from a sensitive data discovery job
    if (finding.category !== 'CLASSIFICATION') {
        console.log("Not a data classification finding, exiting");
        return true;
    } 

    //Determine if any action should be taken based on configured minimum severity level
    if (finding.severity.score) {
        const score = finding.severity.score;

        if ((score < 2 && minSeverityLevel !== 'LOW') || (score < 3 && minSeverityLevel === 'HIGH')) {
            console.log("Score and severity threshold not met, exiting");
            return true;
        }
    }

    return false;
}

/**
 * Format Slack notification details. See https://api.slack.com/docs/message-formatting
 */
function buildSlackMessage(finding) {
    const consoleUrl = `https://console.aws.amazon.com/macie`;
    const remediationDescription = `*WARNING*: Clicking "Remediate" will move the offending object into quarantine bucket: *S3://${quarantineBucket}* with restricted permissions`;
    const account =  finding.accountId;
    const region =  finding.region;
    const findingId = finding.id;
    const severity = finding.severity.description;
    const findingCategory = finding.category;
    const findingTitle = finding.title;
    const findingType = finding.type;
    const findingDescription = finding.description;
    const findingTime = finding.updatedAt;
    const findingTimeEpoch = Math.floor(new Date(findingTime) / 1000);
    const findingTimeFormatted = `<!date^${findingTimeEpoch}^{date} at {time} | ${findingTime}>`;
    const objectPath = finding.resourcesAffected.s3Object.path;

    const messageContent = [
        {
            "type": "section",
            "block_id": "section1",
            "text": {
                "type": "mrkdwn",
                "text": `*Finding in ${region} for Acct: ${account}*`
            }
        },
        {
            "type": "section",
            "block_id": "section2",
            "text": {
                "type": "mrkdwn",
                "text": `*Offending Object:* \`S3://${objectPath}\` \n*Finding:* ${findingDescription}\n <${consoleUrl}/home?region=${region}#/findings?itemId=${findingId}| View Macie Finding in Console>`
            },
            "accessory": {
                "type": "image",
                "image_url": "https://raw.githubusercontent.com/nikcuneo/macie-auto-remediation/master/images/macielogo.png",
                "alt_text": "Macie image"
            }
        },
        {
            "type": "section",
            "block_id": "section3",
            "fields": [
              {
                "type": "mrkdwn",
                "text": `*Severity:*  \`${severity}\``
              },
              {
                "type": "mrkdwn",
                "text": `*Region:* ${region}`
              },
              {
                "type": "mrkdwn",
                "text": `*Account Number:* ${account}`
              },
              {
                "type": "mrkdwn",
                "text": `*Finding Category:* ${findingCategory}`
              },
              {
                "type": "mrkdwn",
                "text": `*Finding Type:* ${findingType}`
              },
              {
                "type": "mrkdwn",
                "text": `*Finding Time:* ${findingTimeFormatted}`
              }
            ]
        },
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "Remediate",
                        "emoji": true
                    },
                    "value": `${findingId}`
                }
            ]
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": `${remediationDescription}`
                }
            ]
        },
        {
            "type": "divider"
        }
    ];

    const slackMessage = {
        channel: slackChannel,
        blocks: messageContent,
        text : findingTitle,
        username: 'MacieBot',
        'mrkdwn': true,
        as_user: false
    };

    return slackMessage;
}
