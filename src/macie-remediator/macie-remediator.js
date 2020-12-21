// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

'use strict';

const AWS = require('aws-sdk');
const { postSlackMessage } = require('macie-rem-common');

const s3 = new AWS.S3();

const quarantineBucket = process.env.quarantineBucket;
const slackWebHookUrl = process.env.slackWebHookUrl;
const slackChannel = process.env.slackChannel;

//Lambda function respnosible for moving objects containing sensitive data into quarantine
exports.handler = async (event) => {
    try {
        const macieFinding = event.macieFinding;
        const slackPayload = event.slackPayload;

        await quarantineS3Object(
            macieFinding.resourcesAffected.s3Bucket.name, 
            macieFinding.resourcesAffected.s3Object.key
        );

        const slackMessage = buildSlackMessage(macieFinding, slackPayload);

        //Deliver remediation confirmation message to Slack, update initial Slack notificaiton if called via a manual auth
        const slackResponse = await postSlackMessage(slackMessage, getSlackURL(slackPayload));

        if (slackResponse.statusCode < 400) {
            console.info('Message posted successfully');
        } else if (slackResponse.statusCode < 500) {
            console.error(`Error posting message to Slack API: ${slackResponse.statusCode} - ${slackResponse.statusMessage} - ${slackResponse.body}`);
        } else {
            console.error(`Slack server error when processing message: ${slackResponse.statusCode} - ${slackResponse.statusMessage} - ${slackResponse.body}`);
        }
    } catch (err) {
        console.error(err);
    }
};

//Determine which URL to use to post the message. If a manual auth get the response URL from the incoming Slack payload
function getSlackURL(slackPayload) {
    return (slackPayload ? slackPayload.response_url : slackWebHookUrl);
}

async function quarantineS3Object(offendingBucket, offendingKey) {
    await copyObjectToQuarantine(offendingBucket, offendingKey);
    await deleteFromInitialLocation(offendingBucket, offendingKey);
}

async function copyObjectToQuarantine(offendingBucket, offendingKey) {
    try {
        await s3.copyObject({
            Bucket: quarantineBucket,
            CopySource: encodeURI(offendingBucket + '/' + offendingKey),
            Key: offendingBucket + '/' + offendingKey
        }).promise();
    } catch (err) {
        console.error(`Unable to copy object to quarantine bucket (${offendingBucket}/${offendingKey})`);
        throw err;
    }
}

async function deleteFromInitialLocation(offendingBucket, offendingKey) {
    try {
        await s3.deleteObject({
            Bucket: offendingBucket,
            Key: offendingKey
        }).promise();
    } catch (err) {
        console.error(`Unable to delete object from source bucket (${offendingBucket}/${offendingKey})`);
        throw err;
    }
}

/**
 * Format Slack remediation notification details
 * See https://api.slack.com/docs/message-formatting
 */
function buildSlackMessage(findingObject, slackPayload) {
    const consoleUrl = `https://console.aws.amazon.com/macie`;
    const account =  findingObject.accountId;
    const region =  findingObject.region;
    const findingId = findingObject.id;
    const findingCategory = findingObject.category;
    const findingTitle = findingObject.title;
    const findingTime = findingObject.updatedAt;
    const findingTimeEpoch = Math.floor(new Date(findingTime) / 1000);
    const findingTimeFormatted = `<!date^${findingTimeEpoch}^{date} at {time} | ${findingTime}>`;
    const objectPath = findingObject.resourcesAffected.s3Object.path;
    const severity = findingObject.severity.description;

    console.log("Building slack response message");

    const messageContent = [
            {
                "type": "section",
                "block_id": "section1",
                "text": {
                    "type": "mrkdwn",
                    "text": `${slackPayload ? `*Finding REMDIATED in ${region} for Acct: ${account}* :white_check_mark:` : `*Finding AUTO-REMDIATED in ${region} for Acct: ${account}* :white_check_mark:`}`
                }
            },
            {
                "type": "section",
                "block_id": "section2",
                "text": {
                    "type": "mrkdwn",
                    "text": `${slackPayload ? `Remediation authorised by: @${slackPayload.user.username}` : ''} \nOffending Object: \`S3://${objectPath}\` has been isolated to quarantine bucket: \`S3://${quarantineBucket}\` \n <${consoleUrl}/home?region=${region}#/findings?itemId=${findingId}| View Macie Finding in Console>`
                }
            } ,
            {
                "type": "section",
                "block_id": "section3",
                "fields": [
                {
                    "type": "mrkdwn",
                    "text": `*Finding Type:* ${findingTitle}`
                  },
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
                    "text": `*Finding Time:* ${findingTimeFormatted}`
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
        text: `${slackPayload ? `*Finding REMDIATED in ${region} for Acct: ${account}* :white_check_mark:` : `*Finding AUTO-REMDIATED in ${region} for Acct: ${account}* :white_check_mark:`}`,
        username: 'MacieBot',
        'mrkdwn': true,
        as_user: false
    };

    return slackMessage;
}
