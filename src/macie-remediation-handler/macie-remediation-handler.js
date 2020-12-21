// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

'use strict';

const AWS = require('aws-sdk');
const querystring = require('querystring');
const crypto = require('crypto');
const timingSafeCompare = require('tsscmp');
const { invokeRemediationLambda } = require('macie-rem-common');


const MACIE = new AWS.Macie2();

const slackSigningSecret = process.env.slackSigningSecret;

// API Gateway compatible response helper
const response = (statusCode, body) => ({
    statusCode,
    body: JSON.stringify(body),
});

//Lambda function called by API Gateway when emediation requests triggered from Slack
exports.handler = async (event) => {
    
    //Parse urlencoded payload from Slack
    const parsedPayload = querystring.parse(event.body);
    const reqPayload = JSON.parse(parsedPayload.payload);

    try {
        isValidRequestSig(event.headers, event.body);
    } catch (err) {
        console.error(err);
        return response(401, err);
    }

    try {
        //Retrieve Macie Finding for which remediation has been requested
        const findingsResp = await retrieveFindingDetails(reqPayload.actions[0].value).promise();
        const finding = findingsResp.findings[0];
        if (!finding) {
            console.error(`No finding found for id: ${reqPayload.actions[0].value}`);
            return response(400, { text: "Error: Finding not found" });
        }
        
        //Validate finding is from a sensitive data discovery job
        if (finding.category !== 'CLASSIFICATION') {
            console.error(`Remediation requested on unsupported finding category: ${finding.category}  FindingID: ${reqPayload.findingId}`);
            return response(400, { text: "Error: Remediation not supported for this finding type" });
        }

        const lambdaPayload = {
            macieFinding: finding,
            slackPayload: reqPayload
        };

        //Async invoke of remediation lambda 
        await invokeRemediationLambda(lambdaPayload);

        //Notify Slack that remediation request has been acknowledge. 
        return response(200, { text: "request acknowledged" });

    } catch (err) {
        console.error(err);
        return response(500, err);
    }
};


/**
 * Validate request originated from trusted Slack channel
 */
function isValidRequestSig(requestHeaders, body) {

    const signature = requestHeaders['X-Slack-Signature'];
    const ts = requestHeaders['X-Slack-Request-Timestamp'];

    // Divide current date to match Slack ts format
    // Subtract 5 minutes from current time
    const fiveMinutesAgo = Math.floor(Date.now() / 1000) - (60 * 5);

    if (ts < fiveMinutesAgo) {
      console.error('request is older than 5 minutes');
      throw new Error('Slack request signing verification failed');
    }

    const hmac = crypto.createHmac('sha256', slackSigningSecret);
    const [version, hash] = signature.split('=');
    hmac.update(`${version}:${ts}:${body}`);

    if (!timingSafeCompare(hash, hmac.digest('hex'))) {
      console.error('request signature is not valid');
      throw new Error('Slack request signing verification failed');
    }
}


/**
 * Load Macie finding details referenced by remediation call
 */
function retrieveFindingDetails(findingId) {

    var params = {
        findingIds: [findingId]
      };
    
      return MACIE.getFindings(params);
}
