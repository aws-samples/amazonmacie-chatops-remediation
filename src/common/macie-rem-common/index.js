// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

const AWS = require('aws-sdk');
const url = require('url');
const https = require('https');

const LAMBDA = new AWS.Lambda();

/**
 * Post message to Slack endpoint
 */
function postSlackMessage(message, slackUrl) {
    const body = JSON.stringify(message);
    const options = url.parse(slackUrl);

    options.method = 'POST';
    options.headers = {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
    };

    return new Promise((resolve, reject) => {
        const req = https.request(options, (res) => {
            res.setEncoding('utf8');
            // Response object.
            let response = {
                statusCode: res.statusCode,
                headers: res.headers,
                body: []
            };

            res.on('data', (chunk) => {
                response.body.push(chunk);
            });

            res.on('end', () => {
                resolve(res);
            });
        });

        req.on('error', (err) => {
            reject(err);
        });

        req.write(body);
        req.end();
    });
}


/**
 * Async invoke lambda function to remediate Macie finding
 */
function invokeRemediationLambda(payload) {
    const params = {
        FunctionName: 'macie-remediator',
        InvocationType: 'Event',
        Payload: JSON.stringify(payload)
    };

    return new Promise((resolve, reject) => {
        LAMBDA.invoke(params, (err, data) => {
            if (err) {
                console.log(err, err.stack);
                reject(err);
            }
            else {
                console.log(data);
                resolve(data);
            }
        });
    });
}
exports.invokeRemediationLambda = invokeRemediationLambda;
exports.postSlackMessage = postSlackMessage;
