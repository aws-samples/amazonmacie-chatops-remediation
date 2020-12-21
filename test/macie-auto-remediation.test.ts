import { expect as expectCDK, matchTemplate, MatchStyle } from '@aws-cdk/assert';
import * as cdk from '@aws-cdk/core';
import * as MacieAutoRemediation from '../lib/macie-auto-remediation-stack';

test('Empty Stack', () => {
    const app = new cdk.App();
    // WHEN
    const stack = new MacieAutoRemediation.MacieAutoRemediationStack(app, 'MyTestStack');
    // THEN
    expectCDK(stack).to(matchTemplate({
      "Resources": {}
    }, MatchStyle.EXACT))
});
