#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { CdkNagScanStack } from '../lib/cdk-nag-scan-stack';
import { AwsSolutionsChecks } from 'cdk-nag';

const app = new cdk.App();

const templateFileName = app.node.tryGetContext('fileName');
if (!templateFileName) {
  throw new Error('fileName is required');
}

var stackName = templateFileName
  .replace(/\/(src|run|out|work)\//, '')
  .replace(/[\W_]+/gi, '-')
  .replace(/^-+/, '');

if (stackName.length > 128) {
  stackName = stackName.substr(stackName.length - 128, stackName.length);
}

new CdkNagScanStack(app, stackName);

cdk.Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));

app.synth();
