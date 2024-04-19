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

/*
 * This uses the input file name to generate the temp stack name.
 * The temp stack name uses up to 128 characters of the path-name
 * (CloudFormation stack name length limit) to the CloudFormation
 * template that is found, slugifying non-whitespace characters to
 * scalar hyphens (-).
 *
 * This is done to ensure that the output files are unique and do
 * not overwrite each other when a scanned repository has multiple
 * CloudFormation template found to scan.
 */
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
