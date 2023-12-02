#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { CdkNagScanStack } from '../lib/cdk-nag-scan-stack';
import { AwsSolutionsChecks } from 'cdk-nag';

const app = new cdk.App();
new CdkNagScanStack(app, 'CdkNagScanStack');

cdk.Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));

app.synth();
