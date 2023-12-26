import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
// import * as sqs from 'aws-cdk-lib/aws-sqs';

export class CdkNagScanStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // The code that defines your stack goes here

    // example resource
    // const queue = new sqs.Queue(this, 'CdkNagScanQueue', {
    //   visibilityTimeout: cdk.Duration.seconds(300)
    // });

    const templateFileName = this.node.tryGetContext('fileName');

    if ( templateFileName != undefined ) {
      try {
        const cfnTemplate = new cdk.cloudformation_include.CfnInclude(this, templateFileName, {
          templateFile: templateFileName
        });
      } catch(error) {
        let message = ''
        if ( error instanceof Error ) {
          message = error.message
        } else {
          message = 'unknown caught type'
        }
        console.log(`Error calling CfnInclude, Error: ${message}`)
      }
  
    } else {
      console.log(`Context parameter "fileName" must be set!`)
    }
  }
}
