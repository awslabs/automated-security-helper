# ASH Quickstart

The purpose of this template is to deploy an AWS Cloud9 Environment with ASH and all the dependencies pre-installed.

This quickstart is designed for **learning purposes only**. The user will be responsible for any patching strategy, network protection and access controls to the instance.

By default, the owner of the AWS Cloud9 Environment will be the user that launched the CloudFormation stackset.

## Pre-requisites

1. An AWS Account and enough permissions to deploy a CloudFormation Stack.

## Installation

1. Download the [template](./c9template.yaml) to your local machine, or clone this repository.
1. Log into your AWS Console
1. Navigate to the AWS CloudFormation console in your region of choice. You can use [this](https://console.aws.amazon.com/cloudformation/home) link.
1. Select `Create stack`
1. In `Specify template` section, select `Upload a template file` option.
1. Use the `Choose file` option to select the template file (`c9template.yaml`) from your local machine and select `Next`.
1. Specify a descriptive `Stack name` (for example `ASH-TestStack`)
1. Select `Next` and accept the default settings on the following screen. Select `Next` again until reaching the last step (`Review ASH-TestStack`).
1. Accept the IAM resource acknowledgement `I acknowledge that AWS CloudFormation might create IAM resources with custom names.` and select Submit to create the Stack.
1. Wait until the Stack is created and status is `CREATE_COMPLETE`.
1. Navigate to the AWS Cloud9 Console. You can use [this](https://console.aws.amazon.com/cloud9control/home) link.
1. Use the `Open` link to access your AWS Cloud9 Environment.
1. You can confirm that ASH is installed properly by running `ash -v` in the terminal. It will take a few minutes for the bootstrap process to complete, wait until you see an empty file with the name `ASH-READY` under  `/home/ec2-user/environment`. If you already launched a terminal, refresh the `PATH` environment variable by running `source ~/.bashrc` on your terminal and try again or close the terminal and launch a new one.


## Troubleshooting

If the stack fails to deploy, check the error message in CloudFormation under the `Event` tabs.  In general errors are very descriptive about the reasons for the failure. For example:

```
ash-admin already exists in stack arn:aws:cloudformation:us-east-1:123456789012:stack/ASHC9/c0426010-c99c-11ed-85fd-0e5951eaa6e5
```

In this case, another environment with the same name already exists. You will need to delete the old stack or change the Environment name.

## Additional information

- [AWS Cloud9 User Guide](https://docs.aws.amazon.com/cloud9/latest/user-guide/welcome.html)
- [AWS CloudFormation User Guide](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/Welcome.html)
- [AWS CloudFormation Troubleshooting](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/troubleshooting.html)