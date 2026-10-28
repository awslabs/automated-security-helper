// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Gives the built-in node the label "linux". Jenkinsfile Runner runs a pipeline on the
// built-in node only, and the Jenkinsfile on the CI pages asks for
// `agent { label 'linux' }`; without the label the build would wait for an agent that
// never comes. Passed to Jenkinsfile Runner with --withInitHooks.
import jenkins.model.Jenkins

Jenkins.get().setLabelString('linux')
