# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from importlib.metadata import version


def get_ash_version():
    return version("automated_security_helper")
