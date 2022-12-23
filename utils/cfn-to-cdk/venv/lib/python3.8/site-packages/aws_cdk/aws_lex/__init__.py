'''
# AWS::Lex Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_lex as lex
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-lex-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::Lex](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_Lex.html).

(Read the [CDK Contributing Guide](https://github.com/aws/aws-cdk/blob/master/CONTRIBUTING.md) if you are interested in contributing to this construct library.)

<!--END CFNONLY DISCLAIMER-->
'''
import abc
import builtins
import datetime
import enum
import typing

import jsii
import publication
import typing_extensions

from .._jsii import *

import constructs
from .. import (
    CfnResource as _CfnResource_9df397a6,
    CfnTag as _CfnTag_f6864754,
    IInspectable as _IInspectable_c2943556,
    IResolvable as _IResolvable_da3f097b,
    TreeInspector as _TreeInspector_488e0dd5,
)


@jsii.implements(_IInspectable_c2943556)
class CfnBot(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_lex.CfnBot",
):
    '''A CloudFormation ``AWS::Lex::Bot``.

    Specifies an Amazon Lex conversational bot.

    You must configure an intent based on the AMAZON.FallbackIntent built-in intent. If you don't add one, creating the bot will fail.

    :cloudformationResource: AWS::Lex::Bot
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-bot.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_lex as lex
        
        # data_privacy: Any
        
        cfn_bot = lex.CfnBot(self, "MyCfnBot",
            data_privacy=data_privacy,
            idle_session_ttl_in_seconds=123,
            name="name",
            role_arn="roleArn",
        
            # the properties below are optional
            auto_build_bot_locales=False,
            bot_file_s3_location=lex.CfnBot.S3LocationProperty(
                s3_bucket="s3Bucket",
                s3_object_key="s3ObjectKey",
        
                # the properties below are optional
                s3_object_version="s3ObjectVersion"
            ),
            bot_locales=[lex.CfnBot.BotLocaleProperty(
                locale_id="localeId",
                nlu_confidence_threshold=123,
        
                # the properties below are optional
                description="description",
                intents=[lex.CfnBot.IntentProperty(
                    name="name",
        
                    # the properties below are optional
                    description="description",
                    dialog_code_hook=lex.CfnBot.DialogCodeHookSettingProperty(
                        enabled=False
                    ),
                    fulfillment_code_hook=lex.CfnBot.FulfillmentCodeHookSettingProperty(
                        enabled=False,
        
                        # the properties below are optional
                        fulfillment_updates_specification=lex.CfnBot.FulfillmentUpdatesSpecificationProperty(
                            active=False,
        
                            # the properties below are optional
                            start_response=lex.CfnBot.FulfillmentStartResponseSpecificationProperty(
                                delay_in_seconds=123,
                                message_groups=[lex.CfnBot.MessageGroupProperty(
                                    message=lex.CfnBot.MessageProperty(
                                        custom_payload=lex.CfnBot.CustomPayloadProperty(
                                            value="value"
                                        ),
                                        image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                            title="title",
        
                                            # the properties below are optional
                                            buttons=[lex.CfnBot.ButtonProperty(
                                                text="text",
                                                value="value"
                                            )],
                                            image_url="imageUrl",
                                            subtitle="subtitle"
                                        ),
                                        plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                            value="value"
                                        ),
                                        ssml_message=lex.CfnBot.SSMLMessageProperty(
                                            value="value"
                                        )
                                    ),
        
                                    # the properties below are optional
                                    variations=[lex.CfnBot.MessageProperty(
                                        custom_payload=lex.CfnBot.CustomPayloadProperty(
                                            value="value"
                                        ),
                                        image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                            title="title",
        
                                            # the properties below are optional
                                            buttons=[lex.CfnBot.ButtonProperty(
                                                text="text",
                                                value="value"
                                            )],
                                            image_url="imageUrl",
                                            subtitle="subtitle"
                                        ),
                                        plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                            value="value"
                                        ),
                                        ssml_message=lex.CfnBot.SSMLMessageProperty(
                                            value="value"
                                        )
                                    )]
                                )],
        
                                # the properties below are optional
                                allow_interrupt=False
                            ),
                            timeout_in_seconds=123,
                            update_response=lex.CfnBot.FulfillmentUpdateResponseSpecificationProperty(
                                frequency_in_seconds=123,
                                message_groups=[lex.CfnBot.MessageGroupProperty(
                                    message=lex.CfnBot.MessageProperty(
                                        custom_payload=lex.CfnBot.CustomPayloadProperty(
                                            value="value"
                                        ),
                                        image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                            title="title",
        
                                            # the properties below are optional
                                            buttons=[lex.CfnBot.ButtonProperty(
                                                text="text",
                                                value="value"
                                            )],
                                            image_url="imageUrl",
                                            subtitle="subtitle"
                                        ),
                                        plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                            value="value"
                                        ),
                                        ssml_message=lex.CfnBot.SSMLMessageProperty(
                                            value="value"
                                        )
                                    ),
        
                                    # the properties below are optional
                                    variations=[lex.CfnBot.MessageProperty(
                                        custom_payload=lex.CfnBot.CustomPayloadProperty(
                                            value="value"
                                        ),
                                        image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                            title="title",
        
                                            # the properties below are optional
                                            buttons=[lex.CfnBot.ButtonProperty(
                                                text="text",
                                                value="value"
                                            )],
                                            image_url="imageUrl",
                                            subtitle="subtitle"
                                        ),
                                        plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                            value="value"
                                        ),
                                        ssml_message=lex.CfnBot.SSMLMessageProperty(
                                            value="value"
                                        )
                                    )]
                                )],
        
                                # the properties below are optional
                                allow_interrupt=False
                            )
                        ),
                        post_fulfillment_status_specification=lex.CfnBot.PostFulfillmentStatusSpecificationProperty(
                            failure_response=lex.CfnBot.ResponseSpecificationProperty(
                                message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                    message=lex.CfnBot.MessageProperty(
                                        custom_payload=lex.CfnBot.CustomPayloadProperty(
                                            value="value"
                                        ),
                                        image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                            title="title",
        
                                            # the properties below are optional
                                            buttons=[lex.CfnBot.ButtonProperty(
                                                text="text",
                                                value="value"
                                            )],
                                            image_url="imageUrl",
                                            subtitle="subtitle"
                                        ),
                                        plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                            value="value"
                                        ),
                                        ssml_message=lex.CfnBot.SSMLMessageProperty(
                                            value="value"
                                        )
                                    ),
        
                                    # the properties below are optional
                                    variations=[lex.CfnBot.MessageProperty(
                                        custom_payload=lex.CfnBot.CustomPayloadProperty(
                                            value="value"
                                        ),
                                        image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                            title="title",
        
                                            # the properties below are optional
                                            buttons=[lex.CfnBot.ButtonProperty(
                                                text="text",
                                                value="value"
                                            )],
                                            image_url="imageUrl",
                                            subtitle="subtitle"
                                        ),
                                        plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                            value="value"
                                        ),
                                        ssml_message=lex.CfnBot.SSMLMessageProperty(
                                            value="value"
                                        )
                                    )]
                                )],
        
                                # the properties below are optional
                                allow_interrupt=False
                            ),
                            success_response=lex.CfnBot.ResponseSpecificationProperty(
                                message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                    message=lex.CfnBot.MessageProperty(
                                        custom_payload=lex.CfnBot.CustomPayloadProperty(
                                            value="value"
                                        ),
                                        image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                            title="title",
        
                                            # the properties below are optional
                                            buttons=[lex.CfnBot.ButtonProperty(
                                                text="text",
                                                value="value"
                                            )],
                                            image_url="imageUrl",
                                            subtitle="subtitle"
                                        ),
                                        plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                            value="value"
                                        ),
                                        ssml_message=lex.CfnBot.SSMLMessageProperty(
                                            value="value"
                                        )
                                    ),
        
                                    # the properties below are optional
                                    variations=[lex.CfnBot.MessageProperty(
                                        custom_payload=lex.CfnBot.CustomPayloadProperty(
                                            value="value"
                                        ),
                                        image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                            title="title",
        
                                            # the properties below are optional
                                            buttons=[lex.CfnBot.ButtonProperty(
                                                text="text",
                                                value="value"
                                            )],
                                            image_url="imageUrl",
                                            subtitle="subtitle"
                                        ),
                                        plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                            value="value"
                                        ),
                                        ssml_message=lex.CfnBot.SSMLMessageProperty(
                                            value="value"
                                        )
                                    )]
                                )],
        
                                # the properties below are optional
                                allow_interrupt=False
                            ),
                            timeout_response=lex.CfnBot.ResponseSpecificationProperty(
                                message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                    message=lex.CfnBot.MessageProperty(
                                        custom_payload=lex.CfnBot.CustomPayloadProperty(
                                            value="value"
                                        ),
                                        image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                            title="title",
        
                                            # the properties below are optional
                                            buttons=[lex.CfnBot.ButtonProperty(
                                                text="text",
                                                value="value"
                                            )],
                                            image_url="imageUrl",
                                            subtitle="subtitle"
                                        ),
                                        plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                            value="value"
                                        ),
                                        ssml_message=lex.CfnBot.SSMLMessageProperty(
                                            value="value"
                                        )
                                    ),
        
                                    # the properties below are optional
                                    variations=[lex.CfnBot.MessageProperty(
                                        custom_payload=lex.CfnBot.CustomPayloadProperty(
                                            value="value"
                                        ),
                                        image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                            title="title",
        
                                            # the properties below are optional
                                            buttons=[lex.CfnBot.ButtonProperty(
                                                text="text",
                                                value="value"
                                            )],
                                            image_url="imageUrl",
                                            subtitle="subtitle"
                                        ),
                                        plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                            value="value"
                                        ),
                                        ssml_message=lex.CfnBot.SSMLMessageProperty(
                                            value="value"
                                        )
                                    )]
                                )],
        
                                # the properties below are optional
                                allow_interrupt=False
                            )
                        )
                    ),
                    input_contexts=[lex.CfnBot.InputContextProperty(
                        name="name"
                    )],
                    intent_closing_setting=lex.CfnBot.IntentClosingSettingProperty(
                        closing_response=lex.CfnBot.ResponseSpecificationProperty(
                            message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                message=lex.CfnBot.MessageProperty(
                                    custom_payload=lex.CfnBot.CustomPayloadProperty(
                                        value="value"
                                    ),
                                    image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                        title="title",
        
                                        # the properties below are optional
                                        buttons=[lex.CfnBot.ButtonProperty(
                                            text="text",
                                            value="value"
                                        )],
                                        image_url="imageUrl",
                                        subtitle="subtitle"
                                    ),
                                    plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                        value="value"
                                    ),
                                    ssml_message=lex.CfnBot.SSMLMessageProperty(
                                        value="value"
                                    )
                                ),
        
                                # the properties below are optional
                                variations=[lex.CfnBot.MessageProperty(
                                    custom_payload=lex.CfnBot.CustomPayloadProperty(
                                        value="value"
                                    ),
                                    image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                        title="title",
        
                                        # the properties below are optional
                                        buttons=[lex.CfnBot.ButtonProperty(
                                            text="text",
                                            value="value"
                                        )],
                                        image_url="imageUrl",
                                        subtitle="subtitle"
                                    ),
                                    plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                        value="value"
                                    ),
                                    ssml_message=lex.CfnBot.SSMLMessageProperty(
                                        value="value"
                                    )
                                )]
                            )],
        
                            # the properties below are optional
                            allow_interrupt=False
                        ),
        
                        # the properties below are optional
                        is_active=False
                    ),
                    intent_confirmation_setting=lex.CfnBot.IntentConfirmationSettingProperty(
                        declination_response=lex.CfnBot.ResponseSpecificationProperty(
                            message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                message=lex.CfnBot.MessageProperty(
                                    custom_payload=lex.CfnBot.CustomPayloadProperty(
                                        value="value"
                                    ),
                                    image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                        title="title",
        
                                        # the properties below are optional
                                        buttons=[lex.CfnBot.ButtonProperty(
                                            text="text",
                                            value="value"
                                        )],
                                        image_url="imageUrl",
                                        subtitle="subtitle"
                                    ),
                                    plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                        value="value"
                                    ),
                                    ssml_message=lex.CfnBot.SSMLMessageProperty(
                                        value="value"
                                    )
                                ),
        
                                # the properties below are optional
                                variations=[lex.CfnBot.MessageProperty(
                                    custom_payload=lex.CfnBot.CustomPayloadProperty(
                                        value="value"
                                    ),
                                    image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                        title="title",
        
                                        # the properties below are optional
                                        buttons=[lex.CfnBot.ButtonProperty(
                                            text="text",
                                            value="value"
                                        )],
                                        image_url="imageUrl",
                                        subtitle="subtitle"
                                    ),
                                    plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                        value="value"
                                    ),
                                    ssml_message=lex.CfnBot.SSMLMessageProperty(
                                        value="value"
                                    )
                                )]
                            )],
        
                            # the properties below are optional
                            allow_interrupt=False
                        ),
                        prompt_specification=lex.CfnBot.PromptSpecificationProperty(
                            max_retries=123,
                            message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                message=lex.CfnBot.MessageProperty(
                                    custom_payload=lex.CfnBot.CustomPayloadProperty(
                                        value="value"
                                    ),
                                    image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                        title="title",
        
                                        # the properties below are optional
                                        buttons=[lex.CfnBot.ButtonProperty(
                                            text="text",
                                            value="value"
                                        )],
                                        image_url="imageUrl",
                                        subtitle="subtitle"
                                    ),
                                    plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                        value="value"
                                    ),
                                    ssml_message=lex.CfnBot.SSMLMessageProperty(
                                        value="value"
                                    )
                                ),
        
                                # the properties below are optional
                                variations=[lex.CfnBot.MessageProperty(
                                    custom_payload=lex.CfnBot.CustomPayloadProperty(
                                        value="value"
                                    ),
                                    image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                        title="title",
        
                                        # the properties below are optional
                                        buttons=[lex.CfnBot.ButtonProperty(
                                            text="text",
                                            value="value"
                                        )],
                                        image_url="imageUrl",
                                        subtitle="subtitle"
                                    ),
                                    plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                        value="value"
                                    ),
                                    ssml_message=lex.CfnBot.SSMLMessageProperty(
                                        value="value"
                                    )
                                )]
                            )],
        
                            # the properties below are optional
                            allow_interrupt=False
                        ),
        
                        # the properties below are optional
                        is_active=False
                    ),
                    kendra_configuration=lex.CfnBot.KendraConfigurationProperty(
                        kendra_index="kendraIndex",
        
                        # the properties below are optional
                        query_filter_string="queryFilterString",
                        query_filter_string_enabled=False
                    ),
                    output_contexts=[lex.CfnBot.OutputContextProperty(
                        name="name",
                        time_to_live_in_seconds=123,
                        turns_to_live=123
                    )],
                    parent_intent_signature="parentIntentSignature",
                    sample_utterances=[lex.CfnBot.SampleUtteranceProperty(
                        utterance="utterance"
                    )],
                    slot_priorities=[lex.CfnBot.SlotPriorityProperty(
                        priority=123,
                        slot_name="slotName"
                    )],
                    slots=[lex.CfnBot.SlotProperty(
                        name="name",
                        slot_type_name="slotTypeName",
                        value_elicitation_setting=lex.CfnBot.SlotValueElicitationSettingProperty(
                            slot_constraint="slotConstraint",
        
                            # the properties below are optional
                            default_value_specification=lex.CfnBot.SlotDefaultValueSpecificationProperty(
                                default_value_list=[lex.CfnBot.SlotDefaultValueProperty(
                                    default_value="defaultValue"
                                )]
                            ),
                            prompt_specification=lex.CfnBot.PromptSpecificationProperty(
                                max_retries=123,
                                message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                    message=lex.CfnBot.MessageProperty(
                                        custom_payload=lex.CfnBot.CustomPayloadProperty(
                                            value="value"
                                        ),
                                        image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                            title="title",
        
                                            # the properties below are optional
                                            buttons=[lex.CfnBot.ButtonProperty(
                                                text="text",
                                                value="value"
                                            )],
                                            image_url="imageUrl",
                                            subtitle="subtitle"
                                        ),
                                        plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                            value="value"
                                        ),
                                        ssml_message=lex.CfnBot.SSMLMessageProperty(
                                            value="value"
                                        )
                                    ),
        
                                    # the properties below are optional
                                    variations=[lex.CfnBot.MessageProperty(
                                        custom_payload=lex.CfnBot.CustomPayloadProperty(
                                            value="value"
                                        ),
                                        image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                            title="title",
        
                                            # the properties below are optional
                                            buttons=[lex.CfnBot.ButtonProperty(
                                                text="text",
                                                value="value"
                                            )],
                                            image_url="imageUrl",
                                            subtitle="subtitle"
                                        ),
                                        plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                            value="value"
                                        ),
                                        ssml_message=lex.CfnBot.SSMLMessageProperty(
                                            value="value"
                                        )
                                    )]
                                )],
        
                                # the properties below are optional
                                allow_interrupt=False
                            ),
                            sample_utterances=[lex.CfnBot.SampleUtteranceProperty(
                                utterance="utterance"
                            )],
                            wait_and_continue_specification=lex.CfnBot.WaitAndContinueSpecificationProperty(
                                continue_response=lex.CfnBot.ResponseSpecificationProperty(
                                    message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                        message=lex.CfnBot.MessageProperty(
                                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                value="value"
                                            ),
                                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                title="title",
        
                                                # the properties below are optional
                                                buttons=[lex.CfnBot.ButtonProperty(
                                                    text="text",
                                                    value="value"
                                                )],
                                                image_url="imageUrl",
                                                subtitle="subtitle"
                                            ),
                                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                value="value"
                                            ),
                                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                value="value"
                                            )
                                        ),
        
                                        # the properties below are optional
                                        variations=[lex.CfnBot.MessageProperty(
                                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                value="value"
                                            ),
                                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                title="title",
        
                                                # the properties below are optional
                                                buttons=[lex.CfnBot.ButtonProperty(
                                                    text="text",
                                                    value="value"
                                                )],
                                                image_url="imageUrl",
                                                subtitle="subtitle"
                                            ),
                                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                value="value"
                                            ),
                                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                value="value"
                                            )
                                        )]
                                    )],
        
                                    # the properties below are optional
                                    allow_interrupt=False
                                ),
                                waiting_response=lex.CfnBot.ResponseSpecificationProperty(
                                    message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                        message=lex.CfnBot.MessageProperty(
                                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                value="value"
                                            ),
                                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                title="title",
        
                                                # the properties below are optional
                                                buttons=[lex.CfnBot.ButtonProperty(
                                                    text="text",
                                                    value="value"
                                                )],
                                                image_url="imageUrl",
                                                subtitle="subtitle"
                                            ),
                                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                value="value"
                                            ),
                                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                value="value"
                                            )
                                        ),
        
                                        # the properties below are optional
                                        variations=[lex.CfnBot.MessageProperty(
                                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                value="value"
                                            ),
                                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                title="title",
        
                                                # the properties below are optional
                                                buttons=[lex.CfnBot.ButtonProperty(
                                                    text="text",
                                                    value="value"
                                                )],
                                                image_url="imageUrl",
                                                subtitle="subtitle"
                                            ),
                                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                value="value"
                                            ),
                                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                value="value"
                                            )
                                        )]
                                    )],
        
                                    # the properties below are optional
                                    allow_interrupt=False
                                ),
        
                                # the properties below are optional
                                is_active=False,
                                still_waiting_response=lex.CfnBot.StillWaitingResponseSpecificationProperty(
                                    frequency_in_seconds=123,
                                    message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                        message=lex.CfnBot.MessageProperty(
                                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                value="value"
                                            ),
                                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                title="title",
        
                                                # the properties below are optional
                                                buttons=[lex.CfnBot.ButtonProperty(
                                                    text="text",
                                                    value="value"
                                                )],
                                                image_url="imageUrl",
                                                subtitle="subtitle"
                                            ),
                                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                value="value"
                                            ),
                                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                value="value"
                                            )
                                        ),
        
                                        # the properties below are optional
                                        variations=[lex.CfnBot.MessageProperty(
                                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                value="value"
                                            ),
                                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                title="title",
        
                                                # the properties below are optional
                                                buttons=[lex.CfnBot.ButtonProperty(
                                                    text="text",
                                                    value="value"
                                                )],
                                                image_url="imageUrl",
                                                subtitle="subtitle"
                                            ),
                                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                value="value"
                                            ),
                                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                value="value"
                                            )
                                        )]
                                    )],
                                    timeout_in_seconds=123,
        
                                    # the properties below are optional
                                    allow_interrupt=False
                                )
                            )
                        ),
        
                        # the properties below are optional
                        description="description",
                        multiple_values_setting=lex.CfnBot.MultipleValuesSettingProperty(
                            allow_multiple_values=False
                        ),
                        obfuscation_setting=lex.CfnBot.ObfuscationSettingProperty(
                            obfuscation_setting_type="obfuscationSettingType"
                        )
                    )]
                )],
                slot_types=[lex.CfnBot.SlotTypeProperty(
                    name="name",
        
                    # the properties below are optional
                    description="description",
                    external_source_setting=lex.CfnBot.ExternalSourceSettingProperty(
                        grammar_slot_type_setting=lex.CfnBot.GrammarSlotTypeSettingProperty(
                            source=lex.CfnBot.GrammarSlotTypeSourceProperty(
                                s3_bucket_name="s3BucketName",
                                s3_object_key="s3ObjectKey",
        
                                # the properties below are optional
                                kms_key_arn="kmsKeyArn"
                            )
                        )
                    ),
                    parent_slot_type_signature="parentSlotTypeSignature",
                    slot_type_values=[lex.CfnBot.SlotTypeValueProperty(
                        sample_value=lex.CfnBot.SampleValueProperty(
                            value="value"
                        ),
        
                        # the properties below are optional
                        synonyms=[lex.CfnBot.SampleValueProperty(
                            value="value"
                        )]
                    )],
                    value_selection_setting=lex.CfnBot.SlotValueSelectionSettingProperty(
                        resolution_strategy="resolutionStrategy",
        
                        # the properties below are optional
                        regex_filter=lex.CfnBot.SlotValueRegexFilterProperty(
                            pattern="pattern"
                        )
                    )
                )],
                voice_settings=lex.CfnBot.VoiceSettingsProperty(
                    voice_id="voiceId"
                )
            )],
            bot_tags=[CfnTag(
                key="key",
                value="value"
            )],
            description="description",
            test_bot_alias_tags=[CfnTag(
                key="key",
                value="value"
            )]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        data_privacy: typing.Any,
        idle_session_ttl_in_seconds: jsii.Number,
        name: builtins.str,
        role_arn: builtins.str,
        auto_build_bot_locales: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        bot_file_s3_location: typing.Optional[typing.Union["CfnBot.S3LocationProperty", _IResolvable_da3f097b]] = None,
        bot_locales: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBot.BotLocaleProperty", _IResolvable_da3f097b]]]] = None,
        bot_tags: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]] = None,
        description: typing.Optional[builtins.str] = None,
        test_bot_alias_tags: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]] = None,
    ) -> None:
        '''Create a new ``AWS::Lex::Bot``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param data_privacy: Provides information on additional privacy protections Amazon Lex should use with the bot's data.
        :param idle_session_ttl_in_seconds: The time, in seconds, that Amazon Lex should keep information about a user's conversation with the bot. A user interaction remains active for the amount of time specified. If no conversation occurs during this time, the session expires and Amazon Lex deletes any data provided before the timeout. You can specify between 60 (1 minute) and 86,400 (24 hours) seconds.
        :param name: The name of the field to filter the list of bots.
        :param role_arn: The Amazon Resource Name (ARN) of the IAM role used to build and run the bot.
        :param auto_build_bot_locales: Indicates whether Amazon Lex V2 should automatically build the locales for the bot after a change.
        :param bot_file_s3_location: The Amazon S3 location of files used to import a bot. The files must be in the import format specified in `JSON format for importing and exporting <https://docs.aws.amazon.com/lexv2/latest/dg/import-export-format.html>`_ in the *Amazon Lex developer guide.*
        :param bot_locales: A list of locales for the bot.
        :param bot_tags: A list of tags to add to the bot. You can only add tags when you import a bot. You can't use the ``UpdateBot`` operation to update tags. To update tags, use the ``TagResource`` operation.
        :param description: The description of the version.
        :param test_bot_alias_tags: A list of tags to add to the test alias for a bot. You can only add tags when you import a bot. You can't use the ``UpdateAlias`` operation to update tags. To update tags on the test alias, use the ``TagResource`` operation.
        '''
        props = CfnBotProps(
            data_privacy=data_privacy,
            idle_session_ttl_in_seconds=idle_session_ttl_in_seconds,
            name=name,
            role_arn=role_arn,
            auto_build_bot_locales=auto_build_bot_locales,
            bot_file_s3_location=bot_file_s3_location,
            bot_locales=bot_locales,
            bot_tags=bot_tags,
            description=description,
            test_bot_alias_tags=test_bot_alias_tags,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="inspect")
    def inspect(self, inspector: _TreeInspector_488e0dd5) -> None:
        '''Examines the CloudFormation resource and discloses attributes.

        :param inspector: - tree inspector to collect and process attributes.
        '''
        return typing.cast(None, jsii.invoke(self, "inspect", [inspector]))

    @jsii.member(jsii_name="renderProperties")
    def _render_properties(
        self,
        props: typing.Mapping[builtins.str, typing.Any],
    ) -> typing.Mapping[builtins.str, typing.Any]:
        '''
        :param props: -
        '''
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.invoke(self, "renderProperties", [props]))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="CFN_RESOURCE_TYPE_NAME")
    def CFN_RESOURCE_TYPE_NAME(cls) -> builtins.str:
        '''The CloudFormation resource type name for this resource class.'''
        return typing.cast(builtins.str, jsii.sget(cls, "CFN_RESOURCE_TYPE_NAME"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrArn")
    def attr_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the bot.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrId")
    def attr_id(self) -> builtins.str:
        '''The unique identifier of the bot.

        :cloudformationAttribute: Id
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="dataPrivacy")
    def data_privacy(self) -> typing.Any:
        '''Provides information on additional privacy protections Amazon Lex should use with the bot's data.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-bot.html#cfn-lex-bot-dataprivacy
        '''
        return typing.cast(typing.Any, jsii.get(self, "dataPrivacy"))

    @data_privacy.setter
    def data_privacy(self, value: typing.Any) -> None:
        jsii.set(self, "dataPrivacy", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="idleSessionTtlInSeconds")
    def idle_session_ttl_in_seconds(self) -> jsii.Number:
        '''The time, in seconds, that Amazon Lex should keep information about a user's conversation with the bot.

        A user interaction remains active for the amount of time specified. If no conversation occurs during this time, the session expires and Amazon Lex deletes any data provided before the timeout.

        You can specify between 60 (1 minute) and 86,400 (24 hours) seconds.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-bot.html#cfn-lex-bot-idlesessionttlinseconds
        '''
        return typing.cast(jsii.Number, jsii.get(self, "idleSessionTtlInSeconds"))

    @idle_session_ttl_in_seconds.setter
    def idle_session_ttl_in_seconds(self, value: jsii.Number) -> None:
        jsii.set(self, "idleSessionTtlInSeconds", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The name of the field to filter the list of bots.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-bot.html#cfn-lex-bot-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="roleArn")
    def role_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the IAM role used to build and run the bot.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-bot.html#cfn-lex-bot-rolearn
        '''
        return typing.cast(builtins.str, jsii.get(self, "roleArn"))

    @role_arn.setter
    def role_arn(self, value: builtins.str) -> None:
        jsii.set(self, "roleArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="autoBuildBotLocales")
    def auto_build_bot_locales(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Indicates whether Amazon Lex V2 should automatically build the locales for the bot after a change.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-bot.html#cfn-lex-bot-autobuildbotlocales
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "autoBuildBotLocales"))

    @auto_build_bot_locales.setter
    def auto_build_bot_locales(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "autoBuildBotLocales", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="botFileS3Location")
    def bot_file_s3_location(
        self,
    ) -> typing.Optional[typing.Union["CfnBot.S3LocationProperty", _IResolvable_da3f097b]]:
        '''The Amazon S3 location of files used to import a bot.

        The files must be in the import format specified in `JSON format for importing and exporting <https://docs.aws.amazon.com/lexv2/latest/dg/import-export-format.html>`_ in the *Amazon Lex developer guide.*

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-bot.html#cfn-lex-bot-botfiles3location
        '''
        return typing.cast(typing.Optional[typing.Union["CfnBot.S3LocationProperty", _IResolvable_da3f097b]], jsii.get(self, "botFileS3Location"))

    @bot_file_s3_location.setter
    def bot_file_s3_location(
        self,
        value: typing.Optional[typing.Union["CfnBot.S3LocationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "botFileS3Location", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="botLocales")
    def bot_locales(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBot.BotLocaleProperty", _IResolvable_da3f097b]]]]:
        '''A list of locales for the bot.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-bot.html#cfn-lex-bot-botlocales
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBot.BotLocaleProperty", _IResolvable_da3f097b]]]], jsii.get(self, "botLocales"))

    @bot_locales.setter
    def bot_locales(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBot.BotLocaleProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "botLocales", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="botTags")
    def bot_tags(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]]:
        '''A list of tags to add to the bot.

        You can only add tags when you import a bot. You can't use the ``UpdateBot`` operation to update tags. To update tags, use the ``TagResource`` operation.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-bot.html#cfn-lex-bot-bottags
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]], jsii.get(self, "botTags"))

    @bot_tags.setter
    def bot_tags(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]],
    ) -> None:
        jsii.set(self, "botTags", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-bot.html#cfn-lex-bot-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="testBotAliasTags")
    def test_bot_alias_tags(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]]:
        '''A list of tags to add to the test alias for a bot.

        You can only add tags when you import a bot. You can't use the ``UpdateAlias`` operation to update tags. To update tags on the test alias, use the ``TagResource`` operation.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-bot.html#cfn-lex-bot-testbotaliastags
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]], jsii.get(self, "testBotAliasTags"))

    @test_bot_alias_tags.setter
    def test_bot_alias_tags(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]],
    ) -> None:
        jsii.set(self, "testBotAliasTags", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBot.BotLocaleProperty",
        jsii_struct_bases=[],
        name_mapping={
            "locale_id": "localeId",
            "nlu_confidence_threshold": "nluConfidenceThreshold",
            "description": "description",
            "intents": "intents",
            "slot_types": "slotTypes",
            "voice_settings": "voiceSettings",
        },
    )
    class BotLocaleProperty:
        def __init__(
            self,
            *,
            locale_id: builtins.str,
            nlu_confidence_threshold: jsii.Number,
            description: typing.Optional[builtins.str] = None,
            intents: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBot.IntentProperty", _IResolvable_da3f097b]]]] = None,
            slot_types: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBot.SlotTypeProperty", _IResolvable_da3f097b]]]] = None,
            voice_settings: typing.Optional[typing.Union["CfnBot.VoiceSettingsProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Provides configuration information for a locale.

            :param locale_id: The identifier of the language and locale that the bot will be used in. The string must match one of the supported locales.
            :param nlu_confidence_threshold: Determines the threshold where Amazon Lex will insert the AMAZON.FallbackIntent, AMAZON.KendraSearchIntent, or both when returning alternative intents. You must configure an AMAZON.FallbackIntent. AMAZON.KendraSearchIntent is only inserted if it is configured for the bot.
            :param description: A description of the bot locale. Use this to help identify the bot locale in lists.
            :param intents: One or more intents defined for the locale.
            :param slot_types: One or more slot types defined for the locale.
            :param voice_settings: Identifies the Amazon Polly voice used for audio interaction with the user.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-botlocale.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                bot_locale_property = lex.CfnBot.BotLocaleProperty(
                    locale_id="localeId",
                    nlu_confidence_threshold=123,
                
                    # the properties below are optional
                    description="description",
                    intents=[lex.CfnBot.IntentProperty(
                        name="name",
                
                        # the properties below are optional
                        description="description",
                        dialog_code_hook=lex.CfnBot.DialogCodeHookSettingProperty(
                            enabled=False
                        ),
                        fulfillment_code_hook=lex.CfnBot.FulfillmentCodeHookSettingProperty(
                            enabled=False,
                
                            # the properties below are optional
                            fulfillment_updates_specification=lex.CfnBot.FulfillmentUpdatesSpecificationProperty(
                                active=False,
                
                                # the properties below are optional
                                start_response=lex.CfnBot.FulfillmentStartResponseSpecificationProperty(
                                    delay_in_seconds=123,
                                    message_groups=[lex.CfnBot.MessageGroupProperty(
                                        message=lex.CfnBot.MessageProperty(
                                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                value="value"
                                            ),
                                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                title="title",
                
                                                # the properties below are optional
                                                buttons=[lex.CfnBot.ButtonProperty(
                                                    text="text",
                                                    value="value"
                                                )],
                                                image_url="imageUrl",
                                                subtitle="subtitle"
                                            ),
                                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                value="value"
                                            ),
                                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                value="value"
                                            )
                                        ),
                
                                        # the properties below are optional
                                        variations=[lex.CfnBot.MessageProperty(
                                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                value="value"
                                            ),
                                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                title="title",
                
                                                # the properties below are optional
                                                buttons=[lex.CfnBot.ButtonProperty(
                                                    text="text",
                                                    value="value"
                                                )],
                                                image_url="imageUrl",
                                                subtitle="subtitle"
                                            ),
                                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                value="value"
                                            ),
                                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                value="value"
                                            )
                                        )]
                                    )],
                
                                    # the properties below are optional
                                    allow_interrupt=False
                                ),
                                timeout_in_seconds=123,
                                update_response=lex.CfnBot.FulfillmentUpdateResponseSpecificationProperty(
                                    frequency_in_seconds=123,
                                    message_groups=[lex.CfnBot.MessageGroupProperty(
                                        message=lex.CfnBot.MessageProperty(
                                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                value="value"
                                            ),
                                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                title="title",
                
                                                # the properties below are optional
                                                buttons=[lex.CfnBot.ButtonProperty(
                                                    text="text",
                                                    value="value"
                                                )],
                                                image_url="imageUrl",
                                                subtitle="subtitle"
                                            ),
                                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                value="value"
                                            ),
                                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                value="value"
                                            )
                                        ),
                
                                        # the properties below are optional
                                        variations=[lex.CfnBot.MessageProperty(
                                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                value="value"
                                            ),
                                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                title="title",
                
                                                # the properties below are optional
                                                buttons=[lex.CfnBot.ButtonProperty(
                                                    text="text",
                                                    value="value"
                                                )],
                                                image_url="imageUrl",
                                                subtitle="subtitle"
                                            ),
                                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                value="value"
                                            ),
                                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                value="value"
                                            )
                                        )]
                                    )],
                
                                    # the properties below are optional
                                    allow_interrupt=False
                                )
                            ),
                            post_fulfillment_status_specification=lex.CfnBot.PostFulfillmentStatusSpecificationProperty(
                                failure_response=lex.CfnBot.ResponseSpecificationProperty(
                                    message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                        message=lex.CfnBot.MessageProperty(
                                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                value="value"
                                            ),
                                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                title="title",
                
                                                # the properties below are optional
                                                buttons=[lex.CfnBot.ButtonProperty(
                                                    text="text",
                                                    value="value"
                                                )],
                                                image_url="imageUrl",
                                                subtitle="subtitle"
                                            ),
                                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                value="value"
                                            ),
                                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                value="value"
                                            )
                                        ),
                
                                        # the properties below are optional
                                        variations=[lex.CfnBot.MessageProperty(
                                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                value="value"
                                            ),
                                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                title="title",
                
                                                # the properties below are optional
                                                buttons=[lex.CfnBot.ButtonProperty(
                                                    text="text",
                                                    value="value"
                                                )],
                                                image_url="imageUrl",
                                                subtitle="subtitle"
                                            ),
                                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                value="value"
                                            ),
                                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                value="value"
                                            )
                                        )]
                                    )],
                
                                    # the properties below are optional
                                    allow_interrupt=False
                                ),
                                success_response=lex.CfnBot.ResponseSpecificationProperty(
                                    message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                        message=lex.CfnBot.MessageProperty(
                                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                value="value"
                                            ),
                                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                title="title",
                
                                                # the properties below are optional
                                                buttons=[lex.CfnBot.ButtonProperty(
                                                    text="text",
                                                    value="value"
                                                )],
                                                image_url="imageUrl",
                                                subtitle="subtitle"
                                            ),
                                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                value="value"
                                            ),
                                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                value="value"
                                            )
                                        ),
                
                                        # the properties below are optional
                                        variations=[lex.CfnBot.MessageProperty(
                                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                value="value"
                                            ),
                                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                title="title",
                
                                                # the properties below are optional
                                                buttons=[lex.CfnBot.ButtonProperty(
                                                    text="text",
                                                    value="value"
                                                )],
                                                image_url="imageUrl",
                                                subtitle="subtitle"
                                            ),
                                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                value="value"
                                            ),
                                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                value="value"
                                            )
                                        )]
                                    )],
                
                                    # the properties below are optional
                                    allow_interrupt=False
                                ),
                                timeout_response=lex.CfnBot.ResponseSpecificationProperty(
                                    message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                        message=lex.CfnBot.MessageProperty(
                                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                value="value"
                                            ),
                                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                title="title",
                
                                                # the properties below are optional
                                                buttons=[lex.CfnBot.ButtonProperty(
                                                    text="text",
                                                    value="value"
                                                )],
                                                image_url="imageUrl",
                                                subtitle="subtitle"
                                            ),
                                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                value="value"
                                            ),
                                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                value="value"
                                            )
                                        ),
                
                                        # the properties below are optional
                                        variations=[lex.CfnBot.MessageProperty(
                                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                value="value"
                                            ),
                                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                title="title",
                
                                                # the properties below are optional
                                                buttons=[lex.CfnBot.ButtonProperty(
                                                    text="text",
                                                    value="value"
                                                )],
                                                image_url="imageUrl",
                                                subtitle="subtitle"
                                            ),
                                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                value="value"
                                            ),
                                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                value="value"
                                            )
                                        )]
                                    )],
                
                                    # the properties below are optional
                                    allow_interrupt=False
                                )
                            )
                        ),
                        input_contexts=[lex.CfnBot.InputContextProperty(
                            name="name"
                        )],
                        intent_closing_setting=lex.CfnBot.IntentClosingSettingProperty(
                            closing_response=lex.CfnBot.ResponseSpecificationProperty(
                                message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                    message=lex.CfnBot.MessageProperty(
                                        custom_payload=lex.CfnBot.CustomPayloadProperty(
                                            value="value"
                                        ),
                                        image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                            title="title",
                
                                            # the properties below are optional
                                            buttons=[lex.CfnBot.ButtonProperty(
                                                text="text",
                                                value="value"
                                            )],
                                            image_url="imageUrl",
                                            subtitle="subtitle"
                                        ),
                                        plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                            value="value"
                                        ),
                                        ssml_message=lex.CfnBot.SSMLMessageProperty(
                                            value="value"
                                        )
                                    ),
                
                                    # the properties below are optional
                                    variations=[lex.CfnBot.MessageProperty(
                                        custom_payload=lex.CfnBot.CustomPayloadProperty(
                                            value="value"
                                        ),
                                        image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                            title="title",
                
                                            # the properties below are optional
                                            buttons=[lex.CfnBot.ButtonProperty(
                                                text="text",
                                                value="value"
                                            )],
                                            image_url="imageUrl",
                                            subtitle="subtitle"
                                        ),
                                        plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                            value="value"
                                        ),
                                        ssml_message=lex.CfnBot.SSMLMessageProperty(
                                            value="value"
                                        )
                                    )]
                                )],
                
                                # the properties below are optional
                                allow_interrupt=False
                            ),
                
                            # the properties below are optional
                            is_active=False
                        ),
                        intent_confirmation_setting=lex.CfnBot.IntentConfirmationSettingProperty(
                            declination_response=lex.CfnBot.ResponseSpecificationProperty(
                                message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                    message=lex.CfnBot.MessageProperty(
                                        custom_payload=lex.CfnBot.CustomPayloadProperty(
                                            value="value"
                                        ),
                                        image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                            title="title",
                
                                            # the properties below are optional
                                            buttons=[lex.CfnBot.ButtonProperty(
                                                text="text",
                                                value="value"
                                            )],
                                            image_url="imageUrl",
                                            subtitle="subtitle"
                                        ),
                                        plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                            value="value"
                                        ),
                                        ssml_message=lex.CfnBot.SSMLMessageProperty(
                                            value="value"
                                        )
                                    ),
                
                                    # the properties below are optional
                                    variations=[lex.CfnBot.MessageProperty(
                                        custom_payload=lex.CfnBot.CustomPayloadProperty(
                                            value="value"
                                        ),
                                        image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                            title="title",
                
                                            # the properties below are optional
                                            buttons=[lex.CfnBot.ButtonProperty(
                                                text="text",
                                                value="value"
                                            )],
                                            image_url="imageUrl",
                                            subtitle="subtitle"
                                        ),
                                        plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                            value="value"
                                        ),
                                        ssml_message=lex.CfnBot.SSMLMessageProperty(
                                            value="value"
                                        )
                                    )]
                                )],
                
                                # the properties below are optional
                                allow_interrupt=False
                            ),
                            prompt_specification=lex.CfnBot.PromptSpecificationProperty(
                                max_retries=123,
                                message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                    message=lex.CfnBot.MessageProperty(
                                        custom_payload=lex.CfnBot.CustomPayloadProperty(
                                            value="value"
                                        ),
                                        image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                            title="title",
                
                                            # the properties below are optional
                                            buttons=[lex.CfnBot.ButtonProperty(
                                                text="text",
                                                value="value"
                                            )],
                                            image_url="imageUrl",
                                            subtitle="subtitle"
                                        ),
                                        plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                            value="value"
                                        ),
                                        ssml_message=lex.CfnBot.SSMLMessageProperty(
                                            value="value"
                                        )
                                    ),
                
                                    # the properties below are optional
                                    variations=[lex.CfnBot.MessageProperty(
                                        custom_payload=lex.CfnBot.CustomPayloadProperty(
                                            value="value"
                                        ),
                                        image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                            title="title",
                
                                            # the properties below are optional
                                            buttons=[lex.CfnBot.ButtonProperty(
                                                text="text",
                                                value="value"
                                            )],
                                            image_url="imageUrl",
                                            subtitle="subtitle"
                                        ),
                                        plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                            value="value"
                                        ),
                                        ssml_message=lex.CfnBot.SSMLMessageProperty(
                                            value="value"
                                        )
                                    )]
                                )],
                
                                # the properties below are optional
                                allow_interrupt=False
                            ),
                
                            # the properties below are optional
                            is_active=False
                        ),
                        kendra_configuration=lex.CfnBot.KendraConfigurationProperty(
                            kendra_index="kendraIndex",
                
                            # the properties below are optional
                            query_filter_string="queryFilterString",
                            query_filter_string_enabled=False
                        ),
                        output_contexts=[lex.CfnBot.OutputContextProperty(
                            name="name",
                            time_to_live_in_seconds=123,
                            turns_to_live=123
                        )],
                        parent_intent_signature="parentIntentSignature",
                        sample_utterances=[lex.CfnBot.SampleUtteranceProperty(
                            utterance="utterance"
                        )],
                        slot_priorities=[lex.CfnBot.SlotPriorityProperty(
                            priority=123,
                            slot_name="slotName"
                        )],
                        slots=[lex.CfnBot.SlotProperty(
                            name="name",
                            slot_type_name="slotTypeName",
                            value_elicitation_setting=lex.CfnBot.SlotValueElicitationSettingProperty(
                                slot_constraint="slotConstraint",
                
                                # the properties below are optional
                                default_value_specification=lex.CfnBot.SlotDefaultValueSpecificationProperty(
                                    default_value_list=[lex.CfnBot.SlotDefaultValueProperty(
                                        default_value="defaultValue"
                                    )]
                                ),
                                prompt_specification=lex.CfnBot.PromptSpecificationProperty(
                                    max_retries=123,
                                    message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                        message=lex.CfnBot.MessageProperty(
                                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                value="value"
                                            ),
                                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                title="title",
                
                                                # the properties below are optional
                                                buttons=[lex.CfnBot.ButtonProperty(
                                                    text="text",
                                                    value="value"
                                                )],
                                                image_url="imageUrl",
                                                subtitle="subtitle"
                                            ),
                                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                value="value"
                                            ),
                                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                value="value"
                                            )
                                        ),
                
                                        # the properties below are optional
                                        variations=[lex.CfnBot.MessageProperty(
                                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                value="value"
                                            ),
                                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                title="title",
                
                                                # the properties below are optional
                                                buttons=[lex.CfnBot.ButtonProperty(
                                                    text="text",
                                                    value="value"
                                                )],
                                                image_url="imageUrl",
                                                subtitle="subtitle"
                                            ),
                                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                value="value"
                                            ),
                                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                value="value"
                                            )
                                        )]
                                    )],
                
                                    # the properties below are optional
                                    allow_interrupt=False
                                ),
                                sample_utterances=[lex.CfnBot.SampleUtteranceProperty(
                                    utterance="utterance"
                                )],
                                wait_and_continue_specification=lex.CfnBot.WaitAndContinueSpecificationProperty(
                                    continue_response=lex.CfnBot.ResponseSpecificationProperty(
                                        message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                            message=lex.CfnBot.MessageProperty(
                                                custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                    value="value"
                                                ),
                                                image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                    title="title",
                
                                                    # the properties below are optional
                                                    buttons=[lex.CfnBot.ButtonProperty(
                                                        text="text",
                                                        value="value"
                                                    )],
                                                    image_url="imageUrl",
                                                    subtitle="subtitle"
                                                ),
                                                plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                    value="value"
                                                ),
                                                ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                    value="value"
                                                )
                                            ),
                
                                            # the properties below are optional
                                            variations=[lex.CfnBot.MessageProperty(
                                                custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                    value="value"
                                                ),
                                                image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                    title="title",
                
                                                    # the properties below are optional
                                                    buttons=[lex.CfnBot.ButtonProperty(
                                                        text="text",
                                                        value="value"
                                                    )],
                                                    image_url="imageUrl",
                                                    subtitle="subtitle"
                                                ),
                                                plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                    value="value"
                                                ),
                                                ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                    value="value"
                                                )
                                            )]
                                        )],
                
                                        # the properties below are optional
                                        allow_interrupt=False
                                    ),
                                    waiting_response=lex.CfnBot.ResponseSpecificationProperty(
                                        message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                            message=lex.CfnBot.MessageProperty(
                                                custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                    value="value"
                                                ),
                                                image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                    title="title",
                
                                                    # the properties below are optional
                                                    buttons=[lex.CfnBot.ButtonProperty(
                                                        text="text",
                                                        value="value"
                                                    )],
                                                    image_url="imageUrl",
                                                    subtitle="subtitle"
                                                ),
                                                plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                    value="value"
                                                ),
                                                ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                    value="value"
                                                )
                                            ),
                
                                            # the properties below are optional
                                            variations=[lex.CfnBot.MessageProperty(
                                                custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                    value="value"
                                                ),
                                                image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                    title="title",
                
                                                    # the properties below are optional
                                                    buttons=[lex.CfnBot.ButtonProperty(
                                                        text="text",
                                                        value="value"
                                                    )],
                                                    image_url="imageUrl",
                                                    subtitle="subtitle"
                                                ),
                                                plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                    value="value"
                                                ),
                                                ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                    value="value"
                                                )
                                            )]
                                        )],
                
                                        # the properties below are optional
                                        allow_interrupt=False
                                    ),
                
                                    # the properties below are optional
                                    is_active=False,
                                    still_waiting_response=lex.CfnBot.StillWaitingResponseSpecificationProperty(
                                        frequency_in_seconds=123,
                                        message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                            message=lex.CfnBot.MessageProperty(
                                                custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                    value="value"
                                                ),
                                                image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                    title="title",
                
                                                    # the properties below are optional
                                                    buttons=[lex.CfnBot.ButtonProperty(
                                                        text="text",
                                                        value="value"
                                                    )],
                                                    image_url="imageUrl",
                                                    subtitle="subtitle"
                                                ),
                                                plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                    value="value"
                                                ),
                                                ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                    value="value"
                                                )
                                            ),
                
                                            # the properties below are optional
                                            variations=[lex.CfnBot.MessageProperty(
                                                custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                    value="value"
                                                ),
                                                image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                    title="title",
                
                                                    # the properties below are optional
                                                    buttons=[lex.CfnBot.ButtonProperty(
                                                        text="text",
                                                        value="value"
                                                    )],
                                                    image_url="imageUrl",
                                                    subtitle="subtitle"
                                                ),
                                                plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                    value="value"
                                                ),
                                                ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                    value="value"
                                                )
                                            )]
                                        )],
                                        timeout_in_seconds=123,
                
                                        # the properties below are optional
                                        allow_interrupt=False
                                    )
                                )
                            ),
                
                            # the properties below are optional
                            description="description",
                            multiple_values_setting=lex.CfnBot.MultipleValuesSettingProperty(
                                allow_multiple_values=False
                            ),
                            obfuscation_setting=lex.CfnBot.ObfuscationSettingProperty(
                                obfuscation_setting_type="obfuscationSettingType"
                            )
                        )]
                    )],
                    slot_types=[lex.CfnBot.SlotTypeProperty(
                        name="name",
                
                        # the properties below are optional
                        description="description",
                        external_source_setting=lex.CfnBot.ExternalSourceSettingProperty(
                            grammar_slot_type_setting=lex.CfnBot.GrammarSlotTypeSettingProperty(
                                source=lex.CfnBot.GrammarSlotTypeSourceProperty(
                                    s3_bucket_name="s3BucketName",
                                    s3_object_key="s3ObjectKey",
                
                                    # the properties below are optional
                                    kms_key_arn="kmsKeyArn"
                                )
                            )
                        ),
                        parent_slot_type_signature="parentSlotTypeSignature",
                        slot_type_values=[lex.CfnBot.SlotTypeValueProperty(
                            sample_value=lex.CfnBot.SampleValueProperty(
                                value="value"
                            ),
                
                            # the properties below are optional
                            synonyms=[lex.CfnBot.SampleValueProperty(
                                value="value"
                            )]
                        )],
                        value_selection_setting=lex.CfnBot.SlotValueSelectionSettingProperty(
                            resolution_strategy="resolutionStrategy",
                
                            # the properties below are optional
                            regex_filter=lex.CfnBot.SlotValueRegexFilterProperty(
                                pattern="pattern"
                            )
                        )
                    )],
                    voice_settings=lex.CfnBot.VoiceSettingsProperty(
                        voice_id="voiceId"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "locale_id": locale_id,
                "nlu_confidence_threshold": nlu_confidence_threshold,
            }
            if description is not None:
                self._values["description"] = description
            if intents is not None:
                self._values["intents"] = intents
            if slot_types is not None:
                self._values["slot_types"] = slot_types
            if voice_settings is not None:
                self._values["voice_settings"] = voice_settings

        @builtins.property
        def locale_id(self) -> builtins.str:
            '''The identifier of the language and locale that the bot will be used in.

            The string must match one of the supported locales.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-botlocale.html#cfn-lex-bot-botlocale-localeid
            '''
            result = self._values.get("locale_id")
            assert result is not None, "Required property 'locale_id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def nlu_confidence_threshold(self) -> jsii.Number:
            '''Determines the threshold where Amazon Lex will insert the AMAZON.FallbackIntent, AMAZON.KendraSearchIntent, or both when returning alternative intents. You must configure an AMAZON.FallbackIntent. AMAZON.KendraSearchIntent is only inserted if it is configured for the bot.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-botlocale.html#cfn-lex-bot-botlocale-nluconfidencethreshold
            '''
            result = self._values.get("nlu_confidence_threshold")
            assert result is not None, "Required property 'nlu_confidence_threshold' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def description(self) -> typing.Optional[builtins.str]:
            '''A description of the bot locale.

            Use this to help identify the bot locale in lists.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-botlocale.html#cfn-lex-bot-botlocale-description
            '''
            result = self._values.get("description")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def intents(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBot.IntentProperty", _IResolvable_da3f097b]]]]:
            '''One or more intents defined for the locale.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-botlocale.html#cfn-lex-bot-botlocale-intents
            '''
            result = self._values.get("intents")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBot.IntentProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def slot_types(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBot.SlotTypeProperty", _IResolvable_da3f097b]]]]:
            '''One or more slot types defined for the locale.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-botlocale.html#cfn-lex-bot-botlocale-slottypes
            '''
            result = self._values.get("slot_types")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBot.SlotTypeProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def voice_settings(
            self,
        ) -> typing.Optional[typing.Union["CfnBot.VoiceSettingsProperty", _IResolvable_da3f097b]]:
            '''Identifies the Amazon Polly voice used for audio interaction with the user.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-botlocale.html#cfn-lex-bot-botlocale-voicesettings
            '''
            result = self._values.get("voice_settings")
            return typing.cast(typing.Optional[typing.Union["CfnBot.VoiceSettingsProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "BotLocaleProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBot.ButtonProperty",
        jsii_struct_bases=[],
        name_mapping={"text": "text", "value": "value"},
    )
    class ButtonProperty:
        def __init__(self, *, text: builtins.str, value: builtins.str) -> None:
            '''Describes a button to use on a response card used to gather slot values from a user.

            :param text: The text that appears on the button. Use this to tell the user the value that is returned when they choose this button.
            :param value: The value returned to Amazon Lex when the user chooses this button. This must be one of the slot values configured for the slot.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-button.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                button_property = lex.CfnBot.ButtonProperty(
                    text="text",
                    value="value"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "text": text,
                "value": value,
            }

        @builtins.property
        def text(self) -> builtins.str:
            '''The text that appears on the button.

            Use this to tell the user the value that is returned when they choose this button.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-button.html#cfn-lex-bot-button-text
            '''
            result = self._values.get("text")
            assert result is not None, "Required property 'text' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def value(self) -> builtins.str:
            '''The value returned to Amazon Lex when the user chooses this button.

            This must be one of the slot values configured for the slot.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-button.html#cfn-lex-bot-button-value
            '''
            result = self._values.get("value")
            assert result is not None, "Required property 'value' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ButtonProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBot.CustomPayloadProperty",
        jsii_struct_bases=[],
        name_mapping={"value": "value"},
    )
    class CustomPayloadProperty:
        def __init__(self, *, value: builtins.str) -> None:
            '''A custom response string that Amazon Lex sends to your application.

            You define the content and structure of the string.

            :param value: The string that is sent to your application.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-custompayload.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                custom_payload_property = lex.CfnBot.CustomPayloadProperty(
                    value="value"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "value": value,
            }

        @builtins.property
        def value(self) -> builtins.str:
            '''The string that is sent to your application.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-custompayload.html#cfn-lex-bot-custompayload-value
            '''
            result = self._values.get("value")
            assert result is not None, "Required property 'value' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CustomPayloadProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBot.DialogCodeHookSettingProperty",
        jsii_struct_bases=[],
        name_mapping={"enabled": "enabled"},
    )
    class DialogCodeHookSettingProperty:
        def __init__(
            self,
            *,
            enabled: typing.Union[builtins.bool, _IResolvable_da3f097b],
        ) -> None:
            '''Specifies whether an intent uses the dialog code hook during conversations with a user.

            :param enabled: Indicates whether an intent uses the dialog code hook during a conversation with a user.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-dialogcodehooksetting.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                dialog_code_hook_setting_property = lex.CfnBot.DialogCodeHookSettingProperty(
                    enabled=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "enabled": enabled,
            }

        @builtins.property
        def enabled(self) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
            '''Indicates whether an intent uses the dialog code hook during a conversation with a user.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-dialogcodehooksetting.html#cfn-lex-bot-dialogcodehooksetting-enabled
            '''
            result = self._values.get("enabled")
            assert result is not None, "Required property 'enabled' is missing"
            return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DialogCodeHookSettingProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBot.ExternalSourceSettingProperty",
        jsii_struct_bases=[],
        name_mapping={"grammar_slot_type_setting": "grammarSlotTypeSetting"},
    )
    class ExternalSourceSettingProperty:
        def __init__(
            self,
            *,
            grammar_slot_type_setting: typing.Optional[typing.Union["CfnBot.GrammarSlotTypeSettingProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Provides information about the external source of the slot type's definition.

            :param grammar_slot_type_setting: Settings required for a slot type based on a grammar that you provide.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-externalsourcesetting.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                external_source_setting_property = lex.CfnBot.ExternalSourceSettingProperty(
                    grammar_slot_type_setting=lex.CfnBot.GrammarSlotTypeSettingProperty(
                        source=lex.CfnBot.GrammarSlotTypeSourceProperty(
                            s3_bucket_name="s3BucketName",
                            s3_object_key="s3ObjectKey",
                
                            # the properties below are optional
                            kms_key_arn="kmsKeyArn"
                        )
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if grammar_slot_type_setting is not None:
                self._values["grammar_slot_type_setting"] = grammar_slot_type_setting

        @builtins.property
        def grammar_slot_type_setting(
            self,
        ) -> typing.Optional[typing.Union["CfnBot.GrammarSlotTypeSettingProperty", _IResolvable_da3f097b]]:
            '''Settings required for a slot type based on a grammar that you provide.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-externalsourcesetting.html#cfn-lex-bot-externalsourcesetting-grammarslottypesetting
            '''
            result = self._values.get("grammar_slot_type_setting")
            return typing.cast(typing.Optional[typing.Union["CfnBot.GrammarSlotTypeSettingProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ExternalSourceSettingProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBot.FulfillmentCodeHookSettingProperty",
        jsii_struct_bases=[],
        name_mapping={
            "enabled": "enabled",
            "fulfillment_updates_specification": "fulfillmentUpdatesSpecification",
            "post_fulfillment_status_specification": "postFulfillmentStatusSpecification",
        },
    )
    class FulfillmentCodeHookSettingProperty:
        def __init__(
            self,
            *,
            enabled: typing.Union[builtins.bool, _IResolvable_da3f097b],
            fulfillment_updates_specification: typing.Optional[typing.Union["CfnBot.FulfillmentUpdatesSpecificationProperty", _IResolvable_da3f097b]] = None,
            post_fulfillment_status_specification: typing.Optional[typing.Union["CfnBot.PostFulfillmentStatusSpecificationProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Determines if a Lambda function should be invoked for a specific intent.

            :param enabled: Indicates whether a Lambda function should be invoked for fulfill a specific intent.
            :param fulfillment_updates_specification: Provides settings for update messages sent to the user for long-running Lambda fulfillment functions. Fulfillment updates can be used only with streaming conversations.
            :param post_fulfillment_status_specification: Provides settings for messages sent to the user for after the Lambda fulfillment function completes. Post-fulfillment messages can be sent for both streaming and non-streaming conversations.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-fulfillmentcodehooksetting.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                fulfillment_code_hook_setting_property = lex.CfnBot.FulfillmentCodeHookSettingProperty(
                    enabled=False,
                
                    # the properties below are optional
                    fulfillment_updates_specification=lex.CfnBot.FulfillmentUpdatesSpecificationProperty(
                        active=False,
                
                        # the properties below are optional
                        start_response=lex.CfnBot.FulfillmentStartResponseSpecificationProperty(
                            delay_in_seconds=123,
                            message_groups=[lex.CfnBot.MessageGroupProperty(
                                message=lex.CfnBot.MessageProperty(
                                    custom_payload=lex.CfnBot.CustomPayloadProperty(
                                        value="value"
                                    ),
                                    image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                        title="title",
                
                                        # the properties below are optional
                                        buttons=[lex.CfnBot.ButtonProperty(
                                            text="text",
                                            value="value"
                                        )],
                                        image_url="imageUrl",
                                        subtitle="subtitle"
                                    ),
                                    plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                        value="value"
                                    ),
                                    ssml_message=lex.CfnBot.SSMLMessageProperty(
                                        value="value"
                                    )
                                ),
                
                                # the properties below are optional
                                variations=[lex.CfnBot.MessageProperty(
                                    custom_payload=lex.CfnBot.CustomPayloadProperty(
                                        value="value"
                                    ),
                                    image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                        title="title",
                
                                        # the properties below are optional
                                        buttons=[lex.CfnBot.ButtonProperty(
                                            text="text",
                                            value="value"
                                        )],
                                        image_url="imageUrl",
                                        subtitle="subtitle"
                                    ),
                                    plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                        value="value"
                                    ),
                                    ssml_message=lex.CfnBot.SSMLMessageProperty(
                                        value="value"
                                    )
                                )]
                            )],
                
                            # the properties below are optional
                            allow_interrupt=False
                        ),
                        timeout_in_seconds=123,
                        update_response=lex.CfnBot.FulfillmentUpdateResponseSpecificationProperty(
                            frequency_in_seconds=123,
                            message_groups=[lex.CfnBot.MessageGroupProperty(
                                message=lex.CfnBot.MessageProperty(
                                    custom_payload=lex.CfnBot.CustomPayloadProperty(
                                        value="value"
                                    ),
                                    image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                        title="title",
                
                                        # the properties below are optional
                                        buttons=[lex.CfnBot.ButtonProperty(
                                            text="text",
                                            value="value"
                                        )],
                                        image_url="imageUrl",
                                        subtitle="subtitle"
                                    ),
                                    plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                        value="value"
                                    ),
                                    ssml_message=lex.CfnBot.SSMLMessageProperty(
                                        value="value"
                                    )
                                ),
                
                                # the properties below are optional
                                variations=[lex.CfnBot.MessageProperty(
                                    custom_payload=lex.CfnBot.CustomPayloadProperty(
                                        value="value"
                                    ),
                                    image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                        title="title",
                
                                        # the properties below are optional
                                        buttons=[lex.CfnBot.ButtonProperty(
                                            text="text",
                                            value="value"
                                        )],
                                        image_url="imageUrl",
                                        subtitle="subtitle"
                                    ),
                                    plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                        value="value"
                                    ),
                                    ssml_message=lex.CfnBot.SSMLMessageProperty(
                                        value="value"
                                    )
                                )]
                            )],
                
                            # the properties below are optional
                            allow_interrupt=False
                        )
                    ),
                    post_fulfillment_status_specification=lex.CfnBot.PostFulfillmentStatusSpecificationProperty(
                        failure_response=lex.CfnBot.ResponseSpecificationProperty(
                            message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                message=lex.CfnBot.MessageProperty(
                                    custom_payload=lex.CfnBot.CustomPayloadProperty(
                                        value="value"
                                    ),
                                    image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                        title="title",
                
                                        # the properties below are optional
                                        buttons=[lex.CfnBot.ButtonProperty(
                                            text="text",
                                            value="value"
                                        )],
                                        image_url="imageUrl",
                                        subtitle="subtitle"
                                    ),
                                    plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                        value="value"
                                    ),
                                    ssml_message=lex.CfnBot.SSMLMessageProperty(
                                        value="value"
                                    )
                                ),
                
                                # the properties below are optional
                                variations=[lex.CfnBot.MessageProperty(
                                    custom_payload=lex.CfnBot.CustomPayloadProperty(
                                        value="value"
                                    ),
                                    image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                        title="title",
                
                                        # the properties below are optional
                                        buttons=[lex.CfnBot.ButtonProperty(
                                            text="text",
                                            value="value"
                                        )],
                                        image_url="imageUrl",
                                        subtitle="subtitle"
                                    ),
                                    plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                        value="value"
                                    ),
                                    ssml_message=lex.CfnBot.SSMLMessageProperty(
                                        value="value"
                                    )
                                )]
                            )],
                
                            # the properties below are optional
                            allow_interrupt=False
                        ),
                        success_response=lex.CfnBot.ResponseSpecificationProperty(
                            message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                message=lex.CfnBot.MessageProperty(
                                    custom_payload=lex.CfnBot.CustomPayloadProperty(
                                        value="value"
                                    ),
                                    image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                        title="title",
                
                                        # the properties below are optional
                                        buttons=[lex.CfnBot.ButtonProperty(
                                            text="text",
                                            value="value"
                                        )],
                                        image_url="imageUrl",
                                        subtitle="subtitle"
                                    ),
                                    plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                        value="value"
                                    ),
                                    ssml_message=lex.CfnBot.SSMLMessageProperty(
                                        value="value"
                                    )
                                ),
                
                                # the properties below are optional
                                variations=[lex.CfnBot.MessageProperty(
                                    custom_payload=lex.CfnBot.CustomPayloadProperty(
                                        value="value"
                                    ),
                                    image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                        title="title",
                
                                        # the properties below are optional
                                        buttons=[lex.CfnBot.ButtonProperty(
                                            text="text",
                                            value="value"
                                        )],
                                        image_url="imageUrl",
                                        subtitle="subtitle"
                                    ),
                                    plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                        value="value"
                                    ),
                                    ssml_message=lex.CfnBot.SSMLMessageProperty(
                                        value="value"
                                    )
                                )]
                            )],
                
                            # the properties below are optional
                            allow_interrupt=False
                        ),
                        timeout_response=lex.CfnBot.ResponseSpecificationProperty(
                            message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                message=lex.CfnBot.MessageProperty(
                                    custom_payload=lex.CfnBot.CustomPayloadProperty(
                                        value="value"
                                    ),
                                    image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                        title="title",
                
                                        # the properties below are optional
                                        buttons=[lex.CfnBot.ButtonProperty(
                                            text="text",
                                            value="value"
                                        )],
                                        image_url="imageUrl",
                                        subtitle="subtitle"
                                    ),
                                    plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                        value="value"
                                    ),
                                    ssml_message=lex.CfnBot.SSMLMessageProperty(
                                        value="value"
                                    )
                                ),
                
                                # the properties below are optional
                                variations=[lex.CfnBot.MessageProperty(
                                    custom_payload=lex.CfnBot.CustomPayloadProperty(
                                        value="value"
                                    ),
                                    image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                        title="title",
                
                                        # the properties below are optional
                                        buttons=[lex.CfnBot.ButtonProperty(
                                            text="text",
                                            value="value"
                                        )],
                                        image_url="imageUrl",
                                        subtitle="subtitle"
                                    ),
                                    plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                        value="value"
                                    ),
                                    ssml_message=lex.CfnBot.SSMLMessageProperty(
                                        value="value"
                                    )
                                )]
                            )],
                
                            # the properties below are optional
                            allow_interrupt=False
                        )
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "enabled": enabled,
            }
            if fulfillment_updates_specification is not None:
                self._values["fulfillment_updates_specification"] = fulfillment_updates_specification
            if post_fulfillment_status_specification is not None:
                self._values["post_fulfillment_status_specification"] = post_fulfillment_status_specification

        @builtins.property
        def enabled(self) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
            '''Indicates whether a Lambda function should be invoked for fulfill a specific intent.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-fulfillmentcodehooksetting.html#cfn-lex-bot-fulfillmentcodehooksetting-enabled
            '''
            result = self._values.get("enabled")
            assert result is not None, "Required property 'enabled' is missing"
            return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], result)

        @builtins.property
        def fulfillment_updates_specification(
            self,
        ) -> typing.Optional[typing.Union["CfnBot.FulfillmentUpdatesSpecificationProperty", _IResolvable_da3f097b]]:
            '''Provides settings for update messages sent to the user for long-running Lambda fulfillment functions.

            Fulfillment updates can be used only with streaming conversations.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-fulfillmentcodehooksetting.html#cfn-lex-bot-fulfillmentcodehooksetting-fulfillmentupdatesspecification
            '''
            result = self._values.get("fulfillment_updates_specification")
            return typing.cast(typing.Optional[typing.Union["CfnBot.FulfillmentUpdatesSpecificationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def post_fulfillment_status_specification(
            self,
        ) -> typing.Optional[typing.Union["CfnBot.PostFulfillmentStatusSpecificationProperty", _IResolvable_da3f097b]]:
            '''Provides settings for messages sent to the user for after the Lambda fulfillment function completes.

            Post-fulfillment messages can be sent for both streaming and non-streaming conversations.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-fulfillmentcodehooksetting.html#cfn-lex-bot-fulfillmentcodehooksetting-postfulfillmentstatusspecification
            '''
            result = self._values.get("post_fulfillment_status_specification")
            return typing.cast(typing.Optional[typing.Union["CfnBot.PostFulfillmentStatusSpecificationProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "FulfillmentCodeHookSettingProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBot.FulfillmentStartResponseSpecificationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "delay_in_seconds": "delayInSeconds",
            "message_groups": "messageGroups",
            "allow_interrupt": "allowInterrupt",
        },
    )
    class FulfillmentStartResponseSpecificationProperty:
        def __init__(
            self,
            *,
            delay_in_seconds: jsii.Number,
            message_groups: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBot.MessageGroupProperty", _IResolvable_da3f097b]]],
            allow_interrupt: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Provides settings for a message that is sent to the user when a fulfillment Lambda function starts running.

            :param delay_in_seconds: The delay between when the Lambda fulfillment function starts running and the start message is played. If the Lambda function returns before the delay is over, the start message isn't played.
            :param message_groups: One to 5 message groups that contain start messages. Amazon Lex chooses one of the messages to play to the user.
            :param allow_interrupt: Determines whether the user can interrupt the start message while it is playing.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-fulfillmentstartresponsespecification.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                fulfillment_start_response_specification_property = lex.CfnBot.FulfillmentStartResponseSpecificationProperty(
                    delay_in_seconds=123,
                    message_groups=[lex.CfnBot.MessageGroupProperty(
                        message=lex.CfnBot.MessageProperty(
                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                value="value"
                            ),
                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                title="title",
                
                                # the properties below are optional
                                buttons=[lex.CfnBot.ButtonProperty(
                                    text="text",
                                    value="value"
                                )],
                                image_url="imageUrl",
                                subtitle="subtitle"
                            ),
                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                value="value"
                            ),
                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                value="value"
                            )
                        ),
                
                        # the properties below are optional
                        variations=[lex.CfnBot.MessageProperty(
                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                value="value"
                            ),
                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                title="title",
                
                                # the properties below are optional
                                buttons=[lex.CfnBot.ButtonProperty(
                                    text="text",
                                    value="value"
                                )],
                                image_url="imageUrl",
                                subtitle="subtitle"
                            ),
                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                value="value"
                            ),
                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                value="value"
                            )
                        )]
                    )],
                
                    # the properties below are optional
                    allow_interrupt=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "delay_in_seconds": delay_in_seconds,
                "message_groups": message_groups,
            }
            if allow_interrupt is not None:
                self._values["allow_interrupt"] = allow_interrupt

        @builtins.property
        def delay_in_seconds(self) -> jsii.Number:
            '''The delay between when the Lambda fulfillment function starts running and the start message is played.

            If the Lambda function returns before the delay is over, the start message isn't played.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-fulfillmentstartresponsespecification.html#cfn-lex-bot-fulfillmentstartresponsespecification-delayinseconds
            '''
            result = self._values.get("delay_in_seconds")
            assert result is not None, "Required property 'delay_in_seconds' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def message_groups(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBot.MessageGroupProperty", _IResolvable_da3f097b]]]:
            '''One to 5 message groups that contain start messages.

            Amazon Lex chooses one of the messages to play to the user.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-fulfillmentstartresponsespecification.html#cfn-lex-bot-fulfillmentstartresponsespecification-messagegroups
            '''
            result = self._values.get("message_groups")
            assert result is not None, "Required property 'message_groups' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBot.MessageGroupProperty", _IResolvable_da3f097b]]], result)

        @builtins.property
        def allow_interrupt(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Determines whether the user can interrupt the start message while it is playing.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-fulfillmentstartresponsespecification.html#cfn-lex-bot-fulfillmentstartresponsespecification-allowinterrupt
            '''
            result = self._values.get("allow_interrupt")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "FulfillmentStartResponseSpecificationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBot.FulfillmentUpdateResponseSpecificationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "frequency_in_seconds": "frequencyInSeconds",
            "message_groups": "messageGroups",
            "allow_interrupt": "allowInterrupt",
        },
    )
    class FulfillmentUpdateResponseSpecificationProperty:
        def __init__(
            self,
            *,
            frequency_in_seconds: jsii.Number,
            message_groups: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBot.MessageGroupProperty", _IResolvable_da3f097b]]],
            allow_interrupt: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Provides information for updating the user on the progress of fulfilling an intent.

            :param frequency_in_seconds: The frequency that a message is sent to the user. When the period ends, Amazon Lex chooses a message from the message groups and plays it to the user. If the fulfillment Lambda function returns before the first period ends, an update message is not played to the user.
            :param message_groups: One to 5 message groups that contain update messages. Amazon Lex chooses one of the messages to play to the user.
            :param allow_interrupt: Determines whether the user can interrupt an update message while it is playing.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-fulfillmentupdateresponsespecification.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                fulfillment_update_response_specification_property = lex.CfnBot.FulfillmentUpdateResponseSpecificationProperty(
                    frequency_in_seconds=123,
                    message_groups=[lex.CfnBot.MessageGroupProperty(
                        message=lex.CfnBot.MessageProperty(
                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                value="value"
                            ),
                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                title="title",
                
                                # the properties below are optional
                                buttons=[lex.CfnBot.ButtonProperty(
                                    text="text",
                                    value="value"
                                )],
                                image_url="imageUrl",
                                subtitle="subtitle"
                            ),
                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                value="value"
                            ),
                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                value="value"
                            )
                        ),
                
                        # the properties below are optional
                        variations=[lex.CfnBot.MessageProperty(
                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                value="value"
                            ),
                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                title="title",
                
                                # the properties below are optional
                                buttons=[lex.CfnBot.ButtonProperty(
                                    text="text",
                                    value="value"
                                )],
                                image_url="imageUrl",
                                subtitle="subtitle"
                            ),
                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                value="value"
                            ),
                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                value="value"
                            )
                        )]
                    )],
                
                    # the properties below are optional
                    allow_interrupt=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "frequency_in_seconds": frequency_in_seconds,
                "message_groups": message_groups,
            }
            if allow_interrupt is not None:
                self._values["allow_interrupt"] = allow_interrupt

        @builtins.property
        def frequency_in_seconds(self) -> jsii.Number:
            '''The frequency that a message is sent to the user.

            When the period ends, Amazon Lex chooses a message from the message groups and plays it to the user. If the fulfillment Lambda function returns before the first period ends, an update message is not played to the user.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-fulfillmentupdateresponsespecification.html#cfn-lex-bot-fulfillmentupdateresponsespecification-frequencyinseconds
            '''
            result = self._values.get("frequency_in_seconds")
            assert result is not None, "Required property 'frequency_in_seconds' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def message_groups(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBot.MessageGroupProperty", _IResolvable_da3f097b]]]:
            '''One to 5 message groups that contain update messages.

            Amazon Lex chooses one of the messages to play to the user.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-fulfillmentupdateresponsespecification.html#cfn-lex-bot-fulfillmentupdateresponsespecification-messagegroups
            '''
            result = self._values.get("message_groups")
            assert result is not None, "Required property 'message_groups' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBot.MessageGroupProperty", _IResolvable_da3f097b]]], result)

        @builtins.property
        def allow_interrupt(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Determines whether the user can interrupt an update message while it is playing.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-fulfillmentupdateresponsespecification.html#cfn-lex-bot-fulfillmentupdateresponsespecification-allowinterrupt
            '''
            result = self._values.get("allow_interrupt")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "FulfillmentUpdateResponseSpecificationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBot.FulfillmentUpdatesSpecificationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "active": "active",
            "start_response": "startResponse",
            "timeout_in_seconds": "timeoutInSeconds",
            "update_response": "updateResponse",
        },
    )
    class FulfillmentUpdatesSpecificationProperty:
        def __init__(
            self,
            *,
            active: typing.Union[builtins.bool, _IResolvable_da3f097b],
            start_response: typing.Optional[typing.Union["CfnBot.FulfillmentStartResponseSpecificationProperty", _IResolvable_da3f097b]] = None,
            timeout_in_seconds: typing.Optional[jsii.Number] = None,
            update_response: typing.Optional[typing.Union["CfnBot.FulfillmentUpdateResponseSpecificationProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Provides information for updating the user on the progress of fulfilling an intent.

            :param active: Determines whether fulfillment updates are sent to the user. When this field is true, updates are sent. If the active field is set to true, the ``startResponse`` , ``updateResponse`` , and ``timeoutInSeconds`` fields are required.
            :param start_response: Provides configuration information for the message sent to users when the fulfillment Lambda functions starts running.
            :param timeout_in_seconds: The length of time that the fulfillment Lambda function should run before it times out.
            :param update_response: Provides configuration information for messages sent periodically to the user while the fulfillment Lambda function is running.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-fulfillmentupdatesspecification.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                fulfillment_updates_specification_property = lex.CfnBot.FulfillmentUpdatesSpecificationProperty(
                    active=False,
                
                    # the properties below are optional
                    start_response=lex.CfnBot.FulfillmentStartResponseSpecificationProperty(
                        delay_in_seconds=123,
                        message_groups=[lex.CfnBot.MessageGroupProperty(
                            message=lex.CfnBot.MessageProperty(
                                custom_payload=lex.CfnBot.CustomPayloadProperty(
                                    value="value"
                                ),
                                image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                    title="title",
                
                                    # the properties below are optional
                                    buttons=[lex.CfnBot.ButtonProperty(
                                        text="text",
                                        value="value"
                                    )],
                                    image_url="imageUrl",
                                    subtitle="subtitle"
                                ),
                                plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                    value="value"
                                ),
                                ssml_message=lex.CfnBot.SSMLMessageProperty(
                                    value="value"
                                )
                            ),
                
                            # the properties below are optional
                            variations=[lex.CfnBot.MessageProperty(
                                custom_payload=lex.CfnBot.CustomPayloadProperty(
                                    value="value"
                                ),
                                image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                    title="title",
                
                                    # the properties below are optional
                                    buttons=[lex.CfnBot.ButtonProperty(
                                        text="text",
                                        value="value"
                                    )],
                                    image_url="imageUrl",
                                    subtitle="subtitle"
                                ),
                                plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                    value="value"
                                ),
                                ssml_message=lex.CfnBot.SSMLMessageProperty(
                                    value="value"
                                )
                            )]
                        )],
                
                        # the properties below are optional
                        allow_interrupt=False
                    ),
                    timeout_in_seconds=123,
                    update_response=lex.CfnBot.FulfillmentUpdateResponseSpecificationProperty(
                        frequency_in_seconds=123,
                        message_groups=[lex.CfnBot.MessageGroupProperty(
                            message=lex.CfnBot.MessageProperty(
                                custom_payload=lex.CfnBot.CustomPayloadProperty(
                                    value="value"
                                ),
                                image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                    title="title",
                
                                    # the properties below are optional
                                    buttons=[lex.CfnBot.ButtonProperty(
                                        text="text",
                                        value="value"
                                    )],
                                    image_url="imageUrl",
                                    subtitle="subtitle"
                                ),
                                plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                    value="value"
                                ),
                                ssml_message=lex.CfnBot.SSMLMessageProperty(
                                    value="value"
                                )
                            ),
                
                            # the properties below are optional
                            variations=[lex.CfnBot.MessageProperty(
                                custom_payload=lex.CfnBot.CustomPayloadProperty(
                                    value="value"
                                ),
                                image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                    title="title",
                
                                    # the properties below are optional
                                    buttons=[lex.CfnBot.ButtonProperty(
                                        text="text",
                                        value="value"
                                    )],
                                    image_url="imageUrl",
                                    subtitle="subtitle"
                                ),
                                plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                    value="value"
                                ),
                                ssml_message=lex.CfnBot.SSMLMessageProperty(
                                    value="value"
                                )
                            )]
                        )],
                
                        # the properties below are optional
                        allow_interrupt=False
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "active": active,
            }
            if start_response is not None:
                self._values["start_response"] = start_response
            if timeout_in_seconds is not None:
                self._values["timeout_in_seconds"] = timeout_in_seconds
            if update_response is not None:
                self._values["update_response"] = update_response

        @builtins.property
        def active(self) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
            '''Determines whether fulfillment updates are sent to the user. When this field is true, updates are sent.

            If the active field is set to true, the ``startResponse`` , ``updateResponse`` , and ``timeoutInSeconds`` fields are required.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-fulfillmentupdatesspecification.html#cfn-lex-bot-fulfillmentupdatesspecification-active
            '''
            result = self._values.get("active")
            assert result is not None, "Required property 'active' is missing"
            return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], result)

        @builtins.property
        def start_response(
            self,
        ) -> typing.Optional[typing.Union["CfnBot.FulfillmentStartResponseSpecificationProperty", _IResolvable_da3f097b]]:
            '''Provides configuration information for the message sent to users when the fulfillment Lambda functions starts running.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-fulfillmentupdatesspecification.html#cfn-lex-bot-fulfillmentupdatesspecification-startresponse
            '''
            result = self._values.get("start_response")
            return typing.cast(typing.Optional[typing.Union["CfnBot.FulfillmentStartResponseSpecificationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def timeout_in_seconds(self) -> typing.Optional[jsii.Number]:
            '''The length of time that the fulfillment Lambda function should run before it times out.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-fulfillmentupdatesspecification.html#cfn-lex-bot-fulfillmentupdatesspecification-timeoutinseconds
            '''
            result = self._values.get("timeout_in_seconds")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def update_response(
            self,
        ) -> typing.Optional[typing.Union["CfnBot.FulfillmentUpdateResponseSpecificationProperty", _IResolvable_da3f097b]]:
            '''Provides configuration information for messages sent periodically to the user while the fulfillment Lambda function is running.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-fulfillmentupdatesspecification.html#cfn-lex-bot-fulfillmentupdatesspecification-updateresponse
            '''
            result = self._values.get("update_response")
            return typing.cast(typing.Optional[typing.Union["CfnBot.FulfillmentUpdateResponseSpecificationProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "FulfillmentUpdatesSpecificationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBot.GrammarSlotTypeSettingProperty",
        jsii_struct_bases=[],
        name_mapping={"source": "source"},
    )
    class GrammarSlotTypeSettingProperty:
        def __init__(
            self,
            *,
            source: typing.Optional[typing.Union["CfnBot.GrammarSlotTypeSourceProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Settings required for a slot type based on a grammar that you provide.

            :param source: The source of the grammar used to create the slot type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-grammarslottypesetting.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                grammar_slot_type_setting_property = lex.CfnBot.GrammarSlotTypeSettingProperty(
                    source=lex.CfnBot.GrammarSlotTypeSourceProperty(
                        s3_bucket_name="s3BucketName",
                        s3_object_key="s3ObjectKey",
                
                        # the properties below are optional
                        kms_key_arn="kmsKeyArn"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if source is not None:
                self._values["source"] = source

        @builtins.property
        def source(
            self,
        ) -> typing.Optional[typing.Union["CfnBot.GrammarSlotTypeSourceProperty", _IResolvable_da3f097b]]:
            '''The source of the grammar used to create the slot type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-grammarslottypesetting.html#cfn-lex-bot-grammarslottypesetting-source
            '''
            result = self._values.get("source")
            return typing.cast(typing.Optional[typing.Union["CfnBot.GrammarSlotTypeSourceProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "GrammarSlotTypeSettingProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBot.GrammarSlotTypeSourceProperty",
        jsii_struct_bases=[],
        name_mapping={
            "s3_bucket_name": "s3BucketName",
            "s3_object_key": "s3ObjectKey",
            "kms_key_arn": "kmsKeyArn",
        },
    )
    class GrammarSlotTypeSourceProperty:
        def __init__(
            self,
            *,
            s3_bucket_name: builtins.str,
            s3_object_key: builtins.str,
            kms_key_arn: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Describes the Amazon S3 bucket name and location for the grammar that is the source of the slot type.

            :param s3_bucket_name: The name of the S3 bucket that contains the grammar source.
            :param s3_object_key: The path to the grammar in the S3 bucket.
            :param kms_key_arn: The AWS Key Management Service key required to decrypt the contents of the grammar, if any.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-grammarslottypesource.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                grammar_slot_type_source_property = lex.CfnBot.GrammarSlotTypeSourceProperty(
                    s3_bucket_name="s3BucketName",
                    s3_object_key="s3ObjectKey",
                
                    # the properties below are optional
                    kms_key_arn="kmsKeyArn"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "s3_bucket_name": s3_bucket_name,
                "s3_object_key": s3_object_key,
            }
            if kms_key_arn is not None:
                self._values["kms_key_arn"] = kms_key_arn

        @builtins.property
        def s3_bucket_name(self) -> builtins.str:
            '''The name of the S3 bucket that contains the grammar source.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-grammarslottypesource.html#cfn-lex-bot-grammarslottypesource-s3bucketname
            '''
            result = self._values.get("s3_bucket_name")
            assert result is not None, "Required property 's3_bucket_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def s3_object_key(self) -> builtins.str:
            '''The path to the grammar in the S3 bucket.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-grammarslottypesource.html#cfn-lex-bot-grammarslottypesource-s3objectkey
            '''
            result = self._values.get("s3_object_key")
            assert result is not None, "Required property 's3_object_key' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def kms_key_arn(self) -> typing.Optional[builtins.str]:
            '''The AWS Key Management Service key required to decrypt the contents of the grammar, if any.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-grammarslottypesource.html#cfn-lex-bot-grammarslottypesource-kmskeyarn
            '''
            result = self._values.get("kms_key_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "GrammarSlotTypeSourceProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBot.ImageResponseCardProperty",
        jsii_struct_bases=[],
        name_mapping={
            "title": "title",
            "buttons": "buttons",
            "image_url": "imageUrl",
            "subtitle": "subtitle",
        },
    )
    class ImageResponseCardProperty:
        def __init__(
            self,
            *,
            title: builtins.str,
            buttons: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBot.ButtonProperty", _IResolvable_da3f097b]]]] = None,
            image_url: typing.Optional[builtins.str] = None,
            subtitle: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A card that is shown to the user by a messaging platform.

            You define the contents of the card, the card is displayed by the platform.

            When you use a response card, the response from the user is constrained to the text associated with a button on the card.

            :param title: The title to display on the response card. The format of the title is determined by the platform displaying the response card.
            :param buttons: A list of buttons that should be displayed on the response card. The arrangement of the buttons is determined by the platform that displays the buttons.
            :param image_url: The URL of an image to display on the response card. The image URL must be publicly available so that the platform displaying the response card has access to the image.
            :param subtitle: The subtitle to display on the response card. The format of the subtitle is determined by the platform displaying the response card.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-imageresponsecard.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                image_response_card_property = lex.CfnBot.ImageResponseCardProperty(
                    title="title",
                
                    # the properties below are optional
                    buttons=[lex.CfnBot.ButtonProperty(
                        text="text",
                        value="value"
                    )],
                    image_url="imageUrl",
                    subtitle="subtitle"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "title": title,
            }
            if buttons is not None:
                self._values["buttons"] = buttons
            if image_url is not None:
                self._values["image_url"] = image_url
            if subtitle is not None:
                self._values["subtitle"] = subtitle

        @builtins.property
        def title(self) -> builtins.str:
            '''The title to display on the response card.

            The format of the title is determined by the platform displaying the response card.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-imageresponsecard.html#cfn-lex-bot-imageresponsecard-title
            '''
            result = self._values.get("title")
            assert result is not None, "Required property 'title' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def buttons(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBot.ButtonProperty", _IResolvable_da3f097b]]]]:
            '''A list of buttons that should be displayed on the response card.

            The arrangement of the buttons is determined by the platform that displays the buttons.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-imageresponsecard.html#cfn-lex-bot-imageresponsecard-buttons
            '''
            result = self._values.get("buttons")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBot.ButtonProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def image_url(self) -> typing.Optional[builtins.str]:
            '''The URL of an image to display on the response card.

            The image URL must be publicly available so that the platform displaying the response card has access to the image.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-imageresponsecard.html#cfn-lex-bot-imageresponsecard-imageurl
            '''
            result = self._values.get("image_url")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def subtitle(self) -> typing.Optional[builtins.str]:
            '''The subtitle to display on the response card.

            The format of the subtitle is determined by the platform displaying the response card.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-imageresponsecard.html#cfn-lex-bot-imageresponsecard-subtitle
            '''
            result = self._values.get("subtitle")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ImageResponseCardProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBot.InputContextProperty",
        jsii_struct_bases=[],
        name_mapping={"name": "name"},
    )
    class InputContextProperty:
        def __init__(self, *, name: builtins.str) -> None:
            '''The name of a context that must be active for an intent to be selected by Amazon Lex .

            :param name: The name of the context.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-inputcontext.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                input_context_property = lex.CfnBot.InputContextProperty(
                    name="name"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "name": name,
            }

        @builtins.property
        def name(self) -> builtins.str:
            '''The name of the context.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-inputcontext.html#cfn-lex-bot-inputcontext-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "InputContextProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBot.IntentClosingSettingProperty",
        jsii_struct_bases=[],
        name_mapping={"closing_response": "closingResponse", "is_active": "isActive"},
    )
    class IntentClosingSettingProperty:
        def __init__(
            self,
            *,
            closing_response: typing.Union["CfnBot.ResponseSpecificationProperty", _IResolvable_da3f097b],
            is_active: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Provides a statement the Amazon Lex conveys to the user when the intent is successfully fulfilled.

            :param closing_response: The response that Amazon Lex sends to the user when the intent is complete.
            :param is_active: Specifies whether an intent's closing response is used. When this field is false, the closing response isn't sent to the user and no closing input from the user is used. If the IsActive field isn't specified, the default is true.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-intentclosingsetting.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                intent_closing_setting_property = lex.CfnBot.IntentClosingSettingProperty(
                    closing_response=lex.CfnBot.ResponseSpecificationProperty(
                        message_groups_list=[lex.CfnBot.MessageGroupProperty(
                            message=lex.CfnBot.MessageProperty(
                                custom_payload=lex.CfnBot.CustomPayloadProperty(
                                    value="value"
                                ),
                                image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                    title="title",
                
                                    # the properties below are optional
                                    buttons=[lex.CfnBot.ButtonProperty(
                                        text="text",
                                        value="value"
                                    )],
                                    image_url="imageUrl",
                                    subtitle="subtitle"
                                ),
                                plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                    value="value"
                                ),
                                ssml_message=lex.CfnBot.SSMLMessageProperty(
                                    value="value"
                                )
                            ),
                
                            # the properties below are optional
                            variations=[lex.CfnBot.MessageProperty(
                                custom_payload=lex.CfnBot.CustomPayloadProperty(
                                    value="value"
                                ),
                                image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                    title="title",
                
                                    # the properties below are optional
                                    buttons=[lex.CfnBot.ButtonProperty(
                                        text="text",
                                        value="value"
                                    )],
                                    image_url="imageUrl",
                                    subtitle="subtitle"
                                ),
                                plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                    value="value"
                                ),
                                ssml_message=lex.CfnBot.SSMLMessageProperty(
                                    value="value"
                                )
                            )]
                        )],
                
                        # the properties below are optional
                        allow_interrupt=False
                    ),
                
                    # the properties below are optional
                    is_active=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "closing_response": closing_response,
            }
            if is_active is not None:
                self._values["is_active"] = is_active

        @builtins.property
        def closing_response(
            self,
        ) -> typing.Union["CfnBot.ResponseSpecificationProperty", _IResolvable_da3f097b]:
            '''The response that Amazon Lex sends to the user when the intent is complete.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-intentclosingsetting.html#cfn-lex-bot-intentclosingsetting-closingresponse
            '''
            result = self._values.get("closing_response")
            assert result is not None, "Required property 'closing_response' is missing"
            return typing.cast(typing.Union["CfnBot.ResponseSpecificationProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def is_active(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Specifies whether an intent's closing response is used.

            When this field is false, the closing response isn't sent to the user and no closing input from the user is used. If the IsActive field isn't specified, the default is true.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-intentclosingsetting.html#cfn-lex-bot-intentclosingsetting-isactive
            '''
            result = self._values.get("is_active")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "IntentClosingSettingProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBot.IntentConfirmationSettingProperty",
        jsii_struct_bases=[],
        name_mapping={
            "declination_response": "declinationResponse",
            "prompt_specification": "promptSpecification",
            "is_active": "isActive",
        },
    )
    class IntentConfirmationSettingProperty:
        def __init__(
            self,
            *,
            declination_response: typing.Union["CfnBot.ResponseSpecificationProperty", _IResolvable_da3f097b],
            prompt_specification: typing.Union["CfnBot.PromptSpecificationProperty", _IResolvable_da3f097b],
            is_active: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Provides a prompt for making sure that the user is ready for the intent to be fulfilled.

            :param declination_response: When the user answers "no" to the question defined in PromptSpecification, Amazon Lex responds with this response to acknowledge that the intent was canceled.
            :param prompt_specification: Prompts the user to confirm the intent. This question should have a yes or no answer.
            :param is_active: Specifies whether the intent's confirmation is sent to the user. When this field is false, confirmation and declination responses aren't sent and processing continues as if the responses aren't present. If the active field isn't specified, the default is true.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-intentconfirmationsetting.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                intent_confirmation_setting_property = lex.CfnBot.IntentConfirmationSettingProperty(
                    declination_response=lex.CfnBot.ResponseSpecificationProperty(
                        message_groups_list=[lex.CfnBot.MessageGroupProperty(
                            message=lex.CfnBot.MessageProperty(
                                custom_payload=lex.CfnBot.CustomPayloadProperty(
                                    value="value"
                                ),
                                image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                    title="title",
                
                                    # the properties below are optional
                                    buttons=[lex.CfnBot.ButtonProperty(
                                        text="text",
                                        value="value"
                                    )],
                                    image_url="imageUrl",
                                    subtitle="subtitle"
                                ),
                                plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                    value="value"
                                ),
                                ssml_message=lex.CfnBot.SSMLMessageProperty(
                                    value="value"
                                )
                            ),
                
                            # the properties below are optional
                            variations=[lex.CfnBot.MessageProperty(
                                custom_payload=lex.CfnBot.CustomPayloadProperty(
                                    value="value"
                                ),
                                image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                    title="title",
                
                                    # the properties below are optional
                                    buttons=[lex.CfnBot.ButtonProperty(
                                        text="text",
                                        value="value"
                                    )],
                                    image_url="imageUrl",
                                    subtitle="subtitle"
                                ),
                                plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                    value="value"
                                ),
                                ssml_message=lex.CfnBot.SSMLMessageProperty(
                                    value="value"
                                )
                            )]
                        )],
                
                        # the properties below are optional
                        allow_interrupt=False
                    ),
                    prompt_specification=lex.CfnBot.PromptSpecificationProperty(
                        max_retries=123,
                        message_groups_list=[lex.CfnBot.MessageGroupProperty(
                            message=lex.CfnBot.MessageProperty(
                                custom_payload=lex.CfnBot.CustomPayloadProperty(
                                    value="value"
                                ),
                                image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                    title="title",
                
                                    # the properties below are optional
                                    buttons=[lex.CfnBot.ButtonProperty(
                                        text="text",
                                        value="value"
                                    )],
                                    image_url="imageUrl",
                                    subtitle="subtitle"
                                ),
                                plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                    value="value"
                                ),
                                ssml_message=lex.CfnBot.SSMLMessageProperty(
                                    value="value"
                                )
                            ),
                
                            # the properties below are optional
                            variations=[lex.CfnBot.MessageProperty(
                                custom_payload=lex.CfnBot.CustomPayloadProperty(
                                    value="value"
                                ),
                                image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                    title="title",
                
                                    # the properties below are optional
                                    buttons=[lex.CfnBot.ButtonProperty(
                                        text="text",
                                        value="value"
                                    )],
                                    image_url="imageUrl",
                                    subtitle="subtitle"
                                ),
                                plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                    value="value"
                                ),
                                ssml_message=lex.CfnBot.SSMLMessageProperty(
                                    value="value"
                                )
                            )]
                        )],
                
                        # the properties below are optional
                        allow_interrupt=False
                    ),
                
                    # the properties below are optional
                    is_active=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "declination_response": declination_response,
                "prompt_specification": prompt_specification,
            }
            if is_active is not None:
                self._values["is_active"] = is_active

        @builtins.property
        def declination_response(
            self,
        ) -> typing.Union["CfnBot.ResponseSpecificationProperty", _IResolvable_da3f097b]:
            '''When the user answers "no" to the question defined in PromptSpecification, Amazon Lex responds with this response to acknowledge that the intent was canceled.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-intentconfirmationsetting.html#cfn-lex-bot-intentconfirmationsetting-declinationresponse
            '''
            result = self._values.get("declination_response")
            assert result is not None, "Required property 'declination_response' is missing"
            return typing.cast(typing.Union["CfnBot.ResponseSpecificationProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def prompt_specification(
            self,
        ) -> typing.Union["CfnBot.PromptSpecificationProperty", _IResolvable_da3f097b]:
            '''Prompts the user to confirm the intent.

            This question should have a yes or no answer.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-intentconfirmationsetting.html#cfn-lex-bot-intentconfirmationsetting-promptspecification
            '''
            result = self._values.get("prompt_specification")
            assert result is not None, "Required property 'prompt_specification' is missing"
            return typing.cast(typing.Union["CfnBot.PromptSpecificationProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def is_active(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Specifies whether the intent's confirmation is sent to the user.

            When this field is false, confirmation and declination responses aren't sent and processing continues as if the responses aren't present. If the active field isn't specified, the default is true.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-intentconfirmationsetting.html#cfn-lex-bot-intentconfirmationsetting-isactive
            '''
            result = self._values.get("is_active")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "IntentConfirmationSettingProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBot.IntentProperty",
        jsii_struct_bases=[],
        name_mapping={
            "name": "name",
            "description": "description",
            "dialog_code_hook": "dialogCodeHook",
            "fulfillment_code_hook": "fulfillmentCodeHook",
            "input_contexts": "inputContexts",
            "intent_closing_setting": "intentClosingSetting",
            "intent_confirmation_setting": "intentConfirmationSetting",
            "kendra_configuration": "kendraConfiguration",
            "output_contexts": "outputContexts",
            "parent_intent_signature": "parentIntentSignature",
            "sample_utterances": "sampleUtterances",
            "slot_priorities": "slotPriorities",
            "slots": "slots",
        },
    )
    class IntentProperty:
        def __init__(
            self,
            *,
            name: builtins.str,
            description: typing.Optional[builtins.str] = None,
            dialog_code_hook: typing.Optional[typing.Union["CfnBot.DialogCodeHookSettingProperty", _IResolvable_da3f097b]] = None,
            fulfillment_code_hook: typing.Optional[typing.Union["CfnBot.FulfillmentCodeHookSettingProperty", _IResolvable_da3f097b]] = None,
            input_contexts: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBot.InputContextProperty", _IResolvable_da3f097b]]]] = None,
            intent_closing_setting: typing.Optional[typing.Union["CfnBot.IntentClosingSettingProperty", _IResolvable_da3f097b]] = None,
            intent_confirmation_setting: typing.Optional[typing.Union["CfnBot.IntentConfirmationSettingProperty", _IResolvable_da3f097b]] = None,
            kendra_configuration: typing.Optional[typing.Union["CfnBot.KendraConfigurationProperty", _IResolvable_da3f097b]] = None,
            output_contexts: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBot.OutputContextProperty", _IResolvable_da3f097b]]]] = None,
            parent_intent_signature: typing.Optional[builtins.str] = None,
            sample_utterances: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBot.SampleUtteranceProperty", _IResolvable_da3f097b]]]] = None,
            slot_priorities: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBot.SlotPriorityProperty", _IResolvable_da3f097b]]]] = None,
            slots: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBot.SlotProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''Represents an action that the user wants to perform.

            :param name: The name of the intent. Intent names must be unique within the locale that contains the intent and can't match the name of any built-in intent.
            :param description: A description of the intent. Use the description to help identify the intent in lists.
            :param dialog_code_hook: Specifies that Amazon Lex invokes the alias Lambda function for each user input. You can invoke this Lambda function to personalize user interaction.
            :param fulfillment_code_hook: Specifies that Amazon Lex invokes the alias Lambda function when the intent is ready for fulfillment. You can invoke this function to complete the bot's transaction with the user.
            :param input_contexts: A list of contexts that must be active for this intent to be considered by Amazon Lex .
            :param intent_closing_setting: Sets the response that Amazon Lex sends to the user when the intent is closed.
            :param intent_confirmation_setting: Provides prompts that Amazon Lex sends to the user to confirm the completion of an intent. If the user answers "no," the settings contain a statement that is sent to the user to end the intent.
            :param kendra_configuration: Configuration information required to use the AMAZON.KendraSearchIntent intent to connect to an Amazon Kendra index. The AMAZON.KendraSearchIntent intent is called with Amazon Lex can't determine another intent to invoke.
            :param output_contexts: A list of contexts that the intent activates when it is fulfilled.
            :param parent_intent_signature: A unique identifier for the built-in intent to base this intent on.
            :param sample_utterances: A list of utterances that a user might say to signal the intent.
            :param slot_priorities: Indicates the priority for slots. Amazon Lex prompts the user for slot values in priority order.
            :param slots: A list of slots that the intent requires for fulfillment.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-intent.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                intent_property = lex.CfnBot.IntentProperty(
                    name="name",
                
                    # the properties below are optional
                    description="description",
                    dialog_code_hook=lex.CfnBot.DialogCodeHookSettingProperty(
                        enabled=False
                    ),
                    fulfillment_code_hook=lex.CfnBot.FulfillmentCodeHookSettingProperty(
                        enabled=False,
                
                        # the properties below are optional
                        fulfillment_updates_specification=lex.CfnBot.FulfillmentUpdatesSpecificationProperty(
                            active=False,
                
                            # the properties below are optional
                            start_response=lex.CfnBot.FulfillmentStartResponseSpecificationProperty(
                                delay_in_seconds=123,
                                message_groups=[lex.CfnBot.MessageGroupProperty(
                                    message=lex.CfnBot.MessageProperty(
                                        custom_payload=lex.CfnBot.CustomPayloadProperty(
                                            value="value"
                                        ),
                                        image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                            title="title",
                
                                            # the properties below are optional
                                            buttons=[lex.CfnBot.ButtonProperty(
                                                text="text",
                                                value="value"
                                            )],
                                            image_url="imageUrl",
                                            subtitle="subtitle"
                                        ),
                                        plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                            value="value"
                                        ),
                                        ssml_message=lex.CfnBot.SSMLMessageProperty(
                                            value="value"
                                        )
                                    ),
                
                                    # the properties below are optional
                                    variations=[lex.CfnBot.MessageProperty(
                                        custom_payload=lex.CfnBot.CustomPayloadProperty(
                                            value="value"
                                        ),
                                        image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                            title="title",
                
                                            # the properties below are optional
                                            buttons=[lex.CfnBot.ButtonProperty(
                                                text="text",
                                                value="value"
                                            )],
                                            image_url="imageUrl",
                                            subtitle="subtitle"
                                        ),
                                        plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                            value="value"
                                        ),
                                        ssml_message=lex.CfnBot.SSMLMessageProperty(
                                            value="value"
                                        )
                                    )]
                                )],
                
                                # the properties below are optional
                                allow_interrupt=False
                            ),
                            timeout_in_seconds=123,
                            update_response=lex.CfnBot.FulfillmentUpdateResponseSpecificationProperty(
                                frequency_in_seconds=123,
                                message_groups=[lex.CfnBot.MessageGroupProperty(
                                    message=lex.CfnBot.MessageProperty(
                                        custom_payload=lex.CfnBot.CustomPayloadProperty(
                                            value="value"
                                        ),
                                        image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                            title="title",
                
                                            # the properties below are optional
                                            buttons=[lex.CfnBot.ButtonProperty(
                                                text="text",
                                                value="value"
                                            )],
                                            image_url="imageUrl",
                                            subtitle="subtitle"
                                        ),
                                        plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                            value="value"
                                        ),
                                        ssml_message=lex.CfnBot.SSMLMessageProperty(
                                            value="value"
                                        )
                                    ),
                
                                    # the properties below are optional
                                    variations=[lex.CfnBot.MessageProperty(
                                        custom_payload=lex.CfnBot.CustomPayloadProperty(
                                            value="value"
                                        ),
                                        image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                            title="title",
                
                                            # the properties below are optional
                                            buttons=[lex.CfnBot.ButtonProperty(
                                                text="text",
                                                value="value"
                                            )],
                                            image_url="imageUrl",
                                            subtitle="subtitle"
                                        ),
                                        plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                            value="value"
                                        ),
                                        ssml_message=lex.CfnBot.SSMLMessageProperty(
                                            value="value"
                                        )
                                    )]
                                )],
                
                                # the properties below are optional
                                allow_interrupt=False
                            )
                        ),
                        post_fulfillment_status_specification=lex.CfnBot.PostFulfillmentStatusSpecificationProperty(
                            failure_response=lex.CfnBot.ResponseSpecificationProperty(
                                message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                    message=lex.CfnBot.MessageProperty(
                                        custom_payload=lex.CfnBot.CustomPayloadProperty(
                                            value="value"
                                        ),
                                        image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                            title="title",
                
                                            # the properties below are optional
                                            buttons=[lex.CfnBot.ButtonProperty(
                                                text="text",
                                                value="value"
                                            )],
                                            image_url="imageUrl",
                                            subtitle="subtitle"
                                        ),
                                        plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                            value="value"
                                        ),
                                        ssml_message=lex.CfnBot.SSMLMessageProperty(
                                            value="value"
                                        )
                                    ),
                
                                    # the properties below are optional
                                    variations=[lex.CfnBot.MessageProperty(
                                        custom_payload=lex.CfnBot.CustomPayloadProperty(
                                            value="value"
                                        ),
                                        image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                            title="title",
                
                                            # the properties below are optional
                                            buttons=[lex.CfnBot.ButtonProperty(
                                                text="text",
                                                value="value"
                                            )],
                                            image_url="imageUrl",
                                            subtitle="subtitle"
                                        ),
                                        plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                            value="value"
                                        ),
                                        ssml_message=lex.CfnBot.SSMLMessageProperty(
                                            value="value"
                                        )
                                    )]
                                )],
                
                                # the properties below are optional
                                allow_interrupt=False
                            ),
                            success_response=lex.CfnBot.ResponseSpecificationProperty(
                                message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                    message=lex.CfnBot.MessageProperty(
                                        custom_payload=lex.CfnBot.CustomPayloadProperty(
                                            value="value"
                                        ),
                                        image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                            title="title",
                
                                            # the properties below are optional
                                            buttons=[lex.CfnBot.ButtonProperty(
                                                text="text",
                                                value="value"
                                            )],
                                            image_url="imageUrl",
                                            subtitle="subtitle"
                                        ),
                                        plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                            value="value"
                                        ),
                                        ssml_message=lex.CfnBot.SSMLMessageProperty(
                                            value="value"
                                        )
                                    ),
                
                                    # the properties below are optional
                                    variations=[lex.CfnBot.MessageProperty(
                                        custom_payload=lex.CfnBot.CustomPayloadProperty(
                                            value="value"
                                        ),
                                        image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                            title="title",
                
                                            # the properties below are optional
                                            buttons=[lex.CfnBot.ButtonProperty(
                                                text="text",
                                                value="value"
                                            )],
                                            image_url="imageUrl",
                                            subtitle="subtitle"
                                        ),
                                        plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                            value="value"
                                        ),
                                        ssml_message=lex.CfnBot.SSMLMessageProperty(
                                            value="value"
                                        )
                                    )]
                                )],
                
                                # the properties below are optional
                                allow_interrupt=False
                            ),
                            timeout_response=lex.CfnBot.ResponseSpecificationProperty(
                                message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                    message=lex.CfnBot.MessageProperty(
                                        custom_payload=lex.CfnBot.CustomPayloadProperty(
                                            value="value"
                                        ),
                                        image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                            title="title",
                
                                            # the properties below are optional
                                            buttons=[lex.CfnBot.ButtonProperty(
                                                text="text",
                                                value="value"
                                            )],
                                            image_url="imageUrl",
                                            subtitle="subtitle"
                                        ),
                                        plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                            value="value"
                                        ),
                                        ssml_message=lex.CfnBot.SSMLMessageProperty(
                                            value="value"
                                        )
                                    ),
                
                                    # the properties below are optional
                                    variations=[lex.CfnBot.MessageProperty(
                                        custom_payload=lex.CfnBot.CustomPayloadProperty(
                                            value="value"
                                        ),
                                        image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                            title="title",
                
                                            # the properties below are optional
                                            buttons=[lex.CfnBot.ButtonProperty(
                                                text="text",
                                                value="value"
                                            )],
                                            image_url="imageUrl",
                                            subtitle="subtitle"
                                        ),
                                        plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                            value="value"
                                        ),
                                        ssml_message=lex.CfnBot.SSMLMessageProperty(
                                            value="value"
                                        )
                                    )]
                                )],
                
                                # the properties below are optional
                                allow_interrupt=False
                            )
                        )
                    ),
                    input_contexts=[lex.CfnBot.InputContextProperty(
                        name="name"
                    )],
                    intent_closing_setting=lex.CfnBot.IntentClosingSettingProperty(
                        closing_response=lex.CfnBot.ResponseSpecificationProperty(
                            message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                message=lex.CfnBot.MessageProperty(
                                    custom_payload=lex.CfnBot.CustomPayloadProperty(
                                        value="value"
                                    ),
                                    image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                        title="title",
                
                                        # the properties below are optional
                                        buttons=[lex.CfnBot.ButtonProperty(
                                            text="text",
                                            value="value"
                                        )],
                                        image_url="imageUrl",
                                        subtitle="subtitle"
                                    ),
                                    plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                        value="value"
                                    ),
                                    ssml_message=lex.CfnBot.SSMLMessageProperty(
                                        value="value"
                                    )
                                ),
                
                                # the properties below are optional
                                variations=[lex.CfnBot.MessageProperty(
                                    custom_payload=lex.CfnBot.CustomPayloadProperty(
                                        value="value"
                                    ),
                                    image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                        title="title",
                
                                        # the properties below are optional
                                        buttons=[lex.CfnBot.ButtonProperty(
                                            text="text",
                                            value="value"
                                        )],
                                        image_url="imageUrl",
                                        subtitle="subtitle"
                                    ),
                                    plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                        value="value"
                                    ),
                                    ssml_message=lex.CfnBot.SSMLMessageProperty(
                                        value="value"
                                    )
                                )]
                            )],
                
                            # the properties below are optional
                            allow_interrupt=False
                        ),
                
                        # the properties below are optional
                        is_active=False
                    ),
                    intent_confirmation_setting=lex.CfnBot.IntentConfirmationSettingProperty(
                        declination_response=lex.CfnBot.ResponseSpecificationProperty(
                            message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                message=lex.CfnBot.MessageProperty(
                                    custom_payload=lex.CfnBot.CustomPayloadProperty(
                                        value="value"
                                    ),
                                    image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                        title="title",
                
                                        # the properties below are optional
                                        buttons=[lex.CfnBot.ButtonProperty(
                                            text="text",
                                            value="value"
                                        )],
                                        image_url="imageUrl",
                                        subtitle="subtitle"
                                    ),
                                    plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                        value="value"
                                    ),
                                    ssml_message=lex.CfnBot.SSMLMessageProperty(
                                        value="value"
                                    )
                                ),
                
                                # the properties below are optional
                                variations=[lex.CfnBot.MessageProperty(
                                    custom_payload=lex.CfnBot.CustomPayloadProperty(
                                        value="value"
                                    ),
                                    image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                        title="title",
                
                                        # the properties below are optional
                                        buttons=[lex.CfnBot.ButtonProperty(
                                            text="text",
                                            value="value"
                                        )],
                                        image_url="imageUrl",
                                        subtitle="subtitle"
                                    ),
                                    plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                        value="value"
                                    ),
                                    ssml_message=lex.CfnBot.SSMLMessageProperty(
                                        value="value"
                                    )
                                )]
                            )],
                
                            # the properties below are optional
                            allow_interrupt=False
                        ),
                        prompt_specification=lex.CfnBot.PromptSpecificationProperty(
                            max_retries=123,
                            message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                message=lex.CfnBot.MessageProperty(
                                    custom_payload=lex.CfnBot.CustomPayloadProperty(
                                        value="value"
                                    ),
                                    image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                        title="title",
                
                                        # the properties below are optional
                                        buttons=[lex.CfnBot.ButtonProperty(
                                            text="text",
                                            value="value"
                                        )],
                                        image_url="imageUrl",
                                        subtitle="subtitle"
                                    ),
                                    plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                        value="value"
                                    ),
                                    ssml_message=lex.CfnBot.SSMLMessageProperty(
                                        value="value"
                                    )
                                ),
                
                                # the properties below are optional
                                variations=[lex.CfnBot.MessageProperty(
                                    custom_payload=lex.CfnBot.CustomPayloadProperty(
                                        value="value"
                                    ),
                                    image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                        title="title",
                
                                        # the properties below are optional
                                        buttons=[lex.CfnBot.ButtonProperty(
                                            text="text",
                                            value="value"
                                        )],
                                        image_url="imageUrl",
                                        subtitle="subtitle"
                                    ),
                                    plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                        value="value"
                                    ),
                                    ssml_message=lex.CfnBot.SSMLMessageProperty(
                                        value="value"
                                    )
                                )]
                            )],
                
                            # the properties below are optional
                            allow_interrupt=False
                        ),
                
                        # the properties below are optional
                        is_active=False
                    ),
                    kendra_configuration=lex.CfnBot.KendraConfigurationProperty(
                        kendra_index="kendraIndex",
                
                        # the properties below are optional
                        query_filter_string="queryFilterString",
                        query_filter_string_enabled=False
                    ),
                    output_contexts=[lex.CfnBot.OutputContextProperty(
                        name="name",
                        time_to_live_in_seconds=123,
                        turns_to_live=123
                    )],
                    parent_intent_signature="parentIntentSignature",
                    sample_utterances=[lex.CfnBot.SampleUtteranceProperty(
                        utterance="utterance"
                    )],
                    slot_priorities=[lex.CfnBot.SlotPriorityProperty(
                        priority=123,
                        slot_name="slotName"
                    )],
                    slots=[lex.CfnBot.SlotProperty(
                        name="name",
                        slot_type_name="slotTypeName",
                        value_elicitation_setting=lex.CfnBot.SlotValueElicitationSettingProperty(
                            slot_constraint="slotConstraint",
                
                            # the properties below are optional
                            default_value_specification=lex.CfnBot.SlotDefaultValueSpecificationProperty(
                                default_value_list=[lex.CfnBot.SlotDefaultValueProperty(
                                    default_value="defaultValue"
                                )]
                            ),
                            prompt_specification=lex.CfnBot.PromptSpecificationProperty(
                                max_retries=123,
                                message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                    message=lex.CfnBot.MessageProperty(
                                        custom_payload=lex.CfnBot.CustomPayloadProperty(
                                            value="value"
                                        ),
                                        image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                            title="title",
                
                                            # the properties below are optional
                                            buttons=[lex.CfnBot.ButtonProperty(
                                                text="text",
                                                value="value"
                                            )],
                                            image_url="imageUrl",
                                            subtitle="subtitle"
                                        ),
                                        plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                            value="value"
                                        ),
                                        ssml_message=lex.CfnBot.SSMLMessageProperty(
                                            value="value"
                                        )
                                    ),
                
                                    # the properties below are optional
                                    variations=[lex.CfnBot.MessageProperty(
                                        custom_payload=lex.CfnBot.CustomPayloadProperty(
                                            value="value"
                                        ),
                                        image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                            title="title",
                
                                            # the properties below are optional
                                            buttons=[lex.CfnBot.ButtonProperty(
                                                text="text",
                                                value="value"
                                            )],
                                            image_url="imageUrl",
                                            subtitle="subtitle"
                                        ),
                                        plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                            value="value"
                                        ),
                                        ssml_message=lex.CfnBot.SSMLMessageProperty(
                                            value="value"
                                        )
                                    )]
                                )],
                
                                # the properties below are optional
                                allow_interrupt=False
                            ),
                            sample_utterances=[lex.CfnBot.SampleUtteranceProperty(
                                utterance="utterance"
                            )],
                            wait_and_continue_specification=lex.CfnBot.WaitAndContinueSpecificationProperty(
                                continue_response=lex.CfnBot.ResponseSpecificationProperty(
                                    message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                        message=lex.CfnBot.MessageProperty(
                                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                value="value"
                                            ),
                                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                title="title",
                
                                                # the properties below are optional
                                                buttons=[lex.CfnBot.ButtonProperty(
                                                    text="text",
                                                    value="value"
                                                )],
                                                image_url="imageUrl",
                                                subtitle="subtitle"
                                            ),
                                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                value="value"
                                            ),
                                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                value="value"
                                            )
                                        ),
                
                                        # the properties below are optional
                                        variations=[lex.CfnBot.MessageProperty(
                                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                value="value"
                                            ),
                                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                title="title",
                
                                                # the properties below are optional
                                                buttons=[lex.CfnBot.ButtonProperty(
                                                    text="text",
                                                    value="value"
                                                )],
                                                image_url="imageUrl",
                                                subtitle="subtitle"
                                            ),
                                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                value="value"
                                            ),
                                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                value="value"
                                            )
                                        )]
                                    )],
                
                                    # the properties below are optional
                                    allow_interrupt=False
                                ),
                                waiting_response=lex.CfnBot.ResponseSpecificationProperty(
                                    message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                        message=lex.CfnBot.MessageProperty(
                                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                value="value"
                                            ),
                                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                title="title",
                
                                                # the properties below are optional
                                                buttons=[lex.CfnBot.ButtonProperty(
                                                    text="text",
                                                    value="value"
                                                )],
                                                image_url="imageUrl",
                                                subtitle="subtitle"
                                            ),
                                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                value="value"
                                            ),
                                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                value="value"
                                            )
                                        ),
                
                                        # the properties below are optional
                                        variations=[lex.CfnBot.MessageProperty(
                                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                value="value"
                                            ),
                                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                title="title",
                
                                                # the properties below are optional
                                                buttons=[lex.CfnBot.ButtonProperty(
                                                    text="text",
                                                    value="value"
                                                )],
                                                image_url="imageUrl",
                                                subtitle="subtitle"
                                            ),
                                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                value="value"
                                            ),
                                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                value="value"
                                            )
                                        )]
                                    )],
                
                                    # the properties below are optional
                                    allow_interrupt=False
                                ),
                
                                # the properties below are optional
                                is_active=False,
                                still_waiting_response=lex.CfnBot.StillWaitingResponseSpecificationProperty(
                                    frequency_in_seconds=123,
                                    message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                        message=lex.CfnBot.MessageProperty(
                                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                value="value"
                                            ),
                                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                title="title",
                
                                                # the properties below are optional
                                                buttons=[lex.CfnBot.ButtonProperty(
                                                    text="text",
                                                    value="value"
                                                )],
                                                image_url="imageUrl",
                                                subtitle="subtitle"
                                            ),
                                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                value="value"
                                            ),
                                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                value="value"
                                            )
                                        ),
                
                                        # the properties below are optional
                                        variations=[lex.CfnBot.MessageProperty(
                                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                value="value"
                                            ),
                                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                title="title",
                
                                                # the properties below are optional
                                                buttons=[lex.CfnBot.ButtonProperty(
                                                    text="text",
                                                    value="value"
                                                )],
                                                image_url="imageUrl",
                                                subtitle="subtitle"
                                            ),
                                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                value="value"
                                            ),
                                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                value="value"
                                            )
                                        )]
                                    )],
                                    timeout_in_seconds=123,
                
                                    # the properties below are optional
                                    allow_interrupt=False
                                )
                            )
                        ),
                
                        # the properties below are optional
                        description="description",
                        multiple_values_setting=lex.CfnBot.MultipleValuesSettingProperty(
                            allow_multiple_values=False
                        ),
                        obfuscation_setting=lex.CfnBot.ObfuscationSettingProperty(
                            obfuscation_setting_type="obfuscationSettingType"
                        )
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "name": name,
            }
            if description is not None:
                self._values["description"] = description
            if dialog_code_hook is not None:
                self._values["dialog_code_hook"] = dialog_code_hook
            if fulfillment_code_hook is not None:
                self._values["fulfillment_code_hook"] = fulfillment_code_hook
            if input_contexts is not None:
                self._values["input_contexts"] = input_contexts
            if intent_closing_setting is not None:
                self._values["intent_closing_setting"] = intent_closing_setting
            if intent_confirmation_setting is not None:
                self._values["intent_confirmation_setting"] = intent_confirmation_setting
            if kendra_configuration is not None:
                self._values["kendra_configuration"] = kendra_configuration
            if output_contexts is not None:
                self._values["output_contexts"] = output_contexts
            if parent_intent_signature is not None:
                self._values["parent_intent_signature"] = parent_intent_signature
            if sample_utterances is not None:
                self._values["sample_utterances"] = sample_utterances
            if slot_priorities is not None:
                self._values["slot_priorities"] = slot_priorities
            if slots is not None:
                self._values["slots"] = slots

        @builtins.property
        def name(self) -> builtins.str:
            '''The name of the intent.

            Intent names must be unique within the locale that contains the intent and can't match the name of any built-in intent.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-intent.html#cfn-lex-bot-intent-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def description(self) -> typing.Optional[builtins.str]:
            '''A description of the intent.

            Use the description to help identify the intent in lists.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-intent.html#cfn-lex-bot-intent-description
            '''
            result = self._values.get("description")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def dialog_code_hook(
            self,
        ) -> typing.Optional[typing.Union["CfnBot.DialogCodeHookSettingProperty", _IResolvable_da3f097b]]:
            '''Specifies that Amazon Lex invokes the alias Lambda function for each user input.

            You can invoke this Lambda function to personalize user interaction.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-intent.html#cfn-lex-bot-intent-dialogcodehook
            '''
            result = self._values.get("dialog_code_hook")
            return typing.cast(typing.Optional[typing.Union["CfnBot.DialogCodeHookSettingProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def fulfillment_code_hook(
            self,
        ) -> typing.Optional[typing.Union["CfnBot.FulfillmentCodeHookSettingProperty", _IResolvable_da3f097b]]:
            '''Specifies that Amazon Lex invokes the alias Lambda function when the intent is ready for fulfillment.

            You can invoke this function to complete the bot's transaction with the user.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-intent.html#cfn-lex-bot-intent-fulfillmentcodehook
            '''
            result = self._values.get("fulfillment_code_hook")
            return typing.cast(typing.Optional[typing.Union["CfnBot.FulfillmentCodeHookSettingProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def input_contexts(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBot.InputContextProperty", _IResolvable_da3f097b]]]]:
            '''A list of contexts that must be active for this intent to be considered by Amazon Lex .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-intent.html#cfn-lex-bot-intent-inputcontexts
            '''
            result = self._values.get("input_contexts")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBot.InputContextProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def intent_closing_setting(
            self,
        ) -> typing.Optional[typing.Union["CfnBot.IntentClosingSettingProperty", _IResolvable_da3f097b]]:
            '''Sets the response that Amazon Lex sends to the user when the intent is closed.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-intent.html#cfn-lex-bot-intent-intentclosingsetting
            '''
            result = self._values.get("intent_closing_setting")
            return typing.cast(typing.Optional[typing.Union["CfnBot.IntentClosingSettingProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def intent_confirmation_setting(
            self,
        ) -> typing.Optional[typing.Union["CfnBot.IntentConfirmationSettingProperty", _IResolvable_da3f097b]]:
            '''Provides prompts that Amazon Lex sends to the user to confirm the completion of an intent.

            If the user answers "no," the settings contain a statement that is sent to the user to end the intent.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-intent.html#cfn-lex-bot-intent-intentconfirmationsetting
            '''
            result = self._values.get("intent_confirmation_setting")
            return typing.cast(typing.Optional[typing.Union["CfnBot.IntentConfirmationSettingProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def kendra_configuration(
            self,
        ) -> typing.Optional[typing.Union["CfnBot.KendraConfigurationProperty", _IResolvable_da3f097b]]:
            '''Configuration information required to use the AMAZON.KendraSearchIntent intent to connect to an Amazon Kendra index. The AMAZON.KendraSearchIntent intent is called with Amazon Lex can't determine another intent to invoke.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-intent.html#cfn-lex-bot-intent-kendraconfiguration
            '''
            result = self._values.get("kendra_configuration")
            return typing.cast(typing.Optional[typing.Union["CfnBot.KendraConfigurationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def output_contexts(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBot.OutputContextProperty", _IResolvable_da3f097b]]]]:
            '''A list of contexts that the intent activates when it is fulfilled.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-intent.html#cfn-lex-bot-intent-outputcontexts
            '''
            result = self._values.get("output_contexts")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBot.OutputContextProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def parent_intent_signature(self) -> typing.Optional[builtins.str]:
            '''A unique identifier for the built-in intent to base this intent on.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-intent.html#cfn-lex-bot-intent-parentintentsignature
            '''
            result = self._values.get("parent_intent_signature")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def sample_utterances(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBot.SampleUtteranceProperty", _IResolvable_da3f097b]]]]:
            '''A list of utterances that a user might say to signal the intent.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-intent.html#cfn-lex-bot-intent-sampleutterances
            '''
            result = self._values.get("sample_utterances")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBot.SampleUtteranceProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def slot_priorities(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBot.SlotPriorityProperty", _IResolvable_da3f097b]]]]:
            '''Indicates the priority for slots.

            Amazon Lex prompts the user for slot values in priority order.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-intent.html#cfn-lex-bot-intent-slotpriorities
            '''
            result = self._values.get("slot_priorities")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBot.SlotPriorityProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def slots(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBot.SlotProperty", _IResolvable_da3f097b]]]]:
            '''A list of slots that the intent requires for fulfillment.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-intent.html#cfn-lex-bot-intent-slots
            '''
            result = self._values.get("slots")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBot.SlotProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "IntentProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBot.KendraConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "kendra_index": "kendraIndex",
            "query_filter_string": "queryFilterString",
            "query_filter_string_enabled": "queryFilterStringEnabled",
        },
    )
    class KendraConfigurationProperty:
        def __init__(
            self,
            *,
            kendra_index: builtins.str,
            query_filter_string: typing.Optional[builtins.str] = None,
            query_filter_string_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Provides configuration information for the AMAZON.KendraSearchIntent intent. When you use this intent, Amazon Lex searches the specified Amazon Kendra index and returns documents from the index that match the user's utterance.

            :param kendra_index: The Amazon Resource Name (ARN) of the Amazon Kendra index that you want the AMAZON.KendraSearchIntent intent to search. The index must be in the same account and Region as the Amazon Lex bot.
            :param query_filter_string: A query filter that Amazon Lex sends to Amazon Kendra to filter the response from a query. The filter is in the format defined by Amazon Kendra.
            :param query_filter_string_enabled: Determines whether the AMAZON.KendraSearchIntent intent uses a custom query string to query the Amazon Kendra index.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-kendraconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                kendra_configuration_property = lex.CfnBot.KendraConfigurationProperty(
                    kendra_index="kendraIndex",
                
                    # the properties below are optional
                    query_filter_string="queryFilterString",
                    query_filter_string_enabled=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "kendra_index": kendra_index,
            }
            if query_filter_string is not None:
                self._values["query_filter_string"] = query_filter_string
            if query_filter_string_enabled is not None:
                self._values["query_filter_string_enabled"] = query_filter_string_enabled

        @builtins.property
        def kendra_index(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the Amazon Kendra index that you want the AMAZON.KendraSearchIntent intent to search. The index must be in the same account and Region as the Amazon Lex bot.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-kendraconfiguration.html#cfn-lex-bot-kendraconfiguration-kendraindex
            '''
            result = self._values.get("kendra_index")
            assert result is not None, "Required property 'kendra_index' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def query_filter_string(self) -> typing.Optional[builtins.str]:
            '''A query filter that Amazon Lex sends to Amazon Kendra to filter the response from a query.

            The filter is in the format defined by Amazon Kendra.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-kendraconfiguration.html#cfn-lex-bot-kendraconfiguration-queryfilterstring
            '''
            result = self._values.get("query_filter_string")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def query_filter_string_enabled(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Determines whether the AMAZON.KendraSearchIntent intent uses a custom query string to query the Amazon Kendra index.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-kendraconfiguration.html#cfn-lex-bot-kendraconfiguration-queryfilterstringenabled
            '''
            result = self._values.get("query_filter_string_enabled")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "KendraConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBot.MessageGroupProperty",
        jsii_struct_bases=[],
        name_mapping={"message": "message", "variations": "variations"},
    )
    class MessageGroupProperty:
        def __init__(
            self,
            *,
            message: typing.Union["CfnBot.MessageProperty", _IResolvable_da3f097b],
            variations: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBot.MessageProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''Provides one or more messages that Amazon Lex should send to the user.

            :param message: The primary message that Amazon Lex should send to the user.
            :param variations: Message variations to send to the user. When variations are defined, Amazon Lex chooses the primary message or one of the variations to send to the user.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-messagegroup.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                message_group_property = lex.CfnBot.MessageGroupProperty(
                    message=lex.CfnBot.MessageProperty(
                        custom_payload=lex.CfnBot.CustomPayloadProperty(
                            value="value"
                        ),
                        image_response_card=lex.CfnBot.ImageResponseCardProperty(
                            title="title",
                
                            # the properties below are optional
                            buttons=[lex.CfnBot.ButtonProperty(
                                text="text",
                                value="value"
                            )],
                            image_url="imageUrl",
                            subtitle="subtitle"
                        ),
                        plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                            value="value"
                        ),
                        ssml_message=lex.CfnBot.SSMLMessageProperty(
                            value="value"
                        )
                    ),
                
                    # the properties below are optional
                    variations=[lex.CfnBot.MessageProperty(
                        custom_payload=lex.CfnBot.CustomPayloadProperty(
                            value="value"
                        ),
                        image_response_card=lex.CfnBot.ImageResponseCardProperty(
                            title="title",
                
                            # the properties below are optional
                            buttons=[lex.CfnBot.ButtonProperty(
                                text="text",
                                value="value"
                            )],
                            image_url="imageUrl",
                            subtitle="subtitle"
                        ),
                        plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                            value="value"
                        ),
                        ssml_message=lex.CfnBot.SSMLMessageProperty(
                            value="value"
                        )
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "message": message,
            }
            if variations is not None:
                self._values["variations"] = variations

        @builtins.property
        def message(
            self,
        ) -> typing.Union["CfnBot.MessageProperty", _IResolvable_da3f097b]:
            '''The primary message that Amazon Lex should send to the user.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-messagegroup.html#cfn-lex-bot-messagegroup-message
            '''
            result = self._values.get("message")
            assert result is not None, "Required property 'message' is missing"
            return typing.cast(typing.Union["CfnBot.MessageProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def variations(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBot.MessageProperty", _IResolvable_da3f097b]]]]:
            '''Message variations to send to the user.

            When variations are defined, Amazon Lex chooses the primary message or one of the variations to send to the user.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-messagegroup.html#cfn-lex-bot-messagegroup-variations
            '''
            result = self._values.get("variations")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBot.MessageProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "MessageGroupProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBot.MessageProperty",
        jsii_struct_bases=[],
        name_mapping={
            "custom_payload": "customPayload",
            "image_response_card": "imageResponseCard",
            "plain_text_message": "plainTextMessage",
            "ssml_message": "ssmlMessage",
        },
    )
    class MessageProperty:
        def __init__(
            self,
            *,
            custom_payload: typing.Optional[typing.Union["CfnBot.CustomPayloadProperty", _IResolvable_da3f097b]] = None,
            image_response_card: typing.Optional[typing.Union["CfnBot.ImageResponseCardProperty", _IResolvable_da3f097b]] = None,
            plain_text_message: typing.Optional[typing.Union["CfnBot.PlainTextMessageProperty", _IResolvable_da3f097b]] = None,
            ssml_message: typing.Optional[typing.Union["CfnBot.SSMLMessageProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The object that provides message text and it's type.

            :param custom_payload: A message in a custom format defined by the client application.
            :param image_response_card: A message that defines a response card that the client application can show to the user.
            :param plain_text_message: A message in plain text format.
            :param ssml_message: A message in Speech Synthesis Markup Language (SSML) format.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-message.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                message_property = lex.CfnBot.MessageProperty(
                    custom_payload=lex.CfnBot.CustomPayloadProperty(
                        value="value"
                    ),
                    image_response_card=lex.CfnBot.ImageResponseCardProperty(
                        title="title",
                
                        # the properties below are optional
                        buttons=[lex.CfnBot.ButtonProperty(
                            text="text",
                            value="value"
                        )],
                        image_url="imageUrl",
                        subtitle="subtitle"
                    ),
                    plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                        value="value"
                    ),
                    ssml_message=lex.CfnBot.SSMLMessageProperty(
                        value="value"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if custom_payload is not None:
                self._values["custom_payload"] = custom_payload
            if image_response_card is not None:
                self._values["image_response_card"] = image_response_card
            if plain_text_message is not None:
                self._values["plain_text_message"] = plain_text_message
            if ssml_message is not None:
                self._values["ssml_message"] = ssml_message

        @builtins.property
        def custom_payload(
            self,
        ) -> typing.Optional[typing.Union["CfnBot.CustomPayloadProperty", _IResolvable_da3f097b]]:
            '''A message in a custom format defined by the client application.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-message.html#cfn-lex-bot-message-custompayload
            '''
            result = self._values.get("custom_payload")
            return typing.cast(typing.Optional[typing.Union["CfnBot.CustomPayloadProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def image_response_card(
            self,
        ) -> typing.Optional[typing.Union["CfnBot.ImageResponseCardProperty", _IResolvable_da3f097b]]:
            '''A message that defines a response card that the client application can show to the user.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-message.html#cfn-lex-bot-message-imageresponsecard
            '''
            result = self._values.get("image_response_card")
            return typing.cast(typing.Optional[typing.Union["CfnBot.ImageResponseCardProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def plain_text_message(
            self,
        ) -> typing.Optional[typing.Union["CfnBot.PlainTextMessageProperty", _IResolvable_da3f097b]]:
            '''A message in plain text format.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-message.html#cfn-lex-bot-message-plaintextmessage
            '''
            result = self._values.get("plain_text_message")
            return typing.cast(typing.Optional[typing.Union["CfnBot.PlainTextMessageProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def ssml_message(
            self,
        ) -> typing.Optional[typing.Union["CfnBot.SSMLMessageProperty", _IResolvable_da3f097b]]:
            '''A message in Speech Synthesis Markup Language (SSML) format.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-message.html#cfn-lex-bot-message-ssmlmessage
            '''
            result = self._values.get("ssml_message")
            return typing.cast(typing.Optional[typing.Union["CfnBot.SSMLMessageProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "MessageProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBot.MultipleValuesSettingProperty",
        jsii_struct_bases=[],
        name_mapping={"allow_multiple_values": "allowMultipleValues"},
    )
    class MultipleValuesSettingProperty:
        def __init__(
            self,
            *,
            allow_multiple_values: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Indicates whether a slot can return multiple values.

            :param allow_multiple_values: Indicates whether a slot can return multiple values. When true, the slot may return more than one value in a response. When false, the slot returns only a single value. If AllowMultipleValues is not set, the default value is false. Multi-value slots are only available in the en-US locale.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-multiplevaluessetting.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                multiple_values_setting_property = lex.CfnBot.MultipleValuesSettingProperty(
                    allow_multiple_values=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if allow_multiple_values is not None:
                self._values["allow_multiple_values"] = allow_multiple_values

        @builtins.property
        def allow_multiple_values(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Indicates whether a slot can return multiple values.

            When true, the slot may return more than one value in a response. When false, the slot returns only a single value. If AllowMultipleValues is not set, the default value is false.

            Multi-value slots are only available in the en-US locale.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-multiplevaluessetting.html#cfn-lex-bot-multiplevaluessetting-allowmultiplevalues
            '''
            result = self._values.get("allow_multiple_values")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "MultipleValuesSettingProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBot.ObfuscationSettingProperty",
        jsii_struct_bases=[],
        name_mapping={"obfuscation_setting_type": "obfuscationSettingType"},
    )
    class ObfuscationSettingProperty:
        def __init__(self, *, obfuscation_setting_type: builtins.str) -> None:
            '''Determines whether Amazon Lex obscures slot values in conversation logs.

            :param obfuscation_setting_type: Value that determines whether Amazon Lex obscures slot values in conversation logs. The default is to obscure the values.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-obfuscationsetting.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                obfuscation_setting_property = lex.CfnBot.ObfuscationSettingProperty(
                    obfuscation_setting_type="obfuscationSettingType"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "obfuscation_setting_type": obfuscation_setting_type,
            }

        @builtins.property
        def obfuscation_setting_type(self) -> builtins.str:
            '''Value that determines whether Amazon Lex obscures slot values in conversation logs.

            The default is to obscure the values.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-obfuscationsetting.html#cfn-lex-bot-obfuscationsetting-obfuscationsettingtype
            '''
            result = self._values.get("obfuscation_setting_type")
            assert result is not None, "Required property 'obfuscation_setting_type' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ObfuscationSettingProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBot.OutputContextProperty",
        jsii_struct_bases=[],
        name_mapping={
            "name": "name",
            "time_to_live_in_seconds": "timeToLiveInSeconds",
            "turns_to_live": "turnsToLive",
        },
    )
    class OutputContextProperty:
        def __init__(
            self,
            *,
            name: builtins.str,
            time_to_live_in_seconds: jsii.Number,
            turns_to_live: jsii.Number,
        ) -> None:
            '''Describes a session context that is activated when an intent is fulfilled.

            :param name: The name of the output context.
            :param time_to_live_in_seconds: The amount of time, in seconds, that the output context should remain active. The time is figured from the first time the context is sent to the user.
            :param turns_to_live: The number of conversation turns that the output context should remain active. The number of turns is counted from the first time that the context is sent to the user.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-outputcontext.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                output_context_property = lex.CfnBot.OutputContextProperty(
                    name="name",
                    time_to_live_in_seconds=123,
                    turns_to_live=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "name": name,
                "time_to_live_in_seconds": time_to_live_in_seconds,
                "turns_to_live": turns_to_live,
            }

        @builtins.property
        def name(self) -> builtins.str:
            '''The name of the output context.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-outputcontext.html#cfn-lex-bot-outputcontext-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def time_to_live_in_seconds(self) -> jsii.Number:
            '''The amount of time, in seconds, that the output context should remain active.

            The time is figured from the first time the context is sent to the user.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-outputcontext.html#cfn-lex-bot-outputcontext-timetoliveinseconds
            '''
            result = self._values.get("time_to_live_in_seconds")
            assert result is not None, "Required property 'time_to_live_in_seconds' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def turns_to_live(self) -> jsii.Number:
            '''The number of conversation turns that the output context should remain active.

            The number of turns is counted from the first time that the context is sent to the user.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-outputcontext.html#cfn-lex-bot-outputcontext-turnstolive
            '''
            result = self._values.get("turns_to_live")
            assert result is not None, "Required property 'turns_to_live' is missing"
            return typing.cast(jsii.Number, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "OutputContextProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBot.PlainTextMessageProperty",
        jsii_struct_bases=[],
        name_mapping={"value": "value"},
    )
    class PlainTextMessageProperty:
        def __init__(self, *, value: builtins.str) -> None:
            '''Defines an ASCII text message to send to the user.

            :param value: The message to send to the user.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-plaintextmessage.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                plain_text_message_property = lex.CfnBot.PlainTextMessageProperty(
                    value="value"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "value": value,
            }

        @builtins.property
        def value(self) -> builtins.str:
            '''The message to send to the user.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-plaintextmessage.html#cfn-lex-bot-plaintextmessage-value
            '''
            result = self._values.get("value")
            assert result is not None, "Required property 'value' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PlainTextMessageProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBot.PostFulfillmentStatusSpecificationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "failure_response": "failureResponse",
            "success_response": "successResponse",
            "timeout_response": "timeoutResponse",
        },
    )
    class PostFulfillmentStatusSpecificationProperty:
        def __init__(
            self,
            *,
            failure_response: typing.Optional[typing.Union["CfnBot.ResponseSpecificationProperty", _IResolvable_da3f097b]] = None,
            success_response: typing.Optional[typing.Union["CfnBot.ResponseSpecificationProperty", _IResolvable_da3f097b]] = None,
            timeout_response: typing.Optional[typing.Union["CfnBot.ResponseSpecificationProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Provides a setting that determines whether the post-fulfillment response is sent to the user.

            For more information, see `Post-fulfillment response <https://docs.aws.amazon.com/lex/latest/dg/streaming-progress.html#progress-complete>`_ in the *Amazon Lex developer guide* .

            :param failure_response: Specifies a list of message groups that Amazon Lex uses to respond when fulfillment isn't successful.
            :param success_response: Specifies a list of message groups that Amazon Lex uses to respond when the fulfillment is successful.
            :param timeout_response: Specifies a list of message groups that Amazon Lex uses to respond when fulfillment isn't completed within the timeout period.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-postfulfillmentstatusspecification.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                post_fulfillment_status_specification_property = lex.CfnBot.PostFulfillmentStatusSpecificationProperty(
                    failure_response=lex.CfnBot.ResponseSpecificationProperty(
                        message_groups_list=[lex.CfnBot.MessageGroupProperty(
                            message=lex.CfnBot.MessageProperty(
                                custom_payload=lex.CfnBot.CustomPayloadProperty(
                                    value="value"
                                ),
                                image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                    title="title",
                
                                    # the properties below are optional
                                    buttons=[lex.CfnBot.ButtonProperty(
                                        text="text",
                                        value="value"
                                    )],
                                    image_url="imageUrl",
                                    subtitle="subtitle"
                                ),
                                plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                    value="value"
                                ),
                                ssml_message=lex.CfnBot.SSMLMessageProperty(
                                    value="value"
                                )
                            ),
                
                            # the properties below are optional
                            variations=[lex.CfnBot.MessageProperty(
                                custom_payload=lex.CfnBot.CustomPayloadProperty(
                                    value="value"
                                ),
                                image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                    title="title",
                
                                    # the properties below are optional
                                    buttons=[lex.CfnBot.ButtonProperty(
                                        text="text",
                                        value="value"
                                    )],
                                    image_url="imageUrl",
                                    subtitle="subtitle"
                                ),
                                plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                    value="value"
                                ),
                                ssml_message=lex.CfnBot.SSMLMessageProperty(
                                    value="value"
                                )
                            )]
                        )],
                
                        # the properties below are optional
                        allow_interrupt=False
                    ),
                    success_response=lex.CfnBot.ResponseSpecificationProperty(
                        message_groups_list=[lex.CfnBot.MessageGroupProperty(
                            message=lex.CfnBot.MessageProperty(
                                custom_payload=lex.CfnBot.CustomPayloadProperty(
                                    value="value"
                                ),
                                image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                    title="title",
                
                                    # the properties below are optional
                                    buttons=[lex.CfnBot.ButtonProperty(
                                        text="text",
                                        value="value"
                                    )],
                                    image_url="imageUrl",
                                    subtitle="subtitle"
                                ),
                                plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                    value="value"
                                ),
                                ssml_message=lex.CfnBot.SSMLMessageProperty(
                                    value="value"
                                )
                            ),
                
                            # the properties below are optional
                            variations=[lex.CfnBot.MessageProperty(
                                custom_payload=lex.CfnBot.CustomPayloadProperty(
                                    value="value"
                                ),
                                image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                    title="title",
                
                                    # the properties below are optional
                                    buttons=[lex.CfnBot.ButtonProperty(
                                        text="text",
                                        value="value"
                                    )],
                                    image_url="imageUrl",
                                    subtitle="subtitle"
                                ),
                                plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                    value="value"
                                ),
                                ssml_message=lex.CfnBot.SSMLMessageProperty(
                                    value="value"
                                )
                            )]
                        )],
                
                        # the properties below are optional
                        allow_interrupt=False
                    ),
                    timeout_response=lex.CfnBot.ResponseSpecificationProperty(
                        message_groups_list=[lex.CfnBot.MessageGroupProperty(
                            message=lex.CfnBot.MessageProperty(
                                custom_payload=lex.CfnBot.CustomPayloadProperty(
                                    value="value"
                                ),
                                image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                    title="title",
                
                                    # the properties below are optional
                                    buttons=[lex.CfnBot.ButtonProperty(
                                        text="text",
                                        value="value"
                                    )],
                                    image_url="imageUrl",
                                    subtitle="subtitle"
                                ),
                                plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                    value="value"
                                ),
                                ssml_message=lex.CfnBot.SSMLMessageProperty(
                                    value="value"
                                )
                            ),
                
                            # the properties below are optional
                            variations=[lex.CfnBot.MessageProperty(
                                custom_payload=lex.CfnBot.CustomPayloadProperty(
                                    value="value"
                                ),
                                image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                    title="title",
                
                                    # the properties below are optional
                                    buttons=[lex.CfnBot.ButtonProperty(
                                        text="text",
                                        value="value"
                                    )],
                                    image_url="imageUrl",
                                    subtitle="subtitle"
                                ),
                                plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                    value="value"
                                ),
                                ssml_message=lex.CfnBot.SSMLMessageProperty(
                                    value="value"
                                )
                            )]
                        )],
                
                        # the properties below are optional
                        allow_interrupt=False
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if failure_response is not None:
                self._values["failure_response"] = failure_response
            if success_response is not None:
                self._values["success_response"] = success_response
            if timeout_response is not None:
                self._values["timeout_response"] = timeout_response

        @builtins.property
        def failure_response(
            self,
        ) -> typing.Optional[typing.Union["CfnBot.ResponseSpecificationProperty", _IResolvable_da3f097b]]:
            '''Specifies a list of message groups that Amazon Lex uses to respond when fulfillment isn't successful.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-postfulfillmentstatusspecification.html#cfn-lex-bot-postfulfillmentstatusspecification-failureresponse
            '''
            result = self._values.get("failure_response")
            return typing.cast(typing.Optional[typing.Union["CfnBot.ResponseSpecificationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def success_response(
            self,
        ) -> typing.Optional[typing.Union["CfnBot.ResponseSpecificationProperty", _IResolvable_da3f097b]]:
            '''Specifies a list of message groups that Amazon Lex uses to respond when the fulfillment is successful.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-postfulfillmentstatusspecification.html#cfn-lex-bot-postfulfillmentstatusspecification-successresponse
            '''
            result = self._values.get("success_response")
            return typing.cast(typing.Optional[typing.Union["CfnBot.ResponseSpecificationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def timeout_response(
            self,
        ) -> typing.Optional[typing.Union["CfnBot.ResponseSpecificationProperty", _IResolvable_da3f097b]]:
            '''Specifies a list of message groups that Amazon Lex uses to respond when fulfillment isn't completed within the timeout period.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-postfulfillmentstatusspecification.html#cfn-lex-bot-postfulfillmentstatusspecification-timeoutresponse
            '''
            result = self._values.get("timeout_response")
            return typing.cast(typing.Optional[typing.Union["CfnBot.ResponseSpecificationProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PostFulfillmentStatusSpecificationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBot.PromptSpecificationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "max_retries": "maxRetries",
            "message_groups_list": "messageGroupsList",
            "allow_interrupt": "allowInterrupt",
        },
    )
    class PromptSpecificationProperty:
        def __init__(
            self,
            *,
            max_retries: jsii.Number,
            message_groups_list: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBot.MessageGroupProperty", _IResolvable_da3f097b]]],
            allow_interrupt: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Specifies a list of message groups that Amazon Lex sends to a user to elicit a response.

            :param max_retries: The maximum number of times the bot tries to elicit a response from the user using this prompt.
            :param message_groups_list: A collection of responses that Amazon Lex can send to the user. Amazon Lex chooses the actual response to send at runtime.
            :param allow_interrupt: Indicates whether the user can interrupt a speech prompt from the bot.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-promptspecification.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                prompt_specification_property = lex.CfnBot.PromptSpecificationProperty(
                    max_retries=123,
                    message_groups_list=[lex.CfnBot.MessageGroupProperty(
                        message=lex.CfnBot.MessageProperty(
                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                value="value"
                            ),
                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                title="title",
                
                                # the properties below are optional
                                buttons=[lex.CfnBot.ButtonProperty(
                                    text="text",
                                    value="value"
                                )],
                                image_url="imageUrl",
                                subtitle="subtitle"
                            ),
                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                value="value"
                            ),
                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                value="value"
                            )
                        ),
                
                        # the properties below are optional
                        variations=[lex.CfnBot.MessageProperty(
                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                value="value"
                            ),
                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                title="title",
                
                                # the properties below are optional
                                buttons=[lex.CfnBot.ButtonProperty(
                                    text="text",
                                    value="value"
                                )],
                                image_url="imageUrl",
                                subtitle="subtitle"
                            ),
                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                value="value"
                            ),
                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                value="value"
                            )
                        )]
                    )],
                
                    # the properties below are optional
                    allow_interrupt=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "max_retries": max_retries,
                "message_groups_list": message_groups_list,
            }
            if allow_interrupt is not None:
                self._values["allow_interrupt"] = allow_interrupt

        @builtins.property
        def max_retries(self) -> jsii.Number:
            '''The maximum number of times the bot tries to elicit a response from the user using this prompt.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-promptspecification.html#cfn-lex-bot-promptspecification-maxretries
            '''
            result = self._values.get("max_retries")
            assert result is not None, "Required property 'max_retries' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def message_groups_list(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBot.MessageGroupProperty", _IResolvable_da3f097b]]]:
            '''A collection of responses that Amazon Lex can send to the user.

            Amazon Lex chooses the actual response to send at runtime.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-promptspecification.html#cfn-lex-bot-promptspecification-messagegroupslist
            '''
            result = self._values.get("message_groups_list")
            assert result is not None, "Required property 'message_groups_list' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBot.MessageGroupProperty", _IResolvable_da3f097b]]], result)

        @builtins.property
        def allow_interrupt(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Indicates whether the user can interrupt a speech prompt from the bot.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-promptspecification.html#cfn-lex-bot-promptspecification-allowinterrupt
            '''
            result = self._values.get("allow_interrupt")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PromptSpecificationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBot.ResponseSpecificationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "message_groups_list": "messageGroupsList",
            "allow_interrupt": "allowInterrupt",
        },
    )
    class ResponseSpecificationProperty:
        def __init__(
            self,
            *,
            message_groups_list: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBot.MessageGroupProperty", _IResolvable_da3f097b]]],
            allow_interrupt: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Specifies a list of message groups that Amazon Lex uses to respond to user input.

            :param message_groups_list: A collection of responses that Amazon Lex can send to the user. Amazon Lex chooses the actual response to send at runtime.
            :param allow_interrupt: Indicates whether the user can interrupt a speech response from Amazon Lex .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-responsespecification.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                response_specification_property = lex.CfnBot.ResponseSpecificationProperty(
                    message_groups_list=[lex.CfnBot.MessageGroupProperty(
                        message=lex.CfnBot.MessageProperty(
                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                value="value"
                            ),
                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                title="title",
                
                                # the properties below are optional
                                buttons=[lex.CfnBot.ButtonProperty(
                                    text="text",
                                    value="value"
                                )],
                                image_url="imageUrl",
                                subtitle="subtitle"
                            ),
                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                value="value"
                            ),
                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                value="value"
                            )
                        ),
                
                        # the properties below are optional
                        variations=[lex.CfnBot.MessageProperty(
                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                value="value"
                            ),
                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                title="title",
                
                                # the properties below are optional
                                buttons=[lex.CfnBot.ButtonProperty(
                                    text="text",
                                    value="value"
                                )],
                                image_url="imageUrl",
                                subtitle="subtitle"
                            ),
                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                value="value"
                            ),
                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                value="value"
                            )
                        )]
                    )],
                
                    # the properties below are optional
                    allow_interrupt=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "message_groups_list": message_groups_list,
            }
            if allow_interrupt is not None:
                self._values["allow_interrupt"] = allow_interrupt

        @builtins.property
        def message_groups_list(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBot.MessageGroupProperty", _IResolvable_da3f097b]]]:
            '''A collection of responses that Amazon Lex can send to the user.

            Amazon Lex chooses the actual response to send at runtime.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-responsespecification.html#cfn-lex-bot-responsespecification-messagegroupslist
            '''
            result = self._values.get("message_groups_list")
            assert result is not None, "Required property 'message_groups_list' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBot.MessageGroupProperty", _IResolvable_da3f097b]]], result)

        @builtins.property
        def allow_interrupt(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Indicates whether the user can interrupt a speech response from Amazon Lex .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-responsespecification.html#cfn-lex-bot-responsespecification-allowinterrupt
            '''
            result = self._values.get("allow_interrupt")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ResponseSpecificationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBot.S3LocationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "s3_bucket": "s3Bucket",
            "s3_object_key": "s3ObjectKey",
            "s3_object_version": "s3ObjectVersion",
        },
    )
    class S3LocationProperty:
        def __init__(
            self,
            *,
            s3_bucket: builtins.str,
            s3_object_key: builtins.str,
            s3_object_version: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Defines an Amazon S3 bucket location.

            :param s3_bucket: The S3 bucket name.
            :param s3_object_key: The path and file name to the object in the S3 bucket.
            :param s3_object_version: The version of the object in the S3 bucket.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-s3location.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                s3_location_property = lex.CfnBot.S3LocationProperty(
                    s3_bucket="s3Bucket",
                    s3_object_key="s3ObjectKey",
                
                    # the properties below are optional
                    s3_object_version="s3ObjectVersion"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "s3_bucket": s3_bucket,
                "s3_object_key": s3_object_key,
            }
            if s3_object_version is not None:
                self._values["s3_object_version"] = s3_object_version

        @builtins.property
        def s3_bucket(self) -> builtins.str:
            '''The S3 bucket name.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-s3location.html#cfn-lex-bot-s3location-s3bucket
            '''
            result = self._values.get("s3_bucket")
            assert result is not None, "Required property 's3_bucket' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def s3_object_key(self) -> builtins.str:
            '''The path and file name to the object in the S3 bucket.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-s3location.html#cfn-lex-bot-s3location-s3objectkey
            '''
            result = self._values.get("s3_object_key")
            assert result is not None, "Required property 's3_object_key' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def s3_object_version(self) -> typing.Optional[builtins.str]:
            '''The version of the object in the S3 bucket.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-s3location.html#cfn-lex-bot-s3location-s3objectversion
            '''
            result = self._values.get("s3_object_version")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "S3LocationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBot.SSMLMessageProperty",
        jsii_struct_bases=[],
        name_mapping={"value": "value"},
    )
    class SSMLMessageProperty:
        def __init__(self, *, value: builtins.str) -> None:
            '''Defines a Speech Synthesis Markup Language (SSML) prompt.

            :param value: The SSML text that defines the prompt.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-ssmlmessage.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                s_sMLMessage_property = lex.CfnBot.SSMLMessageProperty(
                    value="value"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "value": value,
            }

        @builtins.property
        def value(self) -> builtins.str:
            '''The SSML text that defines the prompt.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-ssmlmessage.html#cfn-lex-bot-ssmlmessage-value
            '''
            result = self._values.get("value")
            assert result is not None, "Required property 'value' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SSMLMessageProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBot.SampleUtteranceProperty",
        jsii_struct_bases=[],
        name_mapping={"utterance": "utterance"},
    )
    class SampleUtteranceProperty:
        def __init__(self, *, utterance: builtins.str) -> None:
            '''A sample utterance that invokes and intent or responds to a slot elicitation prompt.

            :param utterance: The sample utterance that Amazon Lex uses to build its machine-learning model to recognize intents.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-sampleutterance.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                sample_utterance_property = lex.CfnBot.SampleUtteranceProperty(
                    utterance="utterance"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "utterance": utterance,
            }

        @builtins.property
        def utterance(self) -> builtins.str:
            '''The sample utterance that Amazon Lex uses to build its machine-learning model to recognize intents.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-sampleutterance.html#cfn-lex-bot-sampleutterance-utterance
            '''
            result = self._values.get("utterance")
            assert result is not None, "Required property 'utterance' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SampleUtteranceProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBot.SampleValueProperty",
        jsii_struct_bases=[],
        name_mapping={"value": "value"},
    )
    class SampleValueProperty:
        def __init__(self, *, value: builtins.str) -> None:
            '''Defines one of the values for a slot type.

            :param value: The value that can be used for a slot type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-samplevalue.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                sample_value_property = lex.CfnBot.SampleValueProperty(
                    value="value"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "value": value,
            }

        @builtins.property
        def value(self) -> builtins.str:
            '''The value that can be used for a slot type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-samplevalue.html#cfn-lex-bot-samplevalue-value
            '''
            result = self._values.get("value")
            assert result is not None, "Required property 'value' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SampleValueProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBot.SlotDefaultValueProperty",
        jsii_struct_bases=[],
        name_mapping={"default_value": "defaultValue"},
    )
    class SlotDefaultValueProperty:
        def __init__(self, *, default_value: builtins.str) -> None:
            '''Specifies the default value to use when a user doesn't provide a value for a slot.

            :param default_value: The default value to use when a user doesn't provide a value for a slot.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-slotdefaultvalue.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                slot_default_value_property = lex.CfnBot.SlotDefaultValueProperty(
                    default_value="defaultValue"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "default_value": default_value,
            }

        @builtins.property
        def default_value(self) -> builtins.str:
            '''The default value to use when a user doesn't provide a value for a slot.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-slotdefaultvalue.html#cfn-lex-bot-slotdefaultvalue-defaultvalue
            '''
            result = self._values.get("default_value")
            assert result is not None, "Required property 'default_value' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SlotDefaultValueProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBot.SlotDefaultValueSpecificationProperty",
        jsii_struct_bases=[],
        name_mapping={"default_value_list": "defaultValueList"},
    )
    class SlotDefaultValueSpecificationProperty:
        def __init__(
            self,
            *,
            default_value_list: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBot.SlotDefaultValueProperty", _IResolvable_da3f097b]]],
        ) -> None:
            '''Defines a list of values that Amazon Lex should use as the default value for a slot.

            :param default_value_list: A list of default values. Amazon Lex chooses the default value to use in the order that they are presented in the list.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-slotdefaultvaluespecification.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                slot_default_value_specification_property = lex.CfnBot.SlotDefaultValueSpecificationProperty(
                    default_value_list=[lex.CfnBot.SlotDefaultValueProperty(
                        default_value="defaultValue"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "default_value_list": default_value_list,
            }

        @builtins.property
        def default_value_list(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBot.SlotDefaultValueProperty", _IResolvable_da3f097b]]]:
            '''A list of default values.

            Amazon Lex chooses the default value to use in the order that they are presented in the list.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-slotdefaultvaluespecification.html#cfn-lex-bot-slotdefaultvaluespecification-defaultvaluelist
            '''
            result = self._values.get("default_value_list")
            assert result is not None, "Required property 'default_value_list' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBot.SlotDefaultValueProperty", _IResolvable_da3f097b]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SlotDefaultValueSpecificationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBot.SlotPriorityProperty",
        jsii_struct_bases=[],
        name_mapping={"priority": "priority", "slot_name": "slotName"},
    )
    class SlotPriorityProperty:
        def __init__(self, *, priority: jsii.Number, slot_name: builtins.str) -> None:
            '''Sets the priority that Amazon Lex should use when eliciting slots values from a user.

            :param priority: The priority that Amazon Lex should apply to the slot.
            :param slot_name: The name of the slot.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-slotpriority.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                slot_priority_property = lex.CfnBot.SlotPriorityProperty(
                    priority=123,
                    slot_name="slotName"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "priority": priority,
                "slot_name": slot_name,
            }

        @builtins.property
        def priority(self) -> jsii.Number:
            '''The priority that Amazon Lex should apply to the slot.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-slotpriority.html#cfn-lex-bot-slotpriority-priority
            '''
            result = self._values.get("priority")
            assert result is not None, "Required property 'priority' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def slot_name(self) -> builtins.str:
            '''The name of the slot.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-slotpriority.html#cfn-lex-bot-slotpriority-slotname
            '''
            result = self._values.get("slot_name")
            assert result is not None, "Required property 'slot_name' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SlotPriorityProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBot.SlotProperty",
        jsii_struct_bases=[],
        name_mapping={
            "name": "name",
            "slot_type_name": "slotTypeName",
            "value_elicitation_setting": "valueElicitationSetting",
            "description": "description",
            "multiple_values_setting": "multipleValuesSetting",
            "obfuscation_setting": "obfuscationSetting",
        },
    )
    class SlotProperty:
        def __init__(
            self,
            *,
            name: builtins.str,
            slot_type_name: builtins.str,
            value_elicitation_setting: typing.Union["CfnBot.SlotValueElicitationSettingProperty", _IResolvable_da3f097b],
            description: typing.Optional[builtins.str] = None,
            multiple_values_setting: typing.Optional[typing.Union["CfnBot.MultipleValuesSettingProperty", _IResolvable_da3f097b]] = None,
            obfuscation_setting: typing.Optional[typing.Union["CfnBot.ObfuscationSettingProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Specifies the definition of a slot.

            Amazon Lex elicits slot values from uses to fulfill the user's intent.

            :param name: The name of the slot.
            :param slot_type_name: The name of the slot type that this slot is based on. The slot type defines the acceptable values for the slot.
            :param value_elicitation_setting: Determines the slot resolution strategy that Amazon Lex uses to return slot type values. The field can be set to one of the following values: - OriginalValue - Returns the value entered by the user, if the user value is similar to a slot value. - TopResolution - If there is a resolution list for the slot, return the first value in the resolution list as the slot type value. If there is no resolution list, null is returned. If you don't specify the valueSelectionStrategy, the default is OriginalValue.
            :param description: A description of the slot type.
            :param multiple_values_setting: Determines whether the slot can return multiple values to the application.
            :param obfuscation_setting: Determines whether the contents of the slot are obfuscated in Amazon CloudWatch Logs logs. Use obfuscated slots to protect information such as personally identifiable information (PII) in logs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-slot.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                slot_property = lex.CfnBot.SlotProperty(
                    name="name",
                    slot_type_name="slotTypeName",
                    value_elicitation_setting=lex.CfnBot.SlotValueElicitationSettingProperty(
                        slot_constraint="slotConstraint",
                
                        # the properties below are optional
                        default_value_specification=lex.CfnBot.SlotDefaultValueSpecificationProperty(
                            default_value_list=[lex.CfnBot.SlotDefaultValueProperty(
                                default_value="defaultValue"
                            )]
                        ),
                        prompt_specification=lex.CfnBot.PromptSpecificationProperty(
                            max_retries=123,
                            message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                message=lex.CfnBot.MessageProperty(
                                    custom_payload=lex.CfnBot.CustomPayloadProperty(
                                        value="value"
                                    ),
                                    image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                        title="title",
                
                                        # the properties below are optional
                                        buttons=[lex.CfnBot.ButtonProperty(
                                            text="text",
                                            value="value"
                                        )],
                                        image_url="imageUrl",
                                        subtitle="subtitle"
                                    ),
                                    plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                        value="value"
                                    ),
                                    ssml_message=lex.CfnBot.SSMLMessageProperty(
                                        value="value"
                                    )
                                ),
                
                                # the properties below are optional
                                variations=[lex.CfnBot.MessageProperty(
                                    custom_payload=lex.CfnBot.CustomPayloadProperty(
                                        value="value"
                                    ),
                                    image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                        title="title",
                
                                        # the properties below are optional
                                        buttons=[lex.CfnBot.ButtonProperty(
                                            text="text",
                                            value="value"
                                        )],
                                        image_url="imageUrl",
                                        subtitle="subtitle"
                                    ),
                                    plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                        value="value"
                                    ),
                                    ssml_message=lex.CfnBot.SSMLMessageProperty(
                                        value="value"
                                    )
                                )]
                            )],
                
                            # the properties below are optional
                            allow_interrupt=False
                        ),
                        sample_utterances=[lex.CfnBot.SampleUtteranceProperty(
                            utterance="utterance"
                        )],
                        wait_and_continue_specification=lex.CfnBot.WaitAndContinueSpecificationProperty(
                            continue_response=lex.CfnBot.ResponseSpecificationProperty(
                                message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                    message=lex.CfnBot.MessageProperty(
                                        custom_payload=lex.CfnBot.CustomPayloadProperty(
                                            value="value"
                                        ),
                                        image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                            title="title",
                
                                            # the properties below are optional
                                            buttons=[lex.CfnBot.ButtonProperty(
                                                text="text",
                                                value="value"
                                            )],
                                            image_url="imageUrl",
                                            subtitle="subtitle"
                                        ),
                                        plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                            value="value"
                                        ),
                                        ssml_message=lex.CfnBot.SSMLMessageProperty(
                                            value="value"
                                        )
                                    ),
                
                                    # the properties below are optional
                                    variations=[lex.CfnBot.MessageProperty(
                                        custom_payload=lex.CfnBot.CustomPayloadProperty(
                                            value="value"
                                        ),
                                        image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                            title="title",
                
                                            # the properties below are optional
                                            buttons=[lex.CfnBot.ButtonProperty(
                                                text="text",
                                                value="value"
                                            )],
                                            image_url="imageUrl",
                                            subtitle="subtitle"
                                        ),
                                        plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                            value="value"
                                        ),
                                        ssml_message=lex.CfnBot.SSMLMessageProperty(
                                            value="value"
                                        )
                                    )]
                                )],
                
                                # the properties below are optional
                                allow_interrupt=False
                            ),
                            waiting_response=lex.CfnBot.ResponseSpecificationProperty(
                                message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                    message=lex.CfnBot.MessageProperty(
                                        custom_payload=lex.CfnBot.CustomPayloadProperty(
                                            value="value"
                                        ),
                                        image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                            title="title",
                
                                            # the properties below are optional
                                            buttons=[lex.CfnBot.ButtonProperty(
                                                text="text",
                                                value="value"
                                            )],
                                            image_url="imageUrl",
                                            subtitle="subtitle"
                                        ),
                                        plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                            value="value"
                                        ),
                                        ssml_message=lex.CfnBot.SSMLMessageProperty(
                                            value="value"
                                        )
                                    ),
                
                                    # the properties below are optional
                                    variations=[lex.CfnBot.MessageProperty(
                                        custom_payload=lex.CfnBot.CustomPayloadProperty(
                                            value="value"
                                        ),
                                        image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                            title="title",
                
                                            # the properties below are optional
                                            buttons=[lex.CfnBot.ButtonProperty(
                                                text="text",
                                                value="value"
                                            )],
                                            image_url="imageUrl",
                                            subtitle="subtitle"
                                        ),
                                        plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                            value="value"
                                        ),
                                        ssml_message=lex.CfnBot.SSMLMessageProperty(
                                            value="value"
                                        )
                                    )]
                                )],
                
                                # the properties below are optional
                                allow_interrupt=False
                            ),
                
                            # the properties below are optional
                            is_active=False,
                            still_waiting_response=lex.CfnBot.StillWaitingResponseSpecificationProperty(
                                frequency_in_seconds=123,
                                message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                    message=lex.CfnBot.MessageProperty(
                                        custom_payload=lex.CfnBot.CustomPayloadProperty(
                                            value="value"
                                        ),
                                        image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                            title="title",
                
                                            # the properties below are optional
                                            buttons=[lex.CfnBot.ButtonProperty(
                                                text="text",
                                                value="value"
                                            )],
                                            image_url="imageUrl",
                                            subtitle="subtitle"
                                        ),
                                        plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                            value="value"
                                        ),
                                        ssml_message=lex.CfnBot.SSMLMessageProperty(
                                            value="value"
                                        )
                                    ),
                
                                    # the properties below are optional
                                    variations=[lex.CfnBot.MessageProperty(
                                        custom_payload=lex.CfnBot.CustomPayloadProperty(
                                            value="value"
                                        ),
                                        image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                            title="title",
                
                                            # the properties below are optional
                                            buttons=[lex.CfnBot.ButtonProperty(
                                                text="text",
                                                value="value"
                                            )],
                                            image_url="imageUrl",
                                            subtitle="subtitle"
                                        ),
                                        plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                            value="value"
                                        ),
                                        ssml_message=lex.CfnBot.SSMLMessageProperty(
                                            value="value"
                                        )
                                    )]
                                )],
                                timeout_in_seconds=123,
                
                                # the properties below are optional
                                allow_interrupt=False
                            )
                        )
                    ),
                
                    # the properties below are optional
                    description="description",
                    multiple_values_setting=lex.CfnBot.MultipleValuesSettingProperty(
                        allow_multiple_values=False
                    ),
                    obfuscation_setting=lex.CfnBot.ObfuscationSettingProperty(
                        obfuscation_setting_type="obfuscationSettingType"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "name": name,
                "slot_type_name": slot_type_name,
                "value_elicitation_setting": value_elicitation_setting,
            }
            if description is not None:
                self._values["description"] = description
            if multiple_values_setting is not None:
                self._values["multiple_values_setting"] = multiple_values_setting
            if obfuscation_setting is not None:
                self._values["obfuscation_setting"] = obfuscation_setting

        @builtins.property
        def name(self) -> builtins.str:
            '''The name of the slot.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-slot.html#cfn-lex-bot-slot-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def slot_type_name(self) -> builtins.str:
            '''The name of the slot type that this slot is based on.

            The slot type defines the acceptable values for the slot.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-slot.html#cfn-lex-bot-slot-slottypename
            '''
            result = self._values.get("slot_type_name")
            assert result is not None, "Required property 'slot_type_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def value_elicitation_setting(
            self,
        ) -> typing.Union["CfnBot.SlotValueElicitationSettingProperty", _IResolvable_da3f097b]:
            '''Determines the slot resolution strategy that Amazon Lex uses to return slot type values.

            The field can be set to one of the following values:

            - OriginalValue - Returns the value entered by the user, if the user value is similar to a slot value.
            - TopResolution - If there is a resolution list for the slot, return the first value in the resolution list as the slot type value. If there is no resolution list, null is returned.

            If you don't specify the valueSelectionStrategy, the default is OriginalValue.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-slot.html#cfn-lex-bot-slot-valueelicitationsetting
            '''
            result = self._values.get("value_elicitation_setting")
            assert result is not None, "Required property 'value_elicitation_setting' is missing"
            return typing.cast(typing.Union["CfnBot.SlotValueElicitationSettingProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def description(self) -> typing.Optional[builtins.str]:
            '''A description of the slot type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-slot.html#cfn-lex-bot-slot-description
            '''
            result = self._values.get("description")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def multiple_values_setting(
            self,
        ) -> typing.Optional[typing.Union["CfnBot.MultipleValuesSettingProperty", _IResolvable_da3f097b]]:
            '''Determines whether the slot can return multiple values to the application.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-slot.html#cfn-lex-bot-slot-multiplevaluessetting
            '''
            result = self._values.get("multiple_values_setting")
            return typing.cast(typing.Optional[typing.Union["CfnBot.MultipleValuesSettingProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def obfuscation_setting(
            self,
        ) -> typing.Optional[typing.Union["CfnBot.ObfuscationSettingProperty", _IResolvable_da3f097b]]:
            '''Determines whether the contents of the slot are obfuscated in Amazon CloudWatch Logs logs.

            Use obfuscated slots to protect information such as personally identifiable information (PII) in logs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-slot.html#cfn-lex-bot-slot-obfuscationsetting
            '''
            result = self._values.get("obfuscation_setting")
            return typing.cast(typing.Optional[typing.Union["CfnBot.ObfuscationSettingProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SlotProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBot.SlotTypeProperty",
        jsii_struct_bases=[],
        name_mapping={
            "name": "name",
            "description": "description",
            "external_source_setting": "externalSourceSetting",
            "parent_slot_type_signature": "parentSlotTypeSignature",
            "slot_type_values": "slotTypeValues",
            "value_selection_setting": "valueSelectionSetting",
        },
    )
    class SlotTypeProperty:
        def __init__(
            self,
            *,
            name: builtins.str,
            description: typing.Optional[builtins.str] = None,
            external_source_setting: typing.Optional[typing.Union["CfnBot.ExternalSourceSettingProperty", _IResolvable_da3f097b]] = None,
            parent_slot_type_signature: typing.Optional[builtins.str] = None,
            slot_type_values: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBot.SlotTypeValueProperty", _IResolvable_da3f097b]]]] = None,
            value_selection_setting: typing.Optional[typing.Union["CfnBot.SlotValueSelectionSettingProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Describes a slot type.

            :param name: The name of the slot type. A slot type name must be unique withing the account.
            :param description: A description of the slot type. Use the description to help identify the slot type in lists.
            :param external_source_setting: Sets the type of external information used to create the slot type.
            :param parent_slot_type_signature: The built-in slot type used as a parent of this slot type. When you define a parent slot type, the new slot type has the configuration of the parent lot type. Only AMAZON.AlphaNumeric is supported.
            :param slot_type_values: A list of SlotTypeValue objects that defines the values that the slot type can take. Each value can have a list of synonyms, additional values that help train the machine learning model about the values that it resolves for the slot.
            :param value_selection_setting: Determines the slot resolution strategy that Amazon Lex uses to return slot type values. The field can be set to one of the following values: - OriginalValue - Returns the value entered by the user, if the user value is similar to a slot value. - TopResolution - If there is a resolution list for the slot, return the first value in the resolution list as the slot type value. If there is no resolution list, null is returned. If you don't specify the valueSelectionStrategy, the default is OriginalValue.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-slottype.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                slot_type_property = lex.CfnBot.SlotTypeProperty(
                    name="name",
                
                    # the properties below are optional
                    description="description",
                    external_source_setting=lex.CfnBot.ExternalSourceSettingProperty(
                        grammar_slot_type_setting=lex.CfnBot.GrammarSlotTypeSettingProperty(
                            source=lex.CfnBot.GrammarSlotTypeSourceProperty(
                                s3_bucket_name="s3BucketName",
                                s3_object_key="s3ObjectKey",
                
                                # the properties below are optional
                                kms_key_arn="kmsKeyArn"
                            )
                        )
                    ),
                    parent_slot_type_signature="parentSlotTypeSignature",
                    slot_type_values=[lex.CfnBot.SlotTypeValueProperty(
                        sample_value=lex.CfnBot.SampleValueProperty(
                            value="value"
                        ),
                
                        # the properties below are optional
                        synonyms=[lex.CfnBot.SampleValueProperty(
                            value="value"
                        )]
                    )],
                    value_selection_setting=lex.CfnBot.SlotValueSelectionSettingProperty(
                        resolution_strategy="resolutionStrategy",
                
                        # the properties below are optional
                        regex_filter=lex.CfnBot.SlotValueRegexFilterProperty(
                            pattern="pattern"
                        )
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "name": name,
            }
            if description is not None:
                self._values["description"] = description
            if external_source_setting is not None:
                self._values["external_source_setting"] = external_source_setting
            if parent_slot_type_signature is not None:
                self._values["parent_slot_type_signature"] = parent_slot_type_signature
            if slot_type_values is not None:
                self._values["slot_type_values"] = slot_type_values
            if value_selection_setting is not None:
                self._values["value_selection_setting"] = value_selection_setting

        @builtins.property
        def name(self) -> builtins.str:
            '''The name of the slot type.

            A slot type name must be unique withing the account.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-slottype.html#cfn-lex-bot-slottype-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def description(self) -> typing.Optional[builtins.str]:
            '''A description of the slot type.

            Use the description to help identify the slot type in lists.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-slottype.html#cfn-lex-bot-slottype-description
            '''
            result = self._values.get("description")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def external_source_setting(
            self,
        ) -> typing.Optional[typing.Union["CfnBot.ExternalSourceSettingProperty", _IResolvable_da3f097b]]:
            '''Sets the type of external information used to create the slot type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-slottype.html#cfn-lex-bot-slottype-externalsourcesetting
            '''
            result = self._values.get("external_source_setting")
            return typing.cast(typing.Optional[typing.Union["CfnBot.ExternalSourceSettingProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def parent_slot_type_signature(self) -> typing.Optional[builtins.str]:
            '''The built-in slot type used as a parent of this slot type.

            When you define a parent slot type, the new slot type has the configuration of the parent lot type.

            Only AMAZON.AlphaNumeric is supported.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-slottype.html#cfn-lex-bot-slottype-parentslottypesignature
            '''
            result = self._values.get("parent_slot_type_signature")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def slot_type_values(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBot.SlotTypeValueProperty", _IResolvable_da3f097b]]]]:
            '''A list of SlotTypeValue objects that defines the values that the slot type can take.

            Each value can have a list of synonyms, additional values that help train the machine learning model about the values that it resolves for the slot.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-slottype.html#cfn-lex-bot-slottype-slottypevalues
            '''
            result = self._values.get("slot_type_values")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBot.SlotTypeValueProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def value_selection_setting(
            self,
        ) -> typing.Optional[typing.Union["CfnBot.SlotValueSelectionSettingProperty", _IResolvable_da3f097b]]:
            '''Determines the slot resolution strategy that Amazon Lex uses to return slot type values.

            The field can be set to one of the following values:

            - OriginalValue - Returns the value entered by the user, if the user value is similar to a slot value.
            - TopResolution - If there is a resolution list for the slot, return the first value in the resolution list as the slot type value. If there is no resolution list, null is returned.

            If you don't specify the valueSelectionStrategy, the default is OriginalValue.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-slottype.html#cfn-lex-bot-slottype-valueselectionsetting
            '''
            result = self._values.get("value_selection_setting")
            return typing.cast(typing.Optional[typing.Union["CfnBot.SlotValueSelectionSettingProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SlotTypeProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBot.SlotTypeValueProperty",
        jsii_struct_bases=[],
        name_mapping={"sample_value": "sampleValue", "synonyms": "synonyms"},
    )
    class SlotTypeValueProperty:
        def __init__(
            self,
            *,
            sample_value: typing.Union["CfnBot.SampleValueProperty", _IResolvable_da3f097b],
            synonyms: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBot.SampleValueProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''Each slot type can have a set of values.

            The ``SlotTypeValue`` represents a value that the slot type can take.

            :param sample_value: The value of the slot type entry.
            :param synonyms: Additional values related to the slot type entry.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-slottypevalue.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                slot_type_value_property = lex.CfnBot.SlotTypeValueProperty(
                    sample_value=lex.CfnBot.SampleValueProperty(
                        value="value"
                    ),
                
                    # the properties below are optional
                    synonyms=[lex.CfnBot.SampleValueProperty(
                        value="value"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "sample_value": sample_value,
            }
            if synonyms is not None:
                self._values["synonyms"] = synonyms

        @builtins.property
        def sample_value(
            self,
        ) -> typing.Union["CfnBot.SampleValueProperty", _IResolvable_da3f097b]:
            '''The value of the slot type entry.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-slottypevalue.html#cfn-lex-bot-slottypevalue-samplevalue
            '''
            result = self._values.get("sample_value")
            assert result is not None, "Required property 'sample_value' is missing"
            return typing.cast(typing.Union["CfnBot.SampleValueProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def synonyms(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBot.SampleValueProperty", _IResolvable_da3f097b]]]]:
            '''Additional values related to the slot type entry.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-slottypevalue.html#cfn-lex-bot-slottypevalue-synonyms
            '''
            result = self._values.get("synonyms")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBot.SampleValueProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SlotTypeValueProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBot.SlotValueElicitationSettingProperty",
        jsii_struct_bases=[],
        name_mapping={
            "slot_constraint": "slotConstraint",
            "default_value_specification": "defaultValueSpecification",
            "prompt_specification": "promptSpecification",
            "sample_utterances": "sampleUtterances",
            "wait_and_continue_specification": "waitAndContinueSpecification",
        },
    )
    class SlotValueElicitationSettingProperty:
        def __init__(
            self,
            *,
            slot_constraint: builtins.str,
            default_value_specification: typing.Optional[typing.Union["CfnBot.SlotDefaultValueSpecificationProperty", _IResolvable_da3f097b]] = None,
            prompt_specification: typing.Optional[typing.Union["CfnBot.PromptSpecificationProperty", _IResolvable_da3f097b]] = None,
            sample_utterances: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBot.SampleUtteranceProperty", _IResolvable_da3f097b]]]] = None,
            wait_and_continue_specification: typing.Optional[typing.Union["CfnBot.WaitAndContinueSpecificationProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Settings that you can use for eliciting a slot value.

            :param slot_constraint: Specifies whether the slot is required or optional.
            :param default_value_specification: A list of default values for a slot. Default values are used when Amazon Lex hasn't determined a value for a slot. You can specify default values from context variables, session attributes, and defined values.
            :param prompt_specification: The prompt that Amazon Lex uses to elicit the slot value from the user.
            :param sample_utterances: If you know a specific pattern that users might respond to an Amazon Lex request for a slot value, you can provide those utterances to improve accuracy. This is optional. In most cases Amazon Lex is capable of understanding user utterances.
            :param wait_and_continue_specification: Specifies the prompts that Amazon Lex uses while a bot is waiting for customer input.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-slotvalueelicitationsetting.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                slot_value_elicitation_setting_property = lex.CfnBot.SlotValueElicitationSettingProperty(
                    slot_constraint="slotConstraint",
                
                    # the properties below are optional
                    default_value_specification=lex.CfnBot.SlotDefaultValueSpecificationProperty(
                        default_value_list=[lex.CfnBot.SlotDefaultValueProperty(
                            default_value="defaultValue"
                        )]
                    ),
                    prompt_specification=lex.CfnBot.PromptSpecificationProperty(
                        max_retries=123,
                        message_groups_list=[lex.CfnBot.MessageGroupProperty(
                            message=lex.CfnBot.MessageProperty(
                                custom_payload=lex.CfnBot.CustomPayloadProperty(
                                    value="value"
                                ),
                                image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                    title="title",
                
                                    # the properties below are optional
                                    buttons=[lex.CfnBot.ButtonProperty(
                                        text="text",
                                        value="value"
                                    )],
                                    image_url="imageUrl",
                                    subtitle="subtitle"
                                ),
                                plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                    value="value"
                                ),
                                ssml_message=lex.CfnBot.SSMLMessageProperty(
                                    value="value"
                                )
                            ),
                
                            # the properties below are optional
                            variations=[lex.CfnBot.MessageProperty(
                                custom_payload=lex.CfnBot.CustomPayloadProperty(
                                    value="value"
                                ),
                                image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                    title="title",
                
                                    # the properties below are optional
                                    buttons=[lex.CfnBot.ButtonProperty(
                                        text="text",
                                        value="value"
                                    )],
                                    image_url="imageUrl",
                                    subtitle="subtitle"
                                ),
                                plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                    value="value"
                                ),
                                ssml_message=lex.CfnBot.SSMLMessageProperty(
                                    value="value"
                                )
                            )]
                        )],
                
                        # the properties below are optional
                        allow_interrupt=False
                    ),
                    sample_utterances=[lex.CfnBot.SampleUtteranceProperty(
                        utterance="utterance"
                    )],
                    wait_and_continue_specification=lex.CfnBot.WaitAndContinueSpecificationProperty(
                        continue_response=lex.CfnBot.ResponseSpecificationProperty(
                            message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                message=lex.CfnBot.MessageProperty(
                                    custom_payload=lex.CfnBot.CustomPayloadProperty(
                                        value="value"
                                    ),
                                    image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                        title="title",
                
                                        # the properties below are optional
                                        buttons=[lex.CfnBot.ButtonProperty(
                                            text="text",
                                            value="value"
                                        )],
                                        image_url="imageUrl",
                                        subtitle="subtitle"
                                    ),
                                    plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                        value="value"
                                    ),
                                    ssml_message=lex.CfnBot.SSMLMessageProperty(
                                        value="value"
                                    )
                                ),
                
                                # the properties below are optional
                                variations=[lex.CfnBot.MessageProperty(
                                    custom_payload=lex.CfnBot.CustomPayloadProperty(
                                        value="value"
                                    ),
                                    image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                        title="title",
                
                                        # the properties below are optional
                                        buttons=[lex.CfnBot.ButtonProperty(
                                            text="text",
                                            value="value"
                                        )],
                                        image_url="imageUrl",
                                        subtitle="subtitle"
                                    ),
                                    plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                        value="value"
                                    ),
                                    ssml_message=lex.CfnBot.SSMLMessageProperty(
                                        value="value"
                                    )
                                )]
                            )],
                
                            # the properties below are optional
                            allow_interrupt=False
                        ),
                        waiting_response=lex.CfnBot.ResponseSpecificationProperty(
                            message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                message=lex.CfnBot.MessageProperty(
                                    custom_payload=lex.CfnBot.CustomPayloadProperty(
                                        value="value"
                                    ),
                                    image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                        title="title",
                
                                        # the properties below are optional
                                        buttons=[lex.CfnBot.ButtonProperty(
                                            text="text",
                                            value="value"
                                        )],
                                        image_url="imageUrl",
                                        subtitle="subtitle"
                                    ),
                                    plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                        value="value"
                                    ),
                                    ssml_message=lex.CfnBot.SSMLMessageProperty(
                                        value="value"
                                    )
                                ),
                
                                # the properties below are optional
                                variations=[lex.CfnBot.MessageProperty(
                                    custom_payload=lex.CfnBot.CustomPayloadProperty(
                                        value="value"
                                    ),
                                    image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                        title="title",
                
                                        # the properties below are optional
                                        buttons=[lex.CfnBot.ButtonProperty(
                                            text="text",
                                            value="value"
                                        )],
                                        image_url="imageUrl",
                                        subtitle="subtitle"
                                    ),
                                    plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                        value="value"
                                    ),
                                    ssml_message=lex.CfnBot.SSMLMessageProperty(
                                        value="value"
                                    )
                                )]
                            )],
                
                            # the properties below are optional
                            allow_interrupt=False
                        ),
                
                        # the properties below are optional
                        is_active=False,
                        still_waiting_response=lex.CfnBot.StillWaitingResponseSpecificationProperty(
                            frequency_in_seconds=123,
                            message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                message=lex.CfnBot.MessageProperty(
                                    custom_payload=lex.CfnBot.CustomPayloadProperty(
                                        value="value"
                                    ),
                                    image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                        title="title",
                
                                        # the properties below are optional
                                        buttons=[lex.CfnBot.ButtonProperty(
                                            text="text",
                                            value="value"
                                        )],
                                        image_url="imageUrl",
                                        subtitle="subtitle"
                                    ),
                                    plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                        value="value"
                                    ),
                                    ssml_message=lex.CfnBot.SSMLMessageProperty(
                                        value="value"
                                    )
                                ),
                
                                # the properties below are optional
                                variations=[lex.CfnBot.MessageProperty(
                                    custom_payload=lex.CfnBot.CustomPayloadProperty(
                                        value="value"
                                    ),
                                    image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                        title="title",
                
                                        # the properties below are optional
                                        buttons=[lex.CfnBot.ButtonProperty(
                                            text="text",
                                            value="value"
                                        )],
                                        image_url="imageUrl",
                                        subtitle="subtitle"
                                    ),
                                    plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                        value="value"
                                    ),
                                    ssml_message=lex.CfnBot.SSMLMessageProperty(
                                        value="value"
                                    )
                                )]
                            )],
                            timeout_in_seconds=123,
                
                            # the properties below are optional
                            allow_interrupt=False
                        )
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "slot_constraint": slot_constraint,
            }
            if default_value_specification is not None:
                self._values["default_value_specification"] = default_value_specification
            if prompt_specification is not None:
                self._values["prompt_specification"] = prompt_specification
            if sample_utterances is not None:
                self._values["sample_utterances"] = sample_utterances
            if wait_and_continue_specification is not None:
                self._values["wait_and_continue_specification"] = wait_and_continue_specification

        @builtins.property
        def slot_constraint(self) -> builtins.str:
            '''Specifies whether the slot is required or optional.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-slotvalueelicitationsetting.html#cfn-lex-bot-slotvalueelicitationsetting-slotconstraint
            '''
            result = self._values.get("slot_constraint")
            assert result is not None, "Required property 'slot_constraint' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def default_value_specification(
            self,
        ) -> typing.Optional[typing.Union["CfnBot.SlotDefaultValueSpecificationProperty", _IResolvable_da3f097b]]:
            '''A list of default values for a slot.

            Default values are used when Amazon Lex hasn't determined a value for a slot. You can specify default values from context variables, session attributes, and defined values.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-slotvalueelicitationsetting.html#cfn-lex-bot-slotvalueelicitationsetting-defaultvaluespecification
            '''
            result = self._values.get("default_value_specification")
            return typing.cast(typing.Optional[typing.Union["CfnBot.SlotDefaultValueSpecificationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def prompt_specification(
            self,
        ) -> typing.Optional[typing.Union["CfnBot.PromptSpecificationProperty", _IResolvable_da3f097b]]:
            '''The prompt that Amazon Lex uses to elicit the slot value from the user.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-slotvalueelicitationsetting.html#cfn-lex-bot-slotvalueelicitationsetting-promptspecification
            '''
            result = self._values.get("prompt_specification")
            return typing.cast(typing.Optional[typing.Union["CfnBot.PromptSpecificationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def sample_utterances(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBot.SampleUtteranceProperty", _IResolvable_da3f097b]]]]:
            '''If you know a specific pattern that users might respond to an Amazon Lex request for a slot value, you can provide those utterances to improve accuracy.

            This is optional. In most cases Amazon Lex is capable of understanding user utterances.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-slotvalueelicitationsetting.html#cfn-lex-bot-slotvalueelicitationsetting-sampleutterances
            '''
            result = self._values.get("sample_utterances")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBot.SampleUtteranceProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def wait_and_continue_specification(
            self,
        ) -> typing.Optional[typing.Union["CfnBot.WaitAndContinueSpecificationProperty", _IResolvable_da3f097b]]:
            '''Specifies the prompts that Amazon Lex uses while a bot is waiting for customer input.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-slotvalueelicitationsetting.html#cfn-lex-bot-slotvalueelicitationsetting-waitandcontinuespecification
            '''
            result = self._values.get("wait_and_continue_specification")
            return typing.cast(typing.Optional[typing.Union["CfnBot.WaitAndContinueSpecificationProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SlotValueElicitationSettingProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBot.SlotValueRegexFilterProperty",
        jsii_struct_bases=[],
        name_mapping={"pattern": "pattern"},
    )
    class SlotValueRegexFilterProperty:
        def __init__(self, *, pattern: builtins.str) -> None:
            '''Provides a regular expression used to validate the value of a slot.

            :param pattern: A regular expression used to validate the value of a slot. Use a standard regular expression. Amazon Lex supports the following characters in the regular expression: - A-Z, a-z - 0-9 - Unicode characters ("\\ u") Represent Unicode characters with four digits, for example "]u0041" or "\\ u005A". The following regular expression operators are not supported: - Infinite repeaters: *, +, or {x,} with no upper bound - Wild card (.)

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-slotvalueregexfilter.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                slot_value_regex_filter_property = lex.CfnBot.SlotValueRegexFilterProperty(
                    pattern="pattern"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "pattern": pattern,
            }

        @builtins.property
        def pattern(self) -> builtins.str:
            '''A regular expression used to validate the value of a slot.

            Use a standard regular expression. Amazon Lex supports the following characters in the regular expression:

            - A-Z, a-z
            - 0-9
            - Unicode characters ("\\ u")

            Represent Unicode characters with four digits, for example "]u0041" or "\\ u005A".

            The following regular expression operators are not supported:

            - Infinite repeaters: *, +, or {x,} with no upper bound
            - Wild card (.)

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-slotvalueregexfilter.html#cfn-lex-bot-slotvalueregexfilter-pattern
            '''
            result = self._values.get("pattern")
            assert result is not None, "Required property 'pattern' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SlotValueRegexFilterProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBot.SlotValueSelectionSettingProperty",
        jsii_struct_bases=[],
        name_mapping={
            "resolution_strategy": "resolutionStrategy",
            "regex_filter": "regexFilter",
        },
    )
    class SlotValueSelectionSettingProperty:
        def __init__(
            self,
            *,
            resolution_strategy: builtins.str,
            regex_filter: typing.Optional[typing.Union["CfnBot.SlotValueRegexFilterProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Contains settings used by Amazon Lex to select a slot value.

            :param resolution_strategy: Determines the slot resolution strategy that Amazon Lex uses to return slot type values. The field can be set to one of the following values: - OriginalValue - Returns the value entered by the user, if the user value is similar to a slot value. - TopResolution - If there is a resolution list for the slot, return the first value in the resolution list as the slot type value. If there is no resolution list, null is returned. If you don't specify the valueSelectionStrategy, the default is OriginalValue.
            :param regex_filter: A regular expression used to validate the value of a slot.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-slotvalueselectionsetting.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                slot_value_selection_setting_property = lex.CfnBot.SlotValueSelectionSettingProperty(
                    resolution_strategy="resolutionStrategy",
                
                    # the properties below are optional
                    regex_filter=lex.CfnBot.SlotValueRegexFilterProperty(
                        pattern="pattern"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "resolution_strategy": resolution_strategy,
            }
            if regex_filter is not None:
                self._values["regex_filter"] = regex_filter

        @builtins.property
        def resolution_strategy(self) -> builtins.str:
            '''Determines the slot resolution strategy that Amazon Lex uses to return slot type values.

            The field can be set to one of the following values:

            - OriginalValue - Returns the value entered by the user, if the user value is similar to a slot value.
            - TopResolution - If there is a resolution list for the slot, return the first value in the resolution list as the slot type value. If there is no resolution list, null is returned.

            If you don't specify the valueSelectionStrategy, the default is OriginalValue.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-slotvalueselectionsetting.html#cfn-lex-bot-slotvalueselectionsetting-resolutionstrategy
            '''
            result = self._values.get("resolution_strategy")
            assert result is not None, "Required property 'resolution_strategy' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def regex_filter(
            self,
        ) -> typing.Optional[typing.Union["CfnBot.SlotValueRegexFilterProperty", _IResolvable_da3f097b]]:
            '''A regular expression used to validate the value of a slot.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-slotvalueselectionsetting.html#cfn-lex-bot-slotvalueselectionsetting-regexfilter
            '''
            result = self._values.get("regex_filter")
            return typing.cast(typing.Optional[typing.Union["CfnBot.SlotValueRegexFilterProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SlotValueSelectionSettingProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBot.StillWaitingResponseSpecificationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "frequency_in_seconds": "frequencyInSeconds",
            "message_groups_list": "messageGroupsList",
            "timeout_in_seconds": "timeoutInSeconds",
            "allow_interrupt": "allowInterrupt",
        },
    )
    class StillWaitingResponseSpecificationProperty:
        def __init__(
            self,
            *,
            frequency_in_seconds: jsii.Number,
            message_groups_list: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBot.MessageGroupProperty", _IResolvable_da3f097b]]],
            timeout_in_seconds: jsii.Number,
            allow_interrupt: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Defines the messages that Amazon Lex sends to a user to remind them that the bot is waiting for a response.

            :param frequency_in_seconds: How often a message should be sent to the user. Minimum of 1 second, maximum of 5 minutes.
            :param message_groups_list: A collection of responses that Amazon Lex can send to the user. Amazon Lex chooses the actual response to send at runtime.
            :param timeout_in_seconds: If Amazon Lex waits longer than this length of time for a response, it will stop sending messages.
            :param allow_interrupt: Indicates that the user can interrupt the response by speaking while the message is being played.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-stillwaitingresponsespecification.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                still_waiting_response_specification_property = lex.CfnBot.StillWaitingResponseSpecificationProperty(
                    frequency_in_seconds=123,
                    message_groups_list=[lex.CfnBot.MessageGroupProperty(
                        message=lex.CfnBot.MessageProperty(
                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                value="value"
                            ),
                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                title="title",
                
                                # the properties below are optional
                                buttons=[lex.CfnBot.ButtonProperty(
                                    text="text",
                                    value="value"
                                )],
                                image_url="imageUrl",
                                subtitle="subtitle"
                            ),
                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                value="value"
                            ),
                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                value="value"
                            )
                        ),
                
                        # the properties below are optional
                        variations=[lex.CfnBot.MessageProperty(
                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                value="value"
                            ),
                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                title="title",
                
                                # the properties below are optional
                                buttons=[lex.CfnBot.ButtonProperty(
                                    text="text",
                                    value="value"
                                )],
                                image_url="imageUrl",
                                subtitle="subtitle"
                            ),
                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                value="value"
                            ),
                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                value="value"
                            )
                        )]
                    )],
                    timeout_in_seconds=123,
                
                    # the properties below are optional
                    allow_interrupt=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "frequency_in_seconds": frequency_in_seconds,
                "message_groups_list": message_groups_list,
                "timeout_in_seconds": timeout_in_seconds,
            }
            if allow_interrupt is not None:
                self._values["allow_interrupt"] = allow_interrupt

        @builtins.property
        def frequency_in_seconds(self) -> jsii.Number:
            '''How often a message should be sent to the user.

            Minimum of 1 second, maximum of 5 minutes.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-stillwaitingresponsespecification.html#cfn-lex-bot-stillwaitingresponsespecification-frequencyinseconds
            '''
            result = self._values.get("frequency_in_seconds")
            assert result is not None, "Required property 'frequency_in_seconds' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def message_groups_list(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBot.MessageGroupProperty", _IResolvable_da3f097b]]]:
            '''A collection of responses that Amazon Lex can send to the user.

            Amazon Lex chooses the actual response to send at runtime.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-stillwaitingresponsespecification.html#cfn-lex-bot-stillwaitingresponsespecification-messagegroupslist
            '''
            result = self._values.get("message_groups_list")
            assert result is not None, "Required property 'message_groups_list' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBot.MessageGroupProperty", _IResolvable_da3f097b]]], result)

        @builtins.property
        def timeout_in_seconds(self) -> jsii.Number:
            '''If Amazon Lex waits longer than this length of time for a response, it will stop sending messages.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-stillwaitingresponsespecification.html#cfn-lex-bot-stillwaitingresponsespecification-timeoutinseconds
            '''
            result = self._values.get("timeout_in_seconds")
            assert result is not None, "Required property 'timeout_in_seconds' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def allow_interrupt(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Indicates that the user can interrupt the response by speaking while the message is being played.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-stillwaitingresponsespecification.html#cfn-lex-bot-stillwaitingresponsespecification-allowinterrupt
            '''
            result = self._values.get("allow_interrupt")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "StillWaitingResponseSpecificationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBot.VoiceSettingsProperty",
        jsii_struct_bases=[],
        name_mapping={"voice_id": "voiceId"},
    )
    class VoiceSettingsProperty:
        def __init__(self, *, voice_id: builtins.str) -> None:
            '''Identifies the Amazon Polly voice used for audio interaction with the user.

            :param voice_id: The Amazon Polly voice used for voice interaction with the user.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-voicesettings.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                voice_settings_property = lex.CfnBot.VoiceSettingsProperty(
                    voice_id="voiceId"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "voice_id": voice_id,
            }

        @builtins.property
        def voice_id(self) -> builtins.str:
            '''The Amazon Polly voice used for voice interaction with the user.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-voicesettings.html#cfn-lex-bot-voicesettings-voiceid
            '''
            result = self._values.get("voice_id")
            assert result is not None, "Required property 'voice_id' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "VoiceSettingsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBot.WaitAndContinueSpecificationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "continue_response": "continueResponse",
            "waiting_response": "waitingResponse",
            "is_active": "isActive",
            "still_waiting_response": "stillWaitingResponse",
        },
    )
    class WaitAndContinueSpecificationProperty:
        def __init__(
            self,
            *,
            continue_response: typing.Union["CfnBot.ResponseSpecificationProperty", _IResolvable_da3f097b],
            waiting_response: typing.Union["CfnBot.ResponseSpecificationProperty", _IResolvable_da3f097b],
            is_active: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            still_waiting_response: typing.Optional[typing.Union["CfnBot.StillWaitingResponseSpecificationProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Specifies the prompts that Amazon Lex uses while a bot is waiting for customer input.

            :param continue_response: The response that Amazon Lex sends to indicate that the bot is ready to continue the conversation.
            :param waiting_response: The response that Amazon Lex sends to indicate that the bot is waiting for the conversation to continue.
            :param is_active: Specifies whether the bot will wait for a user to respond. When this field is false, wait and continue responses for a slot aren't used and the bot expects an appropriate response within the configured timeout. If the IsActive field isn't specified, the default is true.
            :param still_waiting_response: A response that Amazon Lex sends periodically to the user to indicate that the bot is still waiting for input from the user.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-waitandcontinuespecification.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                wait_and_continue_specification_property = lex.CfnBot.WaitAndContinueSpecificationProperty(
                    continue_response=lex.CfnBot.ResponseSpecificationProperty(
                        message_groups_list=[lex.CfnBot.MessageGroupProperty(
                            message=lex.CfnBot.MessageProperty(
                                custom_payload=lex.CfnBot.CustomPayloadProperty(
                                    value="value"
                                ),
                                image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                    title="title",
                
                                    # the properties below are optional
                                    buttons=[lex.CfnBot.ButtonProperty(
                                        text="text",
                                        value="value"
                                    )],
                                    image_url="imageUrl",
                                    subtitle="subtitle"
                                ),
                                plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                    value="value"
                                ),
                                ssml_message=lex.CfnBot.SSMLMessageProperty(
                                    value="value"
                                )
                            ),
                
                            # the properties below are optional
                            variations=[lex.CfnBot.MessageProperty(
                                custom_payload=lex.CfnBot.CustomPayloadProperty(
                                    value="value"
                                ),
                                image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                    title="title",
                
                                    # the properties below are optional
                                    buttons=[lex.CfnBot.ButtonProperty(
                                        text="text",
                                        value="value"
                                    )],
                                    image_url="imageUrl",
                                    subtitle="subtitle"
                                ),
                                plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                    value="value"
                                ),
                                ssml_message=lex.CfnBot.SSMLMessageProperty(
                                    value="value"
                                )
                            )]
                        )],
                
                        # the properties below are optional
                        allow_interrupt=False
                    ),
                    waiting_response=lex.CfnBot.ResponseSpecificationProperty(
                        message_groups_list=[lex.CfnBot.MessageGroupProperty(
                            message=lex.CfnBot.MessageProperty(
                                custom_payload=lex.CfnBot.CustomPayloadProperty(
                                    value="value"
                                ),
                                image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                    title="title",
                
                                    # the properties below are optional
                                    buttons=[lex.CfnBot.ButtonProperty(
                                        text="text",
                                        value="value"
                                    )],
                                    image_url="imageUrl",
                                    subtitle="subtitle"
                                ),
                                plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                    value="value"
                                ),
                                ssml_message=lex.CfnBot.SSMLMessageProperty(
                                    value="value"
                                )
                            ),
                
                            # the properties below are optional
                            variations=[lex.CfnBot.MessageProperty(
                                custom_payload=lex.CfnBot.CustomPayloadProperty(
                                    value="value"
                                ),
                                image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                    title="title",
                
                                    # the properties below are optional
                                    buttons=[lex.CfnBot.ButtonProperty(
                                        text="text",
                                        value="value"
                                    )],
                                    image_url="imageUrl",
                                    subtitle="subtitle"
                                ),
                                plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                    value="value"
                                ),
                                ssml_message=lex.CfnBot.SSMLMessageProperty(
                                    value="value"
                                )
                            )]
                        )],
                
                        # the properties below are optional
                        allow_interrupt=False
                    ),
                
                    # the properties below are optional
                    is_active=False,
                    still_waiting_response=lex.CfnBot.StillWaitingResponseSpecificationProperty(
                        frequency_in_seconds=123,
                        message_groups_list=[lex.CfnBot.MessageGroupProperty(
                            message=lex.CfnBot.MessageProperty(
                                custom_payload=lex.CfnBot.CustomPayloadProperty(
                                    value="value"
                                ),
                                image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                    title="title",
                
                                    # the properties below are optional
                                    buttons=[lex.CfnBot.ButtonProperty(
                                        text="text",
                                        value="value"
                                    )],
                                    image_url="imageUrl",
                                    subtitle="subtitle"
                                ),
                                plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                    value="value"
                                ),
                                ssml_message=lex.CfnBot.SSMLMessageProperty(
                                    value="value"
                                )
                            ),
                
                            # the properties below are optional
                            variations=[lex.CfnBot.MessageProperty(
                                custom_payload=lex.CfnBot.CustomPayloadProperty(
                                    value="value"
                                ),
                                image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                    title="title",
                
                                    # the properties below are optional
                                    buttons=[lex.CfnBot.ButtonProperty(
                                        text="text",
                                        value="value"
                                    )],
                                    image_url="imageUrl",
                                    subtitle="subtitle"
                                ),
                                plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                    value="value"
                                ),
                                ssml_message=lex.CfnBot.SSMLMessageProperty(
                                    value="value"
                                )
                            )]
                        )],
                        timeout_in_seconds=123,
                
                        # the properties below are optional
                        allow_interrupt=False
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "continue_response": continue_response,
                "waiting_response": waiting_response,
            }
            if is_active is not None:
                self._values["is_active"] = is_active
            if still_waiting_response is not None:
                self._values["still_waiting_response"] = still_waiting_response

        @builtins.property
        def continue_response(
            self,
        ) -> typing.Union["CfnBot.ResponseSpecificationProperty", _IResolvable_da3f097b]:
            '''The response that Amazon Lex sends to indicate that the bot is ready to continue the conversation.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-waitandcontinuespecification.html#cfn-lex-bot-waitandcontinuespecification-continueresponse
            '''
            result = self._values.get("continue_response")
            assert result is not None, "Required property 'continue_response' is missing"
            return typing.cast(typing.Union["CfnBot.ResponseSpecificationProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def waiting_response(
            self,
        ) -> typing.Union["CfnBot.ResponseSpecificationProperty", _IResolvable_da3f097b]:
            '''The response that Amazon Lex sends to indicate that the bot is waiting for the conversation to continue.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-waitandcontinuespecification.html#cfn-lex-bot-waitandcontinuespecification-waitingresponse
            '''
            result = self._values.get("waiting_response")
            assert result is not None, "Required property 'waiting_response' is missing"
            return typing.cast(typing.Union["CfnBot.ResponseSpecificationProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def is_active(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Specifies whether the bot will wait for a user to respond.

            When this field is false, wait and continue responses for a slot aren't used and the bot expects an appropriate response within the configured timeout. If the IsActive field isn't specified, the default is true.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-waitandcontinuespecification.html#cfn-lex-bot-waitandcontinuespecification-isactive
            '''
            result = self._values.get("is_active")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def still_waiting_response(
            self,
        ) -> typing.Optional[typing.Union["CfnBot.StillWaitingResponseSpecificationProperty", _IResolvable_da3f097b]]:
            '''A response that Amazon Lex sends periodically to the user to indicate that the bot is still waiting for input from the user.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-bot-waitandcontinuespecification.html#cfn-lex-bot-waitandcontinuespecification-stillwaitingresponse
            '''
            result = self._values.get("still_waiting_response")
            return typing.cast(typing.Optional[typing.Union["CfnBot.StillWaitingResponseSpecificationProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "WaitAndContinueSpecificationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.implements(_IInspectable_c2943556)
class CfnBotAlias(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_lex.CfnBotAlias",
):
    '''A CloudFormation ``AWS::Lex::BotAlias``.

    Specifies an alias for the specified version of a bot. Use an alias to enable you to change the version of a bot without updating applications that use the bot.

    For example, you can specify an alias called "PROD" that your applications use to call the Amazon Lex bot.

    :cloudformationResource: AWS::Lex::BotAlias
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-botalias.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_lex as lex
        
        # sentiment_analysis_settings: Any
        
        cfn_bot_alias = lex.CfnBotAlias(self, "MyCfnBotAlias",
            bot_alias_name="botAliasName",
            bot_id="botId",
        
            # the properties below are optional
            bot_alias_locale_settings=[lex.CfnBotAlias.BotAliasLocaleSettingsItemProperty(
                bot_alias_locale_setting=lex.CfnBotAlias.BotAliasLocaleSettingsProperty(
                    enabled=False,
        
                    # the properties below are optional
                    code_hook_specification=lex.CfnBotAlias.CodeHookSpecificationProperty(
                        lambda_code_hook=lex.CfnBotAlias.LambdaCodeHookProperty(
                            code_hook_interface_version="codeHookInterfaceVersion",
                            lambda_arn="lambdaArn"
                        )
                    )
                ),
                locale_id="localeId"
            )],
            bot_alias_tags=[CfnTag(
                key="key",
                value="value"
            )],
            bot_version="botVersion",
            conversation_log_settings=lex.CfnBotAlias.ConversationLogSettingsProperty(
                audio_log_settings=[lex.CfnBotAlias.AudioLogSettingProperty(
                    destination=lex.CfnBotAlias.AudioLogDestinationProperty(
                        s3_bucket=lex.CfnBotAlias.S3BucketLogDestinationProperty(
                            log_prefix="logPrefix",
                            s3_bucket_arn="s3BucketArn",
        
                            # the properties below are optional
                            kms_key_arn="kmsKeyArn"
                        )
                    ),
                    enabled=False
                )],
                text_log_settings=[lex.CfnBotAlias.TextLogSettingProperty(
                    destination=lex.CfnBotAlias.TextLogDestinationProperty(),
                    enabled=False
                )]
            ),
            description="description",
            sentiment_analysis_settings=sentiment_analysis_settings
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        bot_alias_name: builtins.str,
        bot_id: builtins.str,
        bot_alias_locale_settings: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBotAlias.BotAliasLocaleSettingsItemProperty", _IResolvable_da3f097b]]]] = None,
        bot_alias_tags: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]] = None,
        bot_version: typing.Optional[builtins.str] = None,
        conversation_log_settings: typing.Optional[typing.Union["CfnBotAlias.ConversationLogSettingsProperty", _IResolvable_da3f097b]] = None,
        description: typing.Optional[builtins.str] = None,
        sentiment_analysis_settings: typing.Any = None,
    ) -> None:
        '''Create a new ``AWS::Lex::BotAlias``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param bot_alias_name: The name of the bot alias.
        :param bot_id: The unique identifier of the bot.
        :param bot_alias_locale_settings: Maps configuration information to a specific locale. You can use this parameter to specify a specific Lambda function to run different functions in different locales.
        :param bot_alias_tags: An array of key-value pairs to apply to this resource. You can only add tags when you specify an alias. For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .
        :param bot_version: The version of the bot that the bot alias references.
        :param conversation_log_settings: Specifies whether Amazon Lex logs text and audio for conversations with the bot. When you enable conversation logs, text logs store text input, transcripts of audio input, and associated metadata in Amazon CloudWatch logs. Audio logs store input in Amazon S3 .
        :param description: The description of the bot alias.
        :param sentiment_analysis_settings: Determines whether Amazon Lex will use Amazon Comprehend to detect the sentiment of user utterances.
        '''
        props = CfnBotAliasProps(
            bot_alias_name=bot_alias_name,
            bot_id=bot_id,
            bot_alias_locale_settings=bot_alias_locale_settings,
            bot_alias_tags=bot_alias_tags,
            bot_version=bot_version,
            conversation_log_settings=conversation_log_settings,
            description=description,
            sentiment_analysis_settings=sentiment_analysis_settings,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="inspect")
    def inspect(self, inspector: _TreeInspector_488e0dd5) -> None:
        '''Examines the CloudFormation resource and discloses attributes.

        :param inspector: - tree inspector to collect and process attributes.
        '''
        return typing.cast(None, jsii.invoke(self, "inspect", [inspector]))

    @jsii.member(jsii_name="renderProperties")
    def _render_properties(
        self,
        props: typing.Mapping[builtins.str, typing.Any],
    ) -> typing.Mapping[builtins.str, typing.Any]:
        '''
        :param props: -
        '''
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.invoke(self, "renderProperties", [props]))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="CFN_RESOURCE_TYPE_NAME")
    def CFN_RESOURCE_TYPE_NAME(cls) -> builtins.str:
        '''The CloudFormation resource type name for this resource class.'''
        return typing.cast(builtins.str, jsii.sget(cls, "CFN_RESOURCE_TYPE_NAME"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrArn")
    def attr_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the bot alias.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrBotAliasId")
    def attr_bot_alias_id(self) -> builtins.str:
        '''The unique identifier of the bot alias.

        :cloudformationAttribute: BotAliasId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrBotAliasId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrBotAliasStatus")
    def attr_bot_alias_status(self) -> builtins.str:
        '''The current status of the bot alias.

        When the status is Available the alias is ready for use with your bot.

        :cloudformationAttribute: BotAliasStatus
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrBotAliasStatus"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="botAliasName")
    def bot_alias_name(self) -> builtins.str:
        '''The name of the bot alias.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-botalias.html#cfn-lex-botalias-botaliasname
        '''
        return typing.cast(builtins.str, jsii.get(self, "botAliasName"))

    @bot_alias_name.setter
    def bot_alias_name(self, value: builtins.str) -> None:
        jsii.set(self, "botAliasName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="botId")
    def bot_id(self) -> builtins.str:
        '''The unique identifier of the bot.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-botalias.html#cfn-lex-botalias-botid
        '''
        return typing.cast(builtins.str, jsii.get(self, "botId"))

    @bot_id.setter
    def bot_id(self, value: builtins.str) -> None:
        jsii.set(self, "botId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="sentimentAnalysisSettings")
    def sentiment_analysis_settings(self) -> typing.Any:
        '''Determines whether Amazon Lex will use Amazon Comprehend to detect the sentiment of user utterances.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-botalias.html#cfn-lex-botalias-sentimentanalysissettings
        '''
        return typing.cast(typing.Any, jsii.get(self, "sentimentAnalysisSettings"))

    @sentiment_analysis_settings.setter
    def sentiment_analysis_settings(self, value: typing.Any) -> None:
        jsii.set(self, "sentimentAnalysisSettings", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="botAliasLocaleSettings")
    def bot_alias_locale_settings(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBotAlias.BotAliasLocaleSettingsItemProperty", _IResolvable_da3f097b]]]]:
        '''Maps configuration information to a specific locale.

        You can use this parameter to specify a specific Lambda function to run different functions in different locales.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-botalias.html#cfn-lex-botalias-botaliaslocalesettings
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBotAlias.BotAliasLocaleSettingsItemProperty", _IResolvable_da3f097b]]]], jsii.get(self, "botAliasLocaleSettings"))

    @bot_alias_locale_settings.setter
    def bot_alias_locale_settings(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBotAlias.BotAliasLocaleSettingsItemProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "botAliasLocaleSettings", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="botAliasTags")
    def bot_alias_tags(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]]:
        '''An array of key-value pairs to apply to this resource.

        You can only add tags when you specify an alias.

        For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-botalias.html#cfn-lex-botalias-botaliastags
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]], jsii.get(self, "botAliasTags"))

    @bot_alias_tags.setter
    def bot_alias_tags(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]],
    ) -> None:
        jsii.set(self, "botAliasTags", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="botVersion")
    def bot_version(self) -> typing.Optional[builtins.str]:
        '''The version of the bot that the bot alias references.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-botalias.html#cfn-lex-botalias-botversion
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "botVersion"))

    @bot_version.setter
    def bot_version(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "botVersion", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="conversationLogSettings")
    def conversation_log_settings(
        self,
    ) -> typing.Optional[typing.Union["CfnBotAlias.ConversationLogSettingsProperty", _IResolvable_da3f097b]]:
        '''Specifies whether Amazon Lex logs text and audio for conversations with the bot.

        When you enable conversation logs, text logs store text input, transcripts of audio input, and associated metadata in Amazon CloudWatch logs. Audio logs store input in Amazon S3 .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-botalias.html#cfn-lex-botalias-conversationlogsettings
        '''
        return typing.cast(typing.Optional[typing.Union["CfnBotAlias.ConversationLogSettingsProperty", _IResolvable_da3f097b]], jsii.get(self, "conversationLogSettings"))

    @conversation_log_settings.setter
    def conversation_log_settings(
        self,
        value: typing.Optional[typing.Union["CfnBotAlias.ConversationLogSettingsProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "conversationLogSettings", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the bot alias.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-botalias.html#cfn-lex-botalias-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBotAlias.AudioLogDestinationProperty",
        jsii_struct_bases=[],
        name_mapping={"s3_bucket": "s3Bucket"},
    )
    class AudioLogDestinationProperty:
        def __init__(
            self,
            *,
            s3_bucket: typing.Optional[typing.Union["CfnBotAlias.S3BucketLogDestinationProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Specifies the S3 bucket location where audio logs are stored.

            :param s3_bucket: The S3 bucket location where audio logs are stored.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-botalias-audiologdestination.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                audio_log_destination_property = lex.CfnBotAlias.AudioLogDestinationProperty(
                    s3_bucket=lex.CfnBotAlias.S3BucketLogDestinationProperty(
                        log_prefix="logPrefix",
                        s3_bucket_arn="s3BucketArn",
                
                        # the properties below are optional
                        kms_key_arn="kmsKeyArn"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if s3_bucket is not None:
                self._values["s3_bucket"] = s3_bucket

        @builtins.property
        def s3_bucket(
            self,
        ) -> typing.Optional[typing.Union["CfnBotAlias.S3BucketLogDestinationProperty", _IResolvable_da3f097b]]:
            '''The S3 bucket location where audio logs are stored.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-botalias-audiologdestination.html#cfn-lex-botalias-audiologdestination-s3bucket
            '''
            result = self._values.get("s3_bucket")
            return typing.cast(typing.Optional[typing.Union["CfnBotAlias.S3BucketLogDestinationProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AudioLogDestinationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBotAlias.AudioLogSettingProperty",
        jsii_struct_bases=[],
        name_mapping={"destination": "destination", "enabled": "enabled"},
    )
    class AudioLogSettingProperty:
        def __init__(
            self,
            *,
            destination: typing.Union["CfnBotAlias.AudioLogDestinationProperty", _IResolvable_da3f097b],
            enabled: typing.Union[builtins.bool, _IResolvable_da3f097b],
        ) -> None:
            '''Settings for logging audio of conversations between Amazon Lex and a user.

            You specify whether to log audio and the Amazon S3 bucket where the audio file is stored.

            :param destination: The location of audio log files collected when conversation logging is enabled for a bot.
            :param enabled: Determines whether audio logging in enabled for the bot.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-botalias-audiologsetting.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                audio_log_setting_property = lex.CfnBotAlias.AudioLogSettingProperty(
                    destination=lex.CfnBotAlias.AudioLogDestinationProperty(
                        s3_bucket=lex.CfnBotAlias.S3BucketLogDestinationProperty(
                            log_prefix="logPrefix",
                            s3_bucket_arn="s3BucketArn",
                
                            # the properties below are optional
                            kms_key_arn="kmsKeyArn"
                        )
                    ),
                    enabled=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "destination": destination,
                "enabled": enabled,
            }

        @builtins.property
        def destination(
            self,
        ) -> typing.Union["CfnBotAlias.AudioLogDestinationProperty", _IResolvable_da3f097b]:
            '''The location of audio log files collected when conversation logging is enabled for a bot.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-botalias-audiologsetting.html#cfn-lex-botalias-audiologsetting-destination
            '''
            result = self._values.get("destination")
            assert result is not None, "Required property 'destination' is missing"
            return typing.cast(typing.Union["CfnBotAlias.AudioLogDestinationProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def enabled(self) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
            '''Determines whether audio logging in enabled for the bot.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-botalias-audiologsetting.html#cfn-lex-botalias-audiologsetting-enabled
            '''
            result = self._values.get("enabled")
            assert result is not None, "Required property 'enabled' is missing"
            return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AudioLogSettingProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBotAlias.BotAliasLocaleSettingsItemProperty",
        jsii_struct_bases=[],
        name_mapping={
            "bot_alias_locale_setting": "botAliasLocaleSetting",
            "locale_id": "localeId",
        },
    )
    class BotAliasLocaleSettingsItemProperty:
        def __init__(
            self,
            *,
            bot_alias_locale_setting: typing.Union["CfnBotAlias.BotAliasLocaleSettingsProperty", _IResolvable_da3f097b],
            locale_id: builtins.str,
        ) -> None:
            '''Specifies settings that are unique to a locale.

            For example, you can use different Lambda function depending on the bot's locale.

            :param bot_alias_locale_setting: Specifies settings that are unique to a locale.
            :param locale_id: The unique identifier of the locale.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-botalias-botaliaslocalesettingsitem.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                bot_alias_locale_settings_item_property = lex.CfnBotAlias.BotAliasLocaleSettingsItemProperty(
                    bot_alias_locale_setting=lex.CfnBotAlias.BotAliasLocaleSettingsProperty(
                        enabled=False,
                
                        # the properties below are optional
                        code_hook_specification=lex.CfnBotAlias.CodeHookSpecificationProperty(
                            lambda_code_hook=lex.CfnBotAlias.LambdaCodeHookProperty(
                                code_hook_interface_version="codeHookInterfaceVersion",
                                lambda_arn="lambdaArn"
                            )
                        )
                    ),
                    locale_id="localeId"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "bot_alias_locale_setting": bot_alias_locale_setting,
                "locale_id": locale_id,
            }

        @builtins.property
        def bot_alias_locale_setting(
            self,
        ) -> typing.Union["CfnBotAlias.BotAliasLocaleSettingsProperty", _IResolvable_da3f097b]:
            '''Specifies settings that are unique to a locale.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-botalias-botaliaslocalesettingsitem.html#cfn-lex-botalias-botaliaslocalesettingsitem-botaliaslocalesetting
            '''
            result = self._values.get("bot_alias_locale_setting")
            assert result is not None, "Required property 'bot_alias_locale_setting' is missing"
            return typing.cast(typing.Union["CfnBotAlias.BotAliasLocaleSettingsProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def locale_id(self) -> builtins.str:
            '''The unique identifier of the locale.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-botalias-botaliaslocalesettingsitem.html#cfn-lex-botalias-botaliaslocalesettingsitem-localeid
            '''
            result = self._values.get("locale_id")
            assert result is not None, "Required property 'locale_id' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "BotAliasLocaleSettingsItemProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBotAlias.BotAliasLocaleSettingsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "enabled": "enabled",
            "code_hook_specification": "codeHookSpecification",
        },
    )
    class BotAliasLocaleSettingsProperty:
        def __init__(
            self,
            *,
            enabled: typing.Union[builtins.bool, _IResolvable_da3f097b],
            code_hook_specification: typing.Optional[typing.Union["CfnBotAlias.CodeHookSpecificationProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Specifies settings that are unique to a locale.

            For example, you can use different Lambda function depending on the bot's locale.

            :param enabled: Determines whether the locale is enabled for the bot. If the value is false, the locale isn't available for use.
            :param code_hook_specification: Specifies the Lambda function that should be used in the locale.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-botalias-botaliaslocalesettings.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                bot_alias_locale_settings_property = lex.CfnBotAlias.BotAliasLocaleSettingsProperty(
                    enabled=False,
                
                    # the properties below are optional
                    code_hook_specification=lex.CfnBotAlias.CodeHookSpecificationProperty(
                        lambda_code_hook=lex.CfnBotAlias.LambdaCodeHookProperty(
                            code_hook_interface_version="codeHookInterfaceVersion",
                            lambda_arn="lambdaArn"
                        )
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "enabled": enabled,
            }
            if code_hook_specification is not None:
                self._values["code_hook_specification"] = code_hook_specification

        @builtins.property
        def enabled(self) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
            '''Determines whether the locale is enabled for the bot.

            If the value is false, the locale isn't available for use.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-botalias-botaliaslocalesettings.html#cfn-lex-botalias-botaliaslocalesettings-enabled
            '''
            result = self._values.get("enabled")
            assert result is not None, "Required property 'enabled' is missing"
            return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], result)

        @builtins.property
        def code_hook_specification(
            self,
        ) -> typing.Optional[typing.Union["CfnBotAlias.CodeHookSpecificationProperty", _IResolvable_da3f097b]]:
            '''Specifies the Lambda function that should be used in the locale.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-botalias-botaliaslocalesettings.html#cfn-lex-botalias-botaliaslocalesettings-codehookspecification
            '''
            result = self._values.get("code_hook_specification")
            return typing.cast(typing.Optional[typing.Union["CfnBotAlias.CodeHookSpecificationProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "BotAliasLocaleSettingsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBotAlias.CloudWatchLogGroupLogDestinationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "cloud_watch_log_group_arn": "cloudWatchLogGroupArn",
            "log_prefix": "logPrefix",
        },
    )
    class CloudWatchLogGroupLogDestinationProperty:
        def __init__(
            self,
            *,
            cloud_watch_log_group_arn: builtins.str,
            log_prefix: builtins.str,
        ) -> None:
            '''The Amazon CloudWatch Logs log group where the text and metadata logs are delivered.

            The log group must exist before you enable logging.

            :param cloud_watch_log_group_arn: The Amazon Resource Name (ARN) of the log group where text and metadata logs are delivered.
            :param log_prefix: The prefix of the log stream name within the log group that you specified.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-botalias-cloudwatchloggrouplogdestination.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                cloud_watch_log_group_log_destination_property = lex.CfnBotAlias.CloudWatchLogGroupLogDestinationProperty(
                    cloud_watch_log_group_arn="cloudWatchLogGroupArn",
                    log_prefix="logPrefix"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "cloud_watch_log_group_arn": cloud_watch_log_group_arn,
                "log_prefix": log_prefix,
            }

        @builtins.property
        def cloud_watch_log_group_arn(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the log group where text and metadata logs are delivered.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-botalias-cloudwatchloggrouplogdestination.html#cfn-lex-botalias-cloudwatchloggrouplogdestination-cloudwatchloggrouparn
            '''
            result = self._values.get("cloud_watch_log_group_arn")
            assert result is not None, "Required property 'cloud_watch_log_group_arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def log_prefix(self) -> builtins.str:
            '''The prefix of the log stream name within the log group that you specified.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-botalias-cloudwatchloggrouplogdestination.html#cfn-lex-botalias-cloudwatchloggrouplogdestination-logprefix
            '''
            result = self._values.get("log_prefix")
            assert result is not None, "Required property 'log_prefix' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CloudWatchLogGroupLogDestinationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBotAlias.CodeHookSpecificationProperty",
        jsii_struct_bases=[],
        name_mapping={"lambda_code_hook": "lambdaCodeHook"},
    )
    class CodeHookSpecificationProperty:
        def __init__(
            self,
            *,
            lambda_code_hook: typing.Union["CfnBotAlias.LambdaCodeHookProperty", _IResolvable_da3f097b],
        ) -> None:
            '''Contains information about code hooks that Amazon Lex calls during a conversation.

            :param lambda_code_hook: Specifies a Lambda function that verifies requests to a bot or fulfills the user's request to a bot.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-botalias-codehookspecification.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                code_hook_specification_property = lex.CfnBotAlias.CodeHookSpecificationProperty(
                    lambda_code_hook=lex.CfnBotAlias.LambdaCodeHookProperty(
                        code_hook_interface_version="codeHookInterfaceVersion",
                        lambda_arn="lambdaArn"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "lambda_code_hook": lambda_code_hook,
            }

        @builtins.property
        def lambda_code_hook(
            self,
        ) -> typing.Union["CfnBotAlias.LambdaCodeHookProperty", _IResolvable_da3f097b]:
            '''Specifies a Lambda function that verifies requests to a bot or fulfills the user's request to a bot.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-botalias-codehookspecification.html#cfn-lex-botalias-codehookspecification-lambdacodehook
            '''
            result = self._values.get("lambda_code_hook")
            assert result is not None, "Required property 'lambda_code_hook' is missing"
            return typing.cast(typing.Union["CfnBotAlias.LambdaCodeHookProperty", _IResolvable_da3f097b], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CodeHookSpecificationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBotAlias.ConversationLogSettingsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "audio_log_settings": "audioLogSettings",
            "text_log_settings": "textLogSettings",
        },
    )
    class ConversationLogSettingsProperty:
        def __init__(
            self,
            *,
            audio_log_settings: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBotAlias.AudioLogSettingProperty", _IResolvable_da3f097b]]]] = None,
            text_log_settings: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBotAlias.TextLogSettingProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''Configures conversation logging that saves audio, text, and metadata for the conversations with your users.

            :param audio_log_settings: The Amazon S3 settings for logging audio to an S3 bucket.
            :param text_log_settings: The Amazon CloudWatch Logs settings for logging text and metadata.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-botalias-conversationlogsettings.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                conversation_log_settings_property = lex.CfnBotAlias.ConversationLogSettingsProperty(
                    audio_log_settings=[lex.CfnBotAlias.AudioLogSettingProperty(
                        destination=lex.CfnBotAlias.AudioLogDestinationProperty(
                            s3_bucket=lex.CfnBotAlias.S3BucketLogDestinationProperty(
                                log_prefix="logPrefix",
                                s3_bucket_arn="s3BucketArn",
                
                                # the properties below are optional
                                kms_key_arn="kmsKeyArn"
                            )
                        ),
                        enabled=False
                    )],
                    text_log_settings=[lex.CfnBotAlias.TextLogSettingProperty(
                        destination=lex.CfnBotAlias.TextLogDestinationProperty(),
                        enabled=False
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if audio_log_settings is not None:
                self._values["audio_log_settings"] = audio_log_settings
            if text_log_settings is not None:
                self._values["text_log_settings"] = text_log_settings

        @builtins.property
        def audio_log_settings(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBotAlias.AudioLogSettingProperty", _IResolvable_da3f097b]]]]:
            '''The Amazon S3 settings for logging audio to an S3 bucket.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-botalias-conversationlogsettings.html#cfn-lex-botalias-conversationlogsettings-audiologsettings
            '''
            result = self._values.get("audio_log_settings")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBotAlias.AudioLogSettingProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def text_log_settings(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBotAlias.TextLogSettingProperty", _IResolvable_da3f097b]]]]:
            '''The Amazon CloudWatch Logs settings for logging text and metadata.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-botalias-conversationlogsettings.html#cfn-lex-botalias-conversationlogsettings-textlogsettings
            '''
            result = self._values.get("text_log_settings")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBotAlias.TextLogSettingProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ConversationLogSettingsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBotAlias.LambdaCodeHookProperty",
        jsii_struct_bases=[],
        name_mapping={
            "code_hook_interface_version": "codeHookInterfaceVersion",
            "lambda_arn": "lambdaArn",
        },
    )
    class LambdaCodeHookProperty:
        def __init__(
            self,
            *,
            code_hook_interface_version: builtins.str,
            lambda_arn: builtins.str,
        ) -> None:
            '''Specifies a Lambda function that verifies requests to a bot or fulfills the user's request to a bot.

            :param code_hook_interface_version: The version of the request-response that you want Amazon Lex to use to invoke your Lambda function.
            :param lambda_arn: The Amazon Resource Name (ARN) of the Lambda function.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-botalias-lambdacodehook.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                lambda_code_hook_property = lex.CfnBotAlias.LambdaCodeHookProperty(
                    code_hook_interface_version="codeHookInterfaceVersion",
                    lambda_arn="lambdaArn"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "code_hook_interface_version": code_hook_interface_version,
                "lambda_arn": lambda_arn,
            }

        @builtins.property
        def code_hook_interface_version(self) -> builtins.str:
            '''The version of the request-response that you want Amazon Lex to use to invoke your Lambda function.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-botalias-lambdacodehook.html#cfn-lex-botalias-lambdacodehook-codehookinterfaceversion
            '''
            result = self._values.get("code_hook_interface_version")
            assert result is not None, "Required property 'code_hook_interface_version' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def lambda_arn(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the Lambda function.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-botalias-lambdacodehook.html#cfn-lex-botalias-lambdacodehook-lambdaarn
            '''
            result = self._values.get("lambda_arn")
            assert result is not None, "Required property 'lambda_arn' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LambdaCodeHookProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBotAlias.S3BucketLogDestinationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "log_prefix": "logPrefix",
            "s3_bucket_arn": "s3BucketArn",
            "kms_key_arn": "kmsKeyArn",
        },
    )
    class S3BucketLogDestinationProperty:
        def __init__(
            self,
            *,
            log_prefix: builtins.str,
            s3_bucket_arn: builtins.str,
            kms_key_arn: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Specifies an Amazon S3 bucket for logging audio conversations.

            :param log_prefix: The S3 prefix to assign to audio log files.
            :param s3_bucket_arn: The Amazon Resource Name (ARN) of an Amazon S3 bucket where audio log files are stored.
            :param kms_key_arn: The Amazon Resource Name (ARN) of an AWS Key Management Service key for encrypting audio log files stored in an S3 bucket.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-botalias-s3bucketlogdestination.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                s3_bucket_log_destination_property = lex.CfnBotAlias.S3BucketLogDestinationProperty(
                    log_prefix="logPrefix",
                    s3_bucket_arn="s3BucketArn",
                
                    # the properties below are optional
                    kms_key_arn="kmsKeyArn"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "log_prefix": log_prefix,
                "s3_bucket_arn": s3_bucket_arn,
            }
            if kms_key_arn is not None:
                self._values["kms_key_arn"] = kms_key_arn

        @builtins.property
        def log_prefix(self) -> builtins.str:
            '''The S3 prefix to assign to audio log files.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-botalias-s3bucketlogdestination.html#cfn-lex-botalias-s3bucketlogdestination-logprefix
            '''
            result = self._values.get("log_prefix")
            assert result is not None, "Required property 'log_prefix' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def s3_bucket_arn(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of an Amazon S3 bucket where audio log files are stored.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-botalias-s3bucketlogdestination.html#cfn-lex-botalias-s3bucketlogdestination-s3bucketarn
            '''
            result = self._values.get("s3_bucket_arn")
            assert result is not None, "Required property 's3_bucket_arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def kms_key_arn(self) -> typing.Optional[builtins.str]:
            '''The Amazon Resource Name (ARN) of an AWS Key Management Service key for encrypting audio log files stored in an S3 bucket.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-botalias-s3bucketlogdestination.html#cfn-lex-botalias-s3bucketlogdestination-kmskeyarn
            '''
            result = self._values.get("kms_key_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "S3BucketLogDestinationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBotAlias.TextLogDestinationProperty",
        jsii_struct_bases=[],
        name_mapping={},
    )
    class TextLogDestinationProperty:
        def __init__(self) -> None:
            '''Defines the Amazon CloudWatch Logs destination log group for conversation text logs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-botalias-textlogdestination.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                text_log_destination_property = lex.CfnBotAlias.TextLogDestinationProperty()
            '''
            self._values: typing.Dict[str, typing.Any] = {}

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TextLogDestinationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBotAlias.TextLogSettingProperty",
        jsii_struct_bases=[],
        name_mapping={"destination": "destination", "enabled": "enabled"},
    )
    class TextLogSettingProperty:
        def __init__(
            self,
            *,
            destination: typing.Optional[typing.Union["CfnBotAlias.TextLogDestinationProperty", _IResolvable_da3f097b]] = None,
            enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Defines settings to enable conversation logs.

            :param destination: Defines the Amazon CloudWatch Logs destination log group for conversation text logs.
            :param enabled: Determines whether conversation logs should be stored for an alias.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-botalias-textlogsetting.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                text_log_setting_property = lex.CfnBotAlias.TextLogSettingProperty(
                    destination=lex.CfnBotAlias.TextLogDestinationProperty(),
                    enabled=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if destination is not None:
                self._values["destination"] = destination
            if enabled is not None:
                self._values["enabled"] = enabled

        @builtins.property
        def destination(
            self,
        ) -> typing.Optional[typing.Union["CfnBotAlias.TextLogDestinationProperty", _IResolvable_da3f097b]]:
            '''Defines the Amazon CloudWatch Logs destination log group for conversation text logs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-botalias-textlogsetting.html#cfn-lex-botalias-textlogsetting-destination
            '''
            result = self._values.get("destination")
            return typing.cast(typing.Optional[typing.Union["CfnBotAlias.TextLogDestinationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def enabled(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Determines whether conversation logs should be stored for an alias.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-botalias-textlogsetting.html#cfn-lex-botalias-textlogsetting-enabled
            '''
            result = self._values.get("enabled")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TextLogSettingProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_lex.CfnBotAliasProps",
    jsii_struct_bases=[],
    name_mapping={
        "bot_alias_name": "botAliasName",
        "bot_id": "botId",
        "bot_alias_locale_settings": "botAliasLocaleSettings",
        "bot_alias_tags": "botAliasTags",
        "bot_version": "botVersion",
        "conversation_log_settings": "conversationLogSettings",
        "description": "description",
        "sentiment_analysis_settings": "sentimentAnalysisSettings",
    },
)
class CfnBotAliasProps:
    def __init__(
        self,
        *,
        bot_alias_name: builtins.str,
        bot_id: builtins.str,
        bot_alias_locale_settings: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnBotAlias.BotAliasLocaleSettingsItemProperty, _IResolvable_da3f097b]]]] = None,
        bot_alias_tags: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]] = None,
        bot_version: typing.Optional[builtins.str] = None,
        conversation_log_settings: typing.Optional[typing.Union[CfnBotAlias.ConversationLogSettingsProperty, _IResolvable_da3f097b]] = None,
        description: typing.Optional[builtins.str] = None,
        sentiment_analysis_settings: typing.Any = None,
    ) -> None:
        '''Properties for defining a ``CfnBotAlias``.

        :param bot_alias_name: The name of the bot alias.
        :param bot_id: The unique identifier of the bot.
        :param bot_alias_locale_settings: Maps configuration information to a specific locale. You can use this parameter to specify a specific Lambda function to run different functions in different locales.
        :param bot_alias_tags: An array of key-value pairs to apply to this resource. You can only add tags when you specify an alias. For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .
        :param bot_version: The version of the bot that the bot alias references.
        :param conversation_log_settings: Specifies whether Amazon Lex logs text and audio for conversations with the bot. When you enable conversation logs, text logs store text input, transcripts of audio input, and associated metadata in Amazon CloudWatch logs. Audio logs store input in Amazon S3 .
        :param description: The description of the bot alias.
        :param sentiment_analysis_settings: Determines whether Amazon Lex will use Amazon Comprehend to detect the sentiment of user utterances.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-botalias.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_lex as lex
            
            # sentiment_analysis_settings: Any
            
            cfn_bot_alias_props = lex.CfnBotAliasProps(
                bot_alias_name="botAliasName",
                bot_id="botId",
            
                # the properties below are optional
                bot_alias_locale_settings=[lex.CfnBotAlias.BotAliasLocaleSettingsItemProperty(
                    bot_alias_locale_setting=lex.CfnBotAlias.BotAliasLocaleSettingsProperty(
                        enabled=False,
            
                        # the properties below are optional
                        code_hook_specification=lex.CfnBotAlias.CodeHookSpecificationProperty(
                            lambda_code_hook=lex.CfnBotAlias.LambdaCodeHookProperty(
                                code_hook_interface_version="codeHookInterfaceVersion",
                                lambda_arn="lambdaArn"
                            )
                        )
                    ),
                    locale_id="localeId"
                )],
                bot_alias_tags=[CfnTag(
                    key="key",
                    value="value"
                )],
                bot_version="botVersion",
                conversation_log_settings=lex.CfnBotAlias.ConversationLogSettingsProperty(
                    audio_log_settings=[lex.CfnBotAlias.AudioLogSettingProperty(
                        destination=lex.CfnBotAlias.AudioLogDestinationProperty(
                            s3_bucket=lex.CfnBotAlias.S3BucketLogDestinationProperty(
                                log_prefix="logPrefix",
                                s3_bucket_arn="s3BucketArn",
            
                                # the properties below are optional
                                kms_key_arn="kmsKeyArn"
                            )
                        ),
                        enabled=False
                    )],
                    text_log_settings=[lex.CfnBotAlias.TextLogSettingProperty(
                        destination=lex.CfnBotAlias.TextLogDestinationProperty(),
                        enabled=False
                    )]
                ),
                description="description",
                sentiment_analysis_settings=sentiment_analysis_settings
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "bot_alias_name": bot_alias_name,
            "bot_id": bot_id,
        }
        if bot_alias_locale_settings is not None:
            self._values["bot_alias_locale_settings"] = bot_alias_locale_settings
        if bot_alias_tags is not None:
            self._values["bot_alias_tags"] = bot_alias_tags
        if bot_version is not None:
            self._values["bot_version"] = bot_version
        if conversation_log_settings is not None:
            self._values["conversation_log_settings"] = conversation_log_settings
        if description is not None:
            self._values["description"] = description
        if sentiment_analysis_settings is not None:
            self._values["sentiment_analysis_settings"] = sentiment_analysis_settings

    @builtins.property
    def bot_alias_name(self) -> builtins.str:
        '''The name of the bot alias.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-botalias.html#cfn-lex-botalias-botaliasname
        '''
        result = self._values.get("bot_alias_name")
        assert result is not None, "Required property 'bot_alias_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def bot_id(self) -> builtins.str:
        '''The unique identifier of the bot.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-botalias.html#cfn-lex-botalias-botid
        '''
        result = self._values.get("bot_id")
        assert result is not None, "Required property 'bot_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def bot_alias_locale_settings(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnBotAlias.BotAliasLocaleSettingsItemProperty, _IResolvable_da3f097b]]]]:
        '''Maps configuration information to a specific locale.

        You can use this parameter to specify a specific Lambda function to run different functions in different locales.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-botalias.html#cfn-lex-botalias-botaliaslocalesettings
        '''
        result = self._values.get("bot_alias_locale_settings")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnBotAlias.BotAliasLocaleSettingsItemProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def bot_alias_tags(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]]:
        '''An array of key-value pairs to apply to this resource.

        You can only add tags when you specify an alias.

        For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-botalias.html#cfn-lex-botalias-botaliastags
        '''
        result = self._values.get("bot_alias_tags")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]], result)

    @builtins.property
    def bot_version(self) -> typing.Optional[builtins.str]:
        '''The version of the bot that the bot alias references.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-botalias.html#cfn-lex-botalias-botversion
        '''
        result = self._values.get("bot_version")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def conversation_log_settings(
        self,
    ) -> typing.Optional[typing.Union[CfnBotAlias.ConversationLogSettingsProperty, _IResolvable_da3f097b]]:
        '''Specifies whether Amazon Lex logs text and audio for conversations with the bot.

        When you enable conversation logs, text logs store text input, transcripts of audio input, and associated metadata in Amazon CloudWatch logs. Audio logs store input in Amazon S3 .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-botalias.html#cfn-lex-botalias-conversationlogsettings
        '''
        result = self._values.get("conversation_log_settings")
        return typing.cast(typing.Optional[typing.Union[CfnBotAlias.ConversationLogSettingsProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the bot alias.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-botalias.html#cfn-lex-botalias-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def sentiment_analysis_settings(self) -> typing.Any:
        '''Determines whether Amazon Lex will use Amazon Comprehend to detect the sentiment of user utterances.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-botalias.html#cfn-lex-botalias-sentimentanalysissettings
        '''
        result = self._values.get("sentiment_analysis_settings")
        return typing.cast(typing.Any, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnBotAliasProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_lex.CfnBotProps",
    jsii_struct_bases=[],
    name_mapping={
        "data_privacy": "dataPrivacy",
        "idle_session_ttl_in_seconds": "idleSessionTtlInSeconds",
        "name": "name",
        "role_arn": "roleArn",
        "auto_build_bot_locales": "autoBuildBotLocales",
        "bot_file_s3_location": "botFileS3Location",
        "bot_locales": "botLocales",
        "bot_tags": "botTags",
        "description": "description",
        "test_bot_alias_tags": "testBotAliasTags",
    },
)
class CfnBotProps:
    def __init__(
        self,
        *,
        data_privacy: typing.Any,
        idle_session_ttl_in_seconds: jsii.Number,
        name: builtins.str,
        role_arn: builtins.str,
        auto_build_bot_locales: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        bot_file_s3_location: typing.Optional[typing.Union[CfnBot.S3LocationProperty, _IResolvable_da3f097b]] = None,
        bot_locales: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnBot.BotLocaleProperty, _IResolvable_da3f097b]]]] = None,
        bot_tags: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]] = None,
        description: typing.Optional[builtins.str] = None,
        test_bot_alias_tags: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]] = None,
    ) -> None:
        '''Properties for defining a ``CfnBot``.

        :param data_privacy: Provides information on additional privacy protections Amazon Lex should use with the bot's data.
        :param idle_session_ttl_in_seconds: The time, in seconds, that Amazon Lex should keep information about a user's conversation with the bot. A user interaction remains active for the amount of time specified. If no conversation occurs during this time, the session expires and Amazon Lex deletes any data provided before the timeout. You can specify between 60 (1 minute) and 86,400 (24 hours) seconds.
        :param name: The name of the field to filter the list of bots.
        :param role_arn: The Amazon Resource Name (ARN) of the IAM role used to build and run the bot.
        :param auto_build_bot_locales: Indicates whether Amazon Lex V2 should automatically build the locales for the bot after a change.
        :param bot_file_s3_location: The Amazon S3 location of files used to import a bot. The files must be in the import format specified in `JSON format for importing and exporting <https://docs.aws.amazon.com/lexv2/latest/dg/import-export-format.html>`_ in the *Amazon Lex developer guide.*
        :param bot_locales: A list of locales for the bot.
        :param bot_tags: A list of tags to add to the bot. You can only add tags when you import a bot. You can't use the ``UpdateBot`` operation to update tags. To update tags, use the ``TagResource`` operation.
        :param description: The description of the version.
        :param test_bot_alias_tags: A list of tags to add to the test alias for a bot. You can only add tags when you import a bot. You can't use the ``UpdateAlias`` operation to update tags. To update tags on the test alias, use the ``TagResource`` operation.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-bot.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_lex as lex
            
            # data_privacy: Any
            
            cfn_bot_props = lex.CfnBotProps(
                data_privacy=data_privacy,
                idle_session_ttl_in_seconds=123,
                name="name",
                role_arn="roleArn",
            
                # the properties below are optional
                auto_build_bot_locales=False,
                bot_file_s3_location=lex.CfnBot.S3LocationProperty(
                    s3_bucket="s3Bucket",
                    s3_object_key="s3ObjectKey",
            
                    # the properties below are optional
                    s3_object_version="s3ObjectVersion"
                ),
                bot_locales=[lex.CfnBot.BotLocaleProperty(
                    locale_id="localeId",
                    nlu_confidence_threshold=123,
            
                    # the properties below are optional
                    description="description",
                    intents=[lex.CfnBot.IntentProperty(
                        name="name",
            
                        # the properties below are optional
                        description="description",
                        dialog_code_hook=lex.CfnBot.DialogCodeHookSettingProperty(
                            enabled=False
                        ),
                        fulfillment_code_hook=lex.CfnBot.FulfillmentCodeHookSettingProperty(
                            enabled=False,
            
                            # the properties below are optional
                            fulfillment_updates_specification=lex.CfnBot.FulfillmentUpdatesSpecificationProperty(
                                active=False,
            
                                # the properties below are optional
                                start_response=lex.CfnBot.FulfillmentStartResponseSpecificationProperty(
                                    delay_in_seconds=123,
                                    message_groups=[lex.CfnBot.MessageGroupProperty(
                                        message=lex.CfnBot.MessageProperty(
                                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                value="value"
                                            ),
                                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                title="title",
            
                                                # the properties below are optional
                                                buttons=[lex.CfnBot.ButtonProperty(
                                                    text="text",
                                                    value="value"
                                                )],
                                                image_url="imageUrl",
                                                subtitle="subtitle"
                                            ),
                                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                value="value"
                                            ),
                                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                value="value"
                                            )
                                        ),
            
                                        # the properties below are optional
                                        variations=[lex.CfnBot.MessageProperty(
                                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                value="value"
                                            ),
                                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                title="title",
            
                                                # the properties below are optional
                                                buttons=[lex.CfnBot.ButtonProperty(
                                                    text="text",
                                                    value="value"
                                                )],
                                                image_url="imageUrl",
                                                subtitle="subtitle"
                                            ),
                                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                value="value"
                                            ),
                                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                value="value"
                                            )
                                        )]
                                    )],
            
                                    # the properties below are optional
                                    allow_interrupt=False
                                ),
                                timeout_in_seconds=123,
                                update_response=lex.CfnBot.FulfillmentUpdateResponseSpecificationProperty(
                                    frequency_in_seconds=123,
                                    message_groups=[lex.CfnBot.MessageGroupProperty(
                                        message=lex.CfnBot.MessageProperty(
                                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                value="value"
                                            ),
                                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                title="title",
            
                                                # the properties below are optional
                                                buttons=[lex.CfnBot.ButtonProperty(
                                                    text="text",
                                                    value="value"
                                                )],
                                                image_url="imageUrl",
                                                subtitle="subtitle"
                                            ),
                                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                value="value"
                                            ),
                                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                value="value"
                                            )
                                        ),
            
                                        # the properties below are optional
                                        variations=[lex.CfnBot.MessageProperty(
                                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                value="value"
                                            ),
                                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                title="title",
            
                                                # the properties below are optional
                                                buttons=[lex.CfnBot.ButtonProperty(
                                                    text="text",
                                                    value="value"
                                                )],
                                                image_url="imageUrl",
                                                subtitle="subtitle"
                                            ),
                                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                value="value"
                                            ),
                                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                value="value"
                                            )
                                        )]
                                    )],
            
                                    # the properties below are optional
                                    allow_interrupt=False
                                )
                            ),
                            post_fulfillment_status_specification=lex.CfnBot.PostFulfillmentStatusSpecificationProperty(
                                failure_response=lex.CfnBot.ResponseSpecificationProperty(
                                    message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                        message=lex.CfnBot.MessageProperty(
                                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                value="value"
                                            ),
                                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                title="title",
            
                                                # the properties below are optional
                                                buttons=[lex.CfnBot.ButtonProperty(
                                                    text="text",
                                                    value="value"
                                                )],
                                                image_url="imageUrl",
                                                subtitle="subtitle"
                                            ),
                                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                value="value"
                                            ),
                                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                value="value"
                                            )
                                        ),
            
                                        # the properties below are optional
                                        variations=[lex.CfnBot.MessageProperty(
                                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                value="value"
                                            ),
                                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                title="title",
            
                                                # the properties below are optional
                                                buttons=[lex.CfnBot.ButtonProperty(
                                                    text="text",
                                                    value="value"
                                                )],
                                                image_url="imageUrl",
                                                subtitle="subtitle"
                                            ),
                                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                value="value"
                                            ),
                                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                value="value"
                                            )
                                        )]
                                    )],
            
                                    # the properties below are optional
                                    allow_interrupt=False
                                ),
                                success_response=lex.CfnBot.ResponseSpecificationProperty(
                                    message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                        message=lex.CfnBot.MessageProperty(
                                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                value="value"
                                            ),
                                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                title="title",
            
                                                # the properties below are optional
                                                buttons=[lex.CfnBot.ButtonProperty(
                                                    text="text",
                                                    value="value"
                                                )],
                                                image_url="imageUrl",
                                                subtitle="subtitle"
                                            ),
                                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                value="value"
                                            ),
                                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                value="value"
                                            )
                                        ),
            
                                        # the properties below are optional
                                        variations=[lex.CfnBot.MessageProperty(
                                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                value="value"
                                            ),
                                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                title="title",
            
                                                # the properties below are optional
                                                buttons=[lex.CfnBot.ButtonProperty(
                                                    text="text",
                                                    value="value"
                                                )],
                                                image_url="imageUrl",
                                                subtitle="subtitle"
                                            ),
                                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                value="value"
                                            ),
                                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                value="value"
                                            )
                                        )]
                                    )],
            
                                    # the properties below are optional
                                    allow_interrupt=False
                                ),
                                timeout_response=lex.CfnBot.ResponseSpecificationProperty(
                                    message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                        message=lex.CfnBot.MessageProperty(
                                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                value="value"
                                            ),
                                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                title="title",
            
                                                # the properties below are optional
                                                buttons=[lex.CfnBot.ButtonProperty(
                                                    text="text",
                                                    value="value"
                                                )],
                                                image_url="imageUrl",
                                                subtitle="subtitle"
                                            ),
                                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                value="value"
                                            ),
                                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                value="value"
                                            )
                                        ),
            
                                        # the properties below are optional
                                        variations=[lex.CfnBot.MessageProperty(
                                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                value="value"
                                            ),
                                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                title="title",
            
                                                # the properties below are optional
                                                buttons=[lex.CfnBot.ButtonProperty(
                                                    text="text",
                                                    value="value"
                                                )],
                                                image_url="imageUrl",
                                                subtitle="subtitle"
                                            ),
                                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                value="value"
                                            ),
                                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                value="value"
                                            )
                                        )]
                                    )],
            
                                    # the properties below are optional
                                    allow_interrupt=False
                                )
                            )
                        ),
                        input_contexts=[lex.CfnBot.InputContextProperty(
                            name="name"
                        )],
                        intent_closing_setting=lex.CfnBot.IntentClosingSettingProperty(
                            closing_response=lex.CfnBot.ResponseSpecificationProperty(
                                message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                    message=lex.CfnBot.MessageProperty(
                                        custom_payload=lex.CfnBot.CustomPayloadProperty(
                                            value="value"
                                        ),
                                        image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                            title="title",
            
                                            # the properties below are optional
                                            buttons=[lex.CfnBot.ButtonProperty(
                                                text="text",
                                                value="value"
                                            )],
                                            image_url="imageUrl",
                                            subtitle="subtitle"
                                        ),
                                        plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                            value="value"
                                        ),
                                        ssml_message=lex.CfnBot.SSMLMessageProperty(
                                            value="value"
                                        )
                                    ),
            
                                    # the properties below are optional
                                    variations=[lex.CfnBot.MessageProperty(
                                        custom_payload=lex.CfnBot.CustomPayloadProperty(
                                            value="value"
                                        ),
                                        image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                            title="title",
            
                                            # the properties below are optional
                                            buttons=[lex.CfnBot.ButtonProperty(
                                                text="text",
                                                value="value"
                                            )],
                                            image_url="imageUrl",
                                            subtitle="subtitle"
                                        ),
                                        plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                            value="value"
                                        ),
                                        ssml_message=lex.CfnBot.SSMLMessageProperty(
                                            value="value"
                                        )
                                    )]
                                )],
            
                                # the properties below are optional
                                allow_interrupt=False
                            ),
            
                            # the properties below are optional
                            is_active=False
                        ),
                        intent_confirmation_setting=lex.CfnBot.IntentConfirmationSettingProperty(
                            declination_response=lex.CfnBot.ResponseSpecificationProperty(
                                message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                    message=lex.CfnBot.MessageProperty(
                                        custom_payload=lex.CfnBot.CustomPayloadProperty(
                                            value="value"
                                        ),
                                        image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                            title="title",
            
                                            # the properties below are optional
                                            buttons=[lex.CfnBot.ButtonProperty(
                                                text="text",
                                                value="value"
                                            )],
                                            image_url="imageUrl",
                                            subtitle="subtitle"
                                        ),
                                        plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                            value="value"
                                        ),
                                        ssml_message=lex.CfnBot.SSMLMessageProperty(
                                            value="value"
                                        )
                                    ),
            
                                    # the properties below are optional
                                    variations=[lex.CfnBot.MessageProperty(
                                        custom_payload=lex.CfnBot.CustomPayloadProperty(
                                            value="value"
                                        ),
                                        image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                            title="title",
            
                                            # the properties below are optional
                                            buttons=[lex.CfnBot.ButtonProperty(
                                                text="text",
                                                value="value"
                                            )],
                                            image_url="imageUrl",
                                            subtitle="subtitle"
                                        ),
                                        plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                            value="value"
                                        ),
                                        ssml_message=lex.CfnBot.SSMLMessageProperty(
                                            value="value"
                                        )
                                    )]
                                )],
            
                                # the properties below are optional
                                allow_interrupt=False
                            ),
                            prompt_specification=lex.CfnBot.PromptSpecificationProperty(
                                max_retries=123,
                                message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                    message=lex.CfnBot.MessageProperty(
                                        custom_payload=lex.CfnBot.CustomPayloadProperty(
                                            value="value"
                                        ),
                                        image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                            title="title",
            
                                            # the properties below are optional
                                            buttons=[lex.CfnBot.ButtonProperty(
                                                text="text",
                                                value="value"
                                            )],
                                            image_url="imageUrl",
                                            subtitle="subtitle"
                                        ),
                                        plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                            value="value"
                                        ),
                                        ssml_message=lex.CfnBot.SSMLMessageProperty(
                                            value="value"
                                        )
                                    ),
            
                                    # the properties below are optional
                                    variations=[lex.CfnBot.MessageProperty(
                                        custom_payload=lex.CfnBot.CustomPayloadProperty(
                                            value="value"
                                        ),
                                        image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                            title="title",
            
                                            # the properties below are optional
                                            buttons=[lex.CfnBot.ButtonProperty(
                                                text="text",
                                                value="value"
                                            )],
                                            image_url="imageUrl",
                                            subtitle="subtitle"
                                        ),
                                        plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                            value="value"
                                        ),
                                        ssml_message=lex.CfnBot.SSMLMessageProperty(
                                            value="value"
                                        )
                                    )]
                                )],
            
                                # the properties below are optional
                                allow_interrupt=False
                            ),
            
                            # the properties below are optional
                            is_active=False
                        ),
                        kendra_configuration=lex.CfnBot.KendraConfigurationProperty(
                            kendra_index="kendraIndex",
            
                            # the properties below are optional
                            query_filter_string="queryFilterString",
                            query_filter_string_enabled=False
                        ),
                        output_contexts=[lex.CfnBot.OutputContextProperty(
                            name="name",
                            time_to_live_in_seconds=123,
                            turns_to_live=123
                        )],
                        parent_intent_signature="parentIntentSignature",
                        sample_utterances=[lex.CfnBot.SampleUtteranceProperty(
                            utterance="utterance"
                        )],
                        slot_priorities=[lex.CfnBot.SlotPriorityProperty(
                            priority=123,
                            slot_name="slotName"
                        )],
                        slots=[lex.CfnBot.SlotProperty(
                            name="name",
                            slot_type_name="slotTypeName",
                            value_elicitation_setting=lex.CfnBot.SlotValueElicitationSettingProperty(
                                slot_constraint="slotConstraint",
            
                                # the properties below are optional
                                default_value_specification=lex.CfnBot.SlotDefaultValueSpecificationProperty(
                                    default_value_list=[lex.CfnBot.SlotDefaultValueProperty(
                                        default_value="defaultValue"
                                    )]
                                ),
                                prompt_specification=lex.CfnBot.PromptSpecificationProperty(
                                    max_retries=123,
                                    message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                        message=lex.CfnBot.MessageProperty(
                                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                value="value"
                                            ),
                                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                title="title",
            
                                                # the properties below are optional
                                                buttons=[lex.CfnBot.ButtonProperty(
                                                    text="text",
                                                    value="value"
                                                )],
                                                image_url="imageUrl",
                                                subtitle="subtitle"
                                            ),
                                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                value="value"
                                            ),
                                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                value="value"
                                            )
                                        ),
            
                                        # the properties below are optional
                                        variations=[lex.CfnBot.MessageProperty(
                                            custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                value="value"
                                            ),
                                            image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                title="title",
            
                                                # the properties below are optional
                                                buttons=[lex.CfnBot.ButtonProperty(
                                                    text="text",
                                                    value="value"
                                                )],
                                                image_url="imageUrl",
                                                subtitle="subtitle"
                                            ),
                                            plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                value="value"
                                            ),
                                            ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                value="value"
                                            )
                                        )]
                                    )],
            
                                    # the properties below are optional
                                    allow_interrupt=False
                                ),
                                sample_utterances=[lex.CfnBot.SampleUtteranceProperty(
                                    utterance="utterance"
                                )],
                                wait_and_continue_specification=lex.CfnBot.WaitAndContinueSpecificationProperty(
                                    continue_response=lex.CfnBot.ResponseSpecificationProperty(
                                        message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                            message=lex.CfnBot.MessageProperty(
                                                custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                    value="value"
                                                ),
                                                image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                    title="title",
            
                                                    # the properties below are optional
                                                    buttons=[lex.CfnBot.ButtonProperty(
                                                        text="text",
                                                        value="value"
                                                    )],
                                                    image_url="imageUrl",
                                                    subtitle="subtitle"
                                                ),
                                                plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                    value="value"
                                                ),
                                                ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                    value="value"
                                                )
                                            ),
            
                                            # the properties below are optional
                                            variations=[lex.CfnBot.MessageProperty(
                                                custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                    value="value"
                                                ),
                                                image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                    title="title",
            
                                                    # the properties below are optional
                                                    buttons=[lex.CfnBot.ButtonProperty(
                                                        text="text",
                                                        value="value"
                                                    )],
                                                    image_url="imageUrl",
                                                    subtitle="subtitle"
                                                ),
                                                plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                    value="value"
                                                ),
                                                ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                    value="value"
                                                )
                                            )]
                                        )],
            
                                        # the properties below are optional
                                        allow_interrupt=False
                                    ),
                                    waiting_response=lex.CfnBot.ResponseSpecificationProperty(
                                        message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                            message=lex.CfnBot.MessageProperty(
                                                custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                    value="value"
                                                ),
                                                image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                    title="title",
            
                                                    # the properties below are optional
                                                    buttons=[lex.CfnBot.ButtonProperty(
                                                        text="text",
                                                        value="value"
                                                    )],
                                                    image_url="imageUrl",
                                                    subtitle="subtitle"
                                                ),
                                                plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                    value="value"
                                                ),
                                                ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                    value="value"
                                                )
                                            ),
            
                                            # the properties below are optional
                                            variations=[lex.CfnBot.MessageProperty(
                                                custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                    value="value"
                                                ),
                                                image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                    title="title",
            
                                                    # the properties below are optional
                                                    buttons=[lex.CfnBot.ButtonProperty(
                                                        text="text",
                                                        value="value"
                                                    )],
                                                    image_url="imageUrl",
                                                    subtitle="subtitle"
                                                ),
                                                plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                    value="value"
                                                ),
                                                ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                    value="value"
                                                )
                                            )]
                                        )],
            
                                        # the properties below are optional
                                        allow_interrupt=False
                                    ),
            
                                    # the properties below are optional
                                    is_active=False,
                                    still_waiting_response=lex.CfnBot.StillWaitingResponseSpecificationProperty(
                                        frequency_in_seconds=123,
                                        message_groups_list=[lex.CfnBot.MessageGroupProperty(
                                            message=lex.CfnBot.MessageProperty(
                                                custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                    value="value"
                                                ),
                                                image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                    title="title",
            
                                                    # the properties below are optional
                                                    buttons=[lex.CfnBot.ButtonProperty(
                                                        text="text",
                                                        value="value"
                                                    )],
                                                    image_url="imageUrl",
                                                    subtitle="subtitle"
                                                ),
                                                plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                    value="value"
                                                ),
                                                ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                    value="value"
                                                )
                                            ),
            
                                            # the properties below are optional
                                            variations=[lex.CfnBot.MessageProperty(
                                                custom_payload=lex.CfnBot.CustomPayloadProperty(
                                                    value="value"
                                                ),
                                                image_response_card=lex.CfnBot.ImageResponseCardProperty(
                                                    title="title",
            
                                                    # the properties below are optional
                                                    buttons=[lex.CfnBot.ButtonProperty(
                                                        text="text",
                                                        value="value"
                                                    )],
                                                    image_url="imageUrl",
                                                    subtitle="subtitle"
                                                ),
                                                plain_text_message=lex.CfnBot.PlainTextMessageProperty(
                                                    value="value"
                                                ),
                                                ssml_message=lex.CfnBot.SSMLMessageProperty(
                                                    value="value"
                                                )
                                            )]
                                        )],
                                        timeout_in_seconds=123,
            
                                        # the properties below are optional
                                        allow_interrupt=False
                                    )
                                )
                            ),
            
                            # the properties below are optional
                            description="description",
                            multiple_values_setting=lex.CfnBot.MultipleValuesSettingProperty(
                                allow_multiple_values=False
                            ),
                            obfuscation_setting=lex.CfnBot.ObfuscationSettingProperty(
                                obfuscation_setting_type="obfuscationSettingType"
                            )
                        )]
                    )],
                    slot_types=[lex.CfnBot.SlotTypeProperty(
                        name="name",
            
                        # the properties below are optional
                        description="description",
                        external_source_setting=lex.CfnBot.ExternalSourceSettingProperty(
                            grammar_slot_type_setting=lex.CfnBot.GrammarSlotTypeSettingProperty(
                                source=lex.CfnBot.GrammarSlotTypeSourceProperty(
                                    s3_bucket_name="s3BucketName",
                                    s3_object_key="s3ObjectKey",
            
                                    # the properties below are optional
                                    kms_key_arn="kmsKeyArn"
                                )
                            )
                        ),
                        parent_slot_type_signature="parentSlotTypeSignature",
                        slot_type_values=[lex.CfnBot.SlotTypeValueProperty(
                            sample_value=lex.CfnBot.SampleValueProperty(
                                value="value"
                            ),
            
                            # the properties below are optional
                            synonyms=[lex.CfnBot.SampleValueProperty(
                                value="value"
                            )]
                        )],
                        value_selection_setting=lex.CfnBot.SlotValueSelectionSettingProperty(
                            resolution_strategy="resolutionStrategy",
            
                            # the properties below are optional
                            regex_filter=lex.CfnBot.SlotValueRegexFilterProperty(
                                pattern="pattern"
                            )
                        )
                    )],
                    voice_settings=lex.CfnBot.VoiceSettingsProperty(
                        voice_id="voiceId"
                    )
                )],
                bot_tags=[CfnTag(
                    key="key",
                    value="value"
                )],
                description="description",
                test_bot_alias_tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "data_privacy": data_privacy,
            "idle_session_ttl_in_seconds": idle_session_ttl_in_seconds,
            "name": name,
            "role_arn": role_arn,
        }
        if auto_build_bot_locales is not None:
            self._values["auto_build_bot_locales"] = auto_build_bot_locales
        if bot_file_s3_location is not None:
            self._values["bot_file_s3_location"] = bot_file_s3_location
        if bot_locales is not None:
            self._values["bot_locales"] = bot_locales
        if bot_tags is not None:
            self._values["bot_tags"] = bot_tags
        if description is not None:
            self._values["description"] = description
        if test_bot_alias_tags is not None:
            self._values["test_bot_alias_tags"] = test_bot_alias_tags

    @builtins.property
    def data_privacy(self) -> typing.Any:
        '''Provides information on additional privacy protections Amazon Lex should use with the bot's data.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-bot.html#cfn-lex-bot-dataprivacy
        '''
        result = self._values.get("data_privacy")
        assert result is not None, "Required property 'data_privacy' is missing"
        return typing.cast(typing.Any, result)

    @builtins.property
    def idle_session_ttl_in_seconds(self) -> jsii.Number:
        '''The time, in seconds, that Amazon Lex should keep information about a user's conversation with the bot.

        A user interaction remains active for the amount of time specified. If no conversation occurs during this time, the session expires and Amazon Lex deletes any data provided before the timeout.

        You can specify between 60 (1 minute) and 86,400 (24 hours) seconds.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-bot.html#cfn-lex-bot-idlesessionttlinseconds
        '''
        result = self._values.get("idle_session_ttl_in_seconds")
        assert result is not None, "Required property 'idle_session_ttl_in_seconds' is missing"
        return typing.cast(jsii.Number, result)

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the field to filter the list of bots.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-bot.html#cfn-lex-bot-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def role_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the IAM role used to build and run the bot.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-bot.html#cfn-lex-bot-rolearn
        '''
        result = self._values.get("role_arn")
        assert result is not None, "Required property 'role_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def auto_build_bot_locales(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Indicates whether Amazon Lex V2 should automatically build the locales for the bot after a change.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-bot.html#cfn-lex-bot-autobuildbotlocales
        '''
        result = self._values.get("auto_build_bot_locales")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def bot_file_s3_location(
        self,
    ) -> typing.Optional[typing.Union[CfnBot.S3LocationProperty, _IResolvable_da3f097b]]:
        '''The Amazon S3 location of files used to import a bot.

        The files must be in the import format specified in `JSON format for importing and exporting <https://docs.aws.amazon.com/lexv2/latest/dg/import-export-format.html>`_ in the *Amazon Lex developer guide.*

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-bot.html#cfn-lex-bot-botfiles3location
        '''
        result = self._values.get("bot_file_s3_location")
        return typing.cast(typing.Optional[typing.Union[CfnBot.S3LocationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def bot_locales(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnBot.BotLocaleProperty, _IResolvable_da3f097b]]]]:
        '''A list of locales for the bot.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-bot.html#cfn-lex-bot-botlocales
        '''
        result = self._values.get("bot_locales")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnBot.BotLocaleProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def bot_tags(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]]:
        '''A list of tags to add to the bot.

        You can only add tags when you import a bot. You can't use the ``UpdateBot`` operation to update tags. To update tags, use the ``TagResource`` operation.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-bot.html#cfn-lex-bot-bottags
        '''
        result = self._values.get("bot_tags")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]], result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-bot.html#cfn-lex-bot-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def test_bot_alias_tags(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]]:
        '''A list of tags to add to the test alias for a bot.

        You can only add tags when you import a bot. You can't use the ``UpdateAlias`` operation to update tags. To update tags on the test alias, use the ``TagResource`` operation.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-bot.html#cfn-lex-bot-testbotaliastags
        '''
        result = self._values.get("test_bot_alias_tags")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnBotProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnBotVersion(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_lex.CfnBotVersion",
):
    '''A CloudFormation ``AWS::Lex::BotVersion``.

    Specifies a new version of the bot based on the ``DRAFT`` version. If the ``DRAFT`` version of this resource hasn't changed since you created the last version, Amazon Lex doesn't create a new version, it returns the last created version.

    When you specify the first version of a bot, Amazon Lex sets the version to 1. Subsequent versions increment by 1.

    :cloudformationResource: AWS::Lex::BotVersion
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-botversion.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_lex as lex
        
        cfn_bot_version = lex.CfnBotVersion(self, "MyCfnBotVersion",
            bot_id="botId",
            bot_version_locale_specification=[lex.CfnBotVersion.BotVersionLocaleSpecificationProperty(
                bot_version_locale_details=lex.CfnBotVersion.BotVersionLocaleDetailsProperty(
                    source_bot_version="sourceBotVersion"
                ),
                locale_id="localeId"
            )],
        
            # the properties below are optional
            description="description"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        bot_id: builtins.str,
        bot_version_locale_specification: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBotVersion.BotVersionLocaleSpecificationProperty", _IResolvable_da3f097b]]],
        description: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::Lex::BotVersion``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param bot_id: The unique identifier of the bot.
        :param bot_version_locale_specification: Specifies the locales that Amazon Lex adds to this version. You can choose the Draft version or any other previously published version for each locale. When you specify a source version, the locale data is copied from the source version to the new version.
        :param description: The description of the version.
        '''
        props = CfnBotVersionProps(
            bot_id=bot_id,
            bot_version_locale_specification=bot_version_locale_specification,
            description=description,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="inspect")
    def inspect(self, inspector: _TreeInspector_488e0dd5) -> None:
        '''Examines the CloudFormation resource and discloses attributes.

        :param inspector: - tree inspector to collect and process attributes.
        '''
        return typing.cast(None, jsii.invoke(self, "inspect", [inspector]))

    @jsii.member(jsii_name="renderProperties")
    def _render_properties(
        self,
        props: typing.Mapping[builtins.str, typing.Any],
    ) -> typing.Mapping[builtins.str, typing.Any]:
        '''
        :param props: -
        '''
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.invoke(self, "renderProperties", [props]))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="CFN_RESOURCE_TYPE_NAME")
    def CFN_RESOURCE_TYPE_NAME(cls) -> builtins.str:
        '''The CloudFormation resource type name for this resource class.'''
        return typing.cast(builtins.str, jsii.sget(cls, "CFN_RESOURCE_TYPE_NAME"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrBotVersion")
    def attr_bot_version(self) -> builtins.str:
        '''The version of the bot.

        :cloudformationAttribute: BotVersion
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrBotVersion"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="botId")
    def bot_id(self) -> builtins.str:
        '''The unique identifier of the bot.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-botversion.html#cfn-lex-botversion-botid
        '''
        return typing.cast(builtins.str, jsii.get(self, "botId"))

    @bot_id.setter
    def bot_id(self, value: builtins.str) -> None:
        jsii.set(self, "botId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="botVersionLocaleSpecification")
    def bot_version_locale_specification(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBotVersion.BotVersionLocaleSpecificationProperty", _IResolvable_da3f097b]]]:
        '''Specifies the locales that Amazon Lex adds to this version.

        You can choose the Draft version or any other previously published version for each locale. When you specify a source version, the locale data is copied from the source version to the new version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-botversion.html#cfn-lex-botversion-botversionlocalespecification
        '''
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBotVersion.BotVersionLocaleSpecificationProperty", _IResolvable_da3f097b]]], jsii.get(self, "botVersionLocaleSpecification"))

    @bot_version_locale_specification.setter
    def bot_version_locale_specification(
        self,
        value: typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBotVersion.BotVersionLocaleSpecificationProperty", _IResolvable_da3f097b]]],
    ) -> None:
        jsii.set(self, "botVersionLocaleSpecification", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-botversion.html#cfn-lex-botversion-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBotVersion.BotVersionLocaleDetailsProperty",
        jsii_struct_bases=[],
        name_mapping={"source_bot_version": "sourceBotVersion"},
    )
    class BotVersionLocaleDetailsProperty:
        def __init__(self, *, source_bot_version: builtins.str) -> None:
            '''The version of a bot used for a bot locale.

            :param source_bot_version: The version of a bot used for a bot locale.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-botversion-botversionlocaledetails.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                bot_version_locale_details_property = lex.CfnBotVersion.BotVersionLocaleDetailsProperty(
                    source_bot_version="sourceBotVersion"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "source_bot_version": source_bot_version,
            }

        @builtins.property
        def source_bot_version(self) -> builtins.str:
            '''The version of a bot used for a bot locale.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-botversion-botversionlocaledetails.html#cfn-lex-botversion-botversionlocaledetails-sourcebotversion
            '''
            result = self._values.get("source_bot_version")
            assert result is not None, "Required property 'source_bot_version' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "BotVersionLocaleDetailsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lex.CfnBotVersion.BotVersionLocaleSpecificationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "bot_version_locale_details": "botVersionLocaleDetails",
            "locale_id": "localeId",
        },
    )
    class BotVersionLocaleSpecificationProperty:
        def __init__(
            self,
            *,
            bot_version_locale_details: typing.Union["CfnBotVersion.BotVersionLocaleDetailsProperty", _IResolvable_da3f097b],
            locale_id: builtins.str,
        ) -> None:
            '''Specifies the locale that Amazon Lex adds to this version.

            You can choose the Draft version or any other previously published version for each locale. When you specify a source version, the locale data is copied from the source version to the new version.

            :param bot_version_locale_details: The version of a bot used for a bot locale.
            :param locale_id: The identifier of the locale to add to the version.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-botversion-botversionlocalespecification.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lex as lex
                
                bot_version_locale_specification_property = lex.CfnBotVersion.BotVersionLocaleSpecificationProperty(
                    bot_version_locale_details=lex.CfnBotVersion.BotVersionLocaleDetailsProperty(
                        source_bot_version="sourceBotVersion"
                    ),
                    locale_id="localeId"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "bot_version_locale_details": bot_version_locale_details,
                "locale_id": locale_id,
            }

        @builtins.property
        def bot_version_locale_details(
            self,
        ) -> typing.Union["CfnBotVersion.BotVersionLocaleDetailsProperty", _IResolvable_da3f097b]:
            '''The version of a bot used for a bot locale.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-botversion-botversionlocalespecification.html#cfn-lex-botversion-botversionlocalespecification-botversionlocaledetails
            '''
            result = self._values.get("bot_version_locale_details")
            assert result is not None, "Required property 'bot_version_locale_details' is missing"
            return typing.cast(typing.Union["CfnBotVersion.BotVersionLocaleDetailsProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def locale_id(self) -> builtins.str:
            '''The identifier of the locale to add to the version.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lex-botversion-botversionlocalespecification.html#cfn-lex-botversion-botversionlocalespecification-localeid
            '''
            result = self._values.get("locale_id")
            assert result is not None, "Required property 'locale_id' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "BotVersionLocaleSpecificationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_lex.CfnBotVersionProps",
    jsii_struct_bases=[],
    name_mapping={
        "bot_id": "botId",
        "bot_version_locale_specification": "botVersionLocaleSpecification",
        "description": "description",
    },
)
class CfnBotVersionProps:
    def __init__(
        self,
        *,
        bot_id: builtins.str,
        bot_version_locale_specification: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnBotVersion.BotVersionLocaleSpecificationProperty, _IResolvable_da3f097b]]],
        description: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnBotVersion``.

        :param bot_id: The unique identifier of the bot.
        :param bot_version_locale_specification: Specifies the locales that Amazon Lex adds to this version. You can choose the Draft version or any other previously published version for each locale. When you specify a source version, the locale data is copied from the source version to the new version.
        :param description: The description of the version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-botversion.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_lex as lex
            
            cfn_bot_version_props = lex.CfnBotVersionProps(
                bot_id="botId",
                bot_version_locale_specification=[lex.CfnBotVersion.BotVersionLocaleSpecificationProperty(
                    bot_version_locale_details=lex.CfnBotVersion.BotVersionLocaleDetailsProperty(
                        source_bot_version="sourceBotVersion"
                    ),
                    locale_id="localeId"
                )],
            
                # the properties below are optional
                description="description"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "bot_id": bot_id,
            "bot_version_locale_specification": bot_version_locale_specification,
        }
        if description is not None:
            self._values["description"] = description

    @builtins.property
    def bot_id(self) -> builtins.str:
        '''The unique identifier of the bot.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-botversion.html#cfn-lex-botversion-botid
        '''
        result = self._values.get("bot_id")
        assert result is not None, "Required property 'bot_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def bot_version_locale_specification(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnBotVersion.BotVersionLocaleSpecificationProperty, _IResolvable_da3f097b]]]:
        '''Specifies the locales that Amazon Lex adds to this version.

        You can choose the Draft version or any other previously published version for each locale. When you specify a source version, the locale data is copied from the source version to the new version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-botversion.html#cfn-lex-botversion-botversionlocalespecification
        '''
        result = self._values.get("bot_version_locale_specification")
        assert result is not None, "Required property 'bot_version_locale_specification' is missing"
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnBotVersion.BotVersionLocaleSpecificationProperty, _IResolvable_da3f097b]]], result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-botversion.html#cfn-lex-botversion-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnBotVersionProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnResourcePolicy(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_lex.CfnResourcePolicy",
):
    '''A CloudFormation ``AWS::Lex::ResourcePolicy``.

    Specifies a new resource policy with the specified policy statements.

    :cloudformationResource: AWS::Lex::ResourcePolicy
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-resourcepolicy.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_lex as lex
        
        # policy: Any
        
        cfn_resource_policy = lex.CfnResourcePolicy(self, "MyCfnResourcePolicy",
            policy=policy,
            resource_arn="resourceArn"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        policy: typing.Any,
        resource_arn: builtins.str,
    ) -> None:
        '''Create a new ``AWS::Lex::ResourcePolicy``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param policy: A resource policy to add to the resource. The policy is a JSON structure that contains one or more statements that define the policy. The policy must follow IAM syntax. If the policy isn't valid, Amazon Lex returns a validation exception.
        :param resource_arn: The Amazon Resource Name (ARN) of the bot or bot alias that the resource policy is attached to.
        '''
        props = CfnResourcePolicyProps(policy=policy, resource_arn=resource_arn)

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="inspect")
    def inspect(self, inspector: _TreeInspector_488e0dd5) -> None:
        '''Examines the CloudFormation resource and discloses attributes.

        :param inspector: - tree inspector to collect and process attributes.
        '''
        return typing.cast(None, jsii.invoke(self, "inspect", [inspector]))

    @jsii.member(jsii_name="renderProperties")
    def _render_properties(
        self,
        props: typing.Mapping[builtins.str, typing.Any],
    ) -> typing.Mapping[builtins.str, typing.Any]:
        '''
        :param props: -
        '''
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.invoke(self, "renderProperties", [props]))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="CFN_RESOURCE_TYPE_NAME")
    def CFN_RESOURCE_TYPE_NAME(cls) -> builtins.str:
        '''The CloudFormation resource type name for this resource class.'''
        return typing.cast(builtins.str, jsii.sget(cls, "CFN_RESOURCE_TYPE_NAME"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrId")
    def attr_id(self) -> builtins.str:
        '''The identifier of the resource policy.

        :cloudformationAttribute: Id
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrRevisionId")
    def attr_revision_id(self) -> builtins.str:
        '''
        :cloudformationAttribute: RevisionId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrRevisionId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policy")
    def policy(self) -> typing.Any:
        '''A resource policy to add to the resource.

        The policy is a JSON structure that contains one or more statements that define the policy. The policy must follow IAM syntax. If the policy isn't valid, Amazon Lex returns a validation exception.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-resourcepolicy.html#cfn-lex-resourcepolicy-policy
        '''
        return typing.cast(typing.Any, jsii.get(self, "policy"))

    @policy.setter
    def policy(self, value: typing.Any) -> None:
        jsii.set(self, "policy", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="resourceArn")
    def resource_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the bot or bot alias that the resource policy is attached to.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-resourcepolicy.html#cfn-lex-resourcepolicy-resourcearn
        '''
        return typing.cast(builtins.str, jsii.get(self, "resourceArn"))

    @resource_arn.setter
    def resource_arn(self, value: builtins.str) -> None:
        jsii.set(self, "resourceArn", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_lex.CfnResourcePolicyProps",
    jsii_struct_bases=[],
    name_mapping={"policy": "policy", "resource_arn": "resourceArn"},
)
class CfnResourcePolicyProps:
    def __init__(self, *, policy: typing.Any, resource_arn: builtins.str) -> None:
        '''Properties for defining a ``CfnResourcePolicy``.

        :param policy: A resource policy to add to the resource. The policy is a JSON structure that contains one or more statements that define the policy. The policy must follow IAM syntax. If the policy isn't valid, Amazon Lex returns a validation exception.
        :param resource_arn: The Amazon Resource Name (ARN) of the bot or bot alias that the resource policy is attached to.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-resourcepolicy.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_lex as lex
            
            # policy: Any
            
            cfn_resource_policy_props = lex.CfnResourcePolicyProps(
                policy=policy,
                resource_arn="resourceArn"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "policy": policy,
            "resource_arn": resource_arn,
        }

    @builtins.property
    def policy(self) -> typing.Any:
        '''A resource policy to add to the resource.

        The policy is a JSON structure that contains one or more statements that define the policy. The policy must follow IAM syntax. If the policy isn't valid, Amazon Lex returns a validation exception.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-resourcepolicy.html#cfn-lex-resourcepolicy-policy
        '''
        result = self._values.get("policy")
        assert result is not None, "Required property 'policy' is missing"
        return typing.cast(typing.Any, result)

    @builtins.property
    def resource_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the bot or bot alias that the resource policy is attached to.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lex-resourcepolicy.html#cfn-lex-resourcepolicy-resourcearn
        '''
        result = self._values.get("resource_arn")
        assert result is not None, "Required property 'resource_arn' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnResourcePolicyProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnBot",
    "CfnBotAlias",
    "CfnBotAliasProps",
    "CfnBotProps",
    "CfnBotVersion",
    "CfnBotVersionProps",
    "CfnResourcePolicy",
    "CfnResourcePolicyProps",
]

publication.publish()
