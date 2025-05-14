<!-- markdownlint-disable -->

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/utils/cdk_nag_wrapper.py#L0"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

# <kbd>module</kbd> `utils.cdk_nag_wrapper`





---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/utils/cdk_nag_wrapper.py#L95"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `get_model_from_template`

```python
get_model_from_template(
    template_path: Path | None = None
) → CloudFormationTemplateModel | None
```






---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/utils/cdk_nag_wrapper.py#L114"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `get_nag_packs`

```python
get_nag_packs()
```






---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/utils/cdk_nag_wrapper.py#L138"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `run_cdk_nag_against_cfn_template`

```python
run_cdk_nag_against_cfn_template(
    template_path: Path,
    nag_packs: List[Literal['AwsSolutionsChecks', 'HIPAASecurityChecks', 'NIST80053R4Checks', 'NIST80053R5Checks', 'PCIDSS321Checks']] = ['AwsSolutionsChecks'],
    outdir: Path = None,
    include_compliant_checks: bool = True,
    stack_name: str = 'ASHCDKNagScanner'
) → CdkNagWrapperResponse | None
```






---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/utils/cdk_nag_wrapper.py#L50"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>class</kbd> `CloudFormationResource`





---

#### <kbd>property</kbd> model_extra

Get extra fields set during validation. 



**Returns:**
  A dictionary of extra fields, or `None` if `config.extra` is not set to `"allow"`. 

---

#### <kbd>property</kbd> model_fields_set

Returns the set of fields that have been explicitly set on this model instance. 



**Returns:**
  A set of strings representing the fields that have been set,  i.e. that were not filled from defaults. 




---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/utils/cdk_nag_wrapper.py#L61"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>class</kbd> `CloudFormationTemplateModel`





---

#### <kbd>property</kbd> model_extra

Get extra fields set during validation. 



**Returns:**
  A dictionary of extra fields, or `None` if `config.extra` is not set to `"allow"`. 

---

#### <kbd>property</kbd> model_fields_set

Returns the set of fields that have been explicitly set on this model instance. 



**Returns:**
  A set of strings representing the fields that have been set,  i.e. that were not filled from defaults. 




---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/utils/cdk_nag_wrapper.py#L72"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>class</kbd> `WrapperStack`




<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/utils/cdk_nag_wrapper.py#L73"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `__init__`

```python
__init__(
    scope: Construct | None = None,
    id: str | None = None,
    template_path: Path | None = None
)
```






---

#### <kbd>property</kbd> account

The AWS account into which this stack will be deployed. 

This value is resolved according to the following rules: 

1. The value provided to ``env.account`` when the stack is defined. This can  either be a concrete account (e.g. ``585695031111``) or the  ``Aws.ACCOUNT_ID`` token. 2. ``Aws.ACCOUNT_ID``, which represents the CloudFormation intrinsic reference  ``{ "Ref": "AWS::AccountId" }`` encoded as a string token. 

Preferably, you should use the return value as an opaque string and not attempt to parse it to implement your logic. If you do, you must first check that it is a concrete value an not an unresolved token. If this value is an unresolved token (``Token.isUnresolved(stack.account)`` returns ``true``), this implies that the user wishes that this stack will synthesize into an **account-agnostic template**. In this case, your code should either fail (throw an error, emit a synth error using ``Annotations.of(construct).addError()``) or implement some other account-agnostic behavior. 

---

#### <kbd>property</kbd> artifact_id

The ID of the cloud assembly artifact for this stack. 

---

#### <kbd>property</kbd> availability_zones

Returns the list of AZs that are available in the AWS environment (account/region) associated with this stack. 

If the stack is environment-agnostic (either account and/or region are tokens), this property will return an array with 2 tokens that will resolve at deploy-time to the first two availability zones returned from CloudFormation's ``Fn::GetAZs`` intrinsic function. 

If they are not available in the context, returns a set of dummy values and reports them as missing, and let the CLI resolve them by calling EC2 ``DescribeAvailabilityZones`` on the target environment. 

To specify a different strategy for selecting availability zones override this method. 

---

#### <kbd>property</kbd> bundling_required

Indicates whether the stack requires bundling or not. 

---

#### <kbd>property</kbd> dependencies

Return the stacks this stack depends on. 

---

#### <kbd>property</kbd> environment

The environment coordinates in which this stack is deployed. 

In the form ``aws://account/region``. Use ``stack.account`` and ``stack.region`` to obtain the specific values, no need to parse. 

You can use this value to determine if two stacks are targeting the same environment. 

If either ``stack.account`` or ``stack.region`` are not concrete values (e.g. ``Aws.ACCOUNT_ID`` or ``Aws.REGION``) the special strings ``unknown-account`` and/or ``unknown-region`` will be used respectively to indicate this stack is region/account-agnostic. 

---

#### <kbd>property</kbd> nested

Indicates if this is a nested stack, in which case ``parentStack`` will include a reference to it's parent. 

---

#### <kbd>property</kbd> nested_stack_parent

If this is a nested stack, returns it's parent stack. 

---

#### <kbd>property</kbd> nested_stack_resource

If this is a nested stack, this represents its ``AWS::CloudFormation::Stack`` resource. 

``undefined`` for top-level (non-nested) stacks. 

---

#### <kbd>property</kbd> node

The tree node. 

---

#### <kbd>property</kbd> notification_arns

Returns the list of notification Amazon Resource Names (ARNs) for the current stack. 

---

#### <kbd>property</kbd> partition

The partition in which this stack is defined. 

---

#### <kbd>property</kbd> region

The AWS region into which this stack will be deployed (e.g. ``us-west-2``). 

This value is resolved according to the following rules: 

1. The value provided to ``env.region`` when the stack is defined. This can  either be a concrete region (e.g. ``us-west-2``) or the ``Aws.REGION``  token. 2. ``Aws.REGION``, which is represents the CloudFormation intrinsic reference  ``{ "Ref": "AWS::Region" }`` encoded as a string token. 

Preferably, you should use the return value as an opaque string and not attempt to parse it to implement your logic. If you do, you must first check that it is a concrete value an not an unresolved token. If this value is an unresolved token (``Token.isUnresolved(stack.region)`` returns ``true``), this implies that the user wishes that this stack will synthesize into a **region-agnostic template**. In this case, your code should either fail (throw an error, emit a synth error using ``Annotations.of(construct).addError()``) or implement some other region-agnostic behavior. 

---

#### <kbd>property</kbd> stack_id

The ID of the stack. 



**Example::**
 

 # After resolving, looks like  "arn:aws:cloudformation:us-west-2:123456789012:stack/teststack/51af3dc0-da77-11e4-872e-1234567db123" 

---

#### <kbd>property</kbd> stack_name

The concrete CloudFormation physical stack name. 

This is either the name defined explicitly in the ``stackName`` prop or allocated based on the stack's location in the construct tree. Stacks that are directly defined under the app use their construct ``id`` as their stack name. Stacks that are defined deeper within the tree will use a hashed naming scheme based on the construct path to ensure uniqueness. 

If you wish to obtain the deploy-time AWS::StackName intrinsic, you can use ``Aws.STACK_NAME`` directly. 

---

#### <kbd>property</kbd> synthesizer

Synthesis method for this stack. 

---

#### <kbd>property</kbd> tags

Tags to be applied to the stack. 

---

#### <kbd>property</kbd> template_file

The name of the CloudFormation template file emitted to the output directory during synthesis. 

Example value: ``MyStack.template.json`` 

---

#### <kbd>property</kbd> template_options

Options for CloudFormation template (like version, transform, description). 

---

#### <kbd>property</kbd> termination_protection

Whether termination protection is enabled for this stack. 

---

#### <kbd>property</kbd> url_suffix

The Amazon domain suffix for the region in which this stack is defined. 




---

<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/utils/cdk_nag_wrapper.py#L126"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>class</kbd> `CdkNagWrapperResponse`




<a href="https://github.com/example/my-project/blob/main/src/automated_security_helper/utils/cdk_nag_wrapper.py#L127"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `__init__`

```python
__init__(
    results: Optional[Dict[str, List[Result]]] = None,
    outdir: Path = None,
    template: CloudFormationTemplateModel | None = None
)
```











---

_This file was automatically generated via [lazydocs](https://github.com/ml-tooling/lazydocs)._
