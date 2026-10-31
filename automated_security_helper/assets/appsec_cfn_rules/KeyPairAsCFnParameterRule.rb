require 'cfn-nag/custom_rules/base'
require 'cfn-nag/violation'


class KeyPairAsCFnParameterRule < BaseRule
  def rule_text
    'Passing a KeyPair to a CloudFormation Template represents a long-term credential thats not rotated'
  end

  def rule_type
    Violation::FAILING_VIOLATION
  end

  def rule_id
    'APPSEC-IAM-UseEphemeralCreds-KeyPairAsCFnParam'
  end

  # The parameter types that pass a key pair into the template: the key pair type
  # itself, and the SSM parameter type that reads a key pair name from SSM when the
  # stack is created. Only the first was matched, so a key pair passed through SSM
  # was not reported.
  KEY_PAIR_TYPES = [
    'AWS::EC2::KeyPair::KeyName',
    'AWS::SSM::Parameter::Value<AWS::EC2::KeyPair::KeyName>'
  ].freeze

  def audit_impl(cfn_model)

    parameters = cfn_model.parameters.select do |name, properties|

      # cfn-model gives the type as {"value" => ..., "line" => ...} when it keeps
      # line numbers and as the plain string otherwise; String#[]("value") is nil,
      # so the plain shape never matched and the rule never reported.
      # TODO: find way to preserve the line number from properties.type["line"]
      type = properties.type
      type = type["value"] if type.is_a?(Hash)
      KEY_PAIR_TYPES.include?(type)
    end

    parameters.values.map(&:id)
  end
end
