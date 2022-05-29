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

  def audit_impl(cfn_model)

    parameters = cfn_model.parameters.select do |name, properties|
      
      # TODO: find way to preserve the line number from properties.type["line"] 
      properties.type["value"] == "AWS::EC2::KeyPair::KeyName"
    end

    parameters.values.map(&:id)
  end
end