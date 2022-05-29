require 'cfn-nag/custom_rules/base'
require 'cfn-nag/violation'


class PasswordAsCFnParameterRule < BaseRule
  def rule_text
    'Passing a password to a CloudFormation Template represents a long-term credential thats not rotated'
  end

  def rule_type
    Violation::FAILING_VIOLATION
  end

  def rule_id
    'APPSEC-IAM-UseEphemeralCreds-PasswordAsCFnParam'
  end

  def audit_impl(cfn_model)

    parameters = cfn_model.parameters.select do |name, properties|
      
      # TODO: find way to preserve the line number from properties.type["line"] 
      name.downcase.include?("password") and
      properties.type["value"] == "String" and
      properties.allowedValues != [true, false] and
      properties.allowedValues != ['Yes', 'No']
    end

    parameters.values.map(&:id)
  end
end