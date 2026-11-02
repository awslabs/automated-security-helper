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

  # The AllowedValues that make a String parameter a yes/no switch rather than a
  # secret ("EnablePasswordRotation: Yes"). Matched in any order, case and type, so
  # ['No', 'Yes'], ['false', 'true'] and [true, false] all count; before this only
  # [true, false] and ['Yes', 'No'], in that order and type, did.
  BOOLEAN_CHOICES = [%w[true false], %w[yes no]].freeze

  def audit_impl(cfn_model)

    parameters = cfn_model.parameters.select do |name, properties|

      # cfn-model gives the type as {"value" => ..., "line" => ...} when it keeps
      # line numbers and as the plain string otherwise; String#[]("value") is nil,
      # so the plain shape never matched and the rule never reported.
      # TODO: find way to preserve the line number from properties.type["line"]
      type = properties.type
      type = type["value"] if type.is_a?(Hash)
      name.downcase.include?("password") and
      type == "String" and
      !boolean_choices?(properties.allowedValues)
    end

    parameters.values.map(&:id)
  end

  private

  # True when AllowedValues names a yes/no pair (BOOLEAN_CHOICES), whatever the
  # order, case or type the template wrote it in.
  def boolean_choices?(allowed_values)
    allowed_values = allowed_values["value"] if allowed_values.is_a?(Hash) && allowed_values.key?("value")
    return false unless allowed_values.is_a?(Array)
    normalized = allowed_values.map { |value| value.to_s.strip.downcase }.sort
    BOOLEAN_CHOICES.any? { |choice| choice.sort == normalized }
  end
end
