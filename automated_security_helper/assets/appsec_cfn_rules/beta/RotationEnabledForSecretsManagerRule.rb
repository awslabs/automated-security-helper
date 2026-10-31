require 'cfn-nag/custom_rules/base'
require 'cfn-nag/violation'


class RotationEnabledForSecretsManagerRule < BaseRule
  def rule_text
    'Rotation should be enabled for created Secrets'
  end

  def rule_type
    Violation::FAILING_VIOLATION
  end

  def rule_id
    'APPSEC-IAM-UseEphemeralCreds-RotateSecretsManager'
  end

  def audit_impl(cfn_model)
    secret_ids = cfn_model.resources_by_type('AWS::SecretsManager::Secret').map(&:logical_resource_id)
    rotation_schedules = cfn_model.resources_by_type('AWS::SecretsManager::RotationSchedule')

    # Report violation on all Secret Ids that aren't referred to by RotationSchedule.
    #
    # cfn-model keeps a resource's properties in instance variables named in lower
    # camel case (secretId for SecretId) and answers them through method_missing, so
    # the capitalized SecretId named nothing and every secret was reported. The
    # value is the template's, a Ref or a GetAtt to the secret, not the secret's
    # logical id, so the id it points at is read out of it before the subtraction.
    covered = rotation_schedules.map { |schedule| referenced_logical_id(schedule.secretId) }.compact
    secret_ids - covered
  end

  private

  # The logical id a property value points at: the target of a Ref, or the resource
  # of an Fn::GetAtt. nil for a literal ARN of a secret outside the template, and
  # for anything else. cfn_nag_scan parses with line numbers, under which cfn-model
  # keeps a scalar as {"value" => ..., "line" => ...}; that shape is unwrapped.
  def referenced_logical_id(value)
    value = value["value"] if value.is_a?(Hash) && value.key?("value") && value.key?("line")
    return nil unless value.is_a?(Hash)
    return value["Ref"] if value.key?("Ref")
    attribute = value["Fn::GetAtt"]
    return attribute.first if attribute.is_a?(Array)
    attribute.to_s.split(".").first if attribute.is_a?(String)
  end
end
