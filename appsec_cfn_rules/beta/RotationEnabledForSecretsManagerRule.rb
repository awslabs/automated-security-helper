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

    # Report violation on all Secret Ids that aren't referred to by RotationSchedule
    secret_ids - rotation_schedules.map(&:SecretId)
  end
end
