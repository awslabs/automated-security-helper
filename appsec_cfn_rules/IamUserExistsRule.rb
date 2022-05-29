require 'cfn-nag/custom_rules/base'
require 'cfn-nag/violation'


class IamUserExistsRule < BaseRule
  def rule_text
    'IAM Users represent long-term credentials'
  end

  def rule_type
    Violation::FAILING_VIOLATION
  end

  def rule_id
    'APPSEC-IAM-UseEphemeralCredentials-IAMUser'
  end

  def audit_impl(cfn_model)
    cfn_model.resources_by_type('AWS::IAM::User').map(&:logical_resource_id)
  end
end
