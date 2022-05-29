require 'cfn-nag/custom_rules/base'
require 'cfn-nag/violation'
require 'cfn-model/parser/policy_document_parser'


class ResourcePolicyStarAccessVerbPolicyRule < BaseRule
  def rule_text
    'Overly permissive access in resource policy allowing caller to mutate or delete the resource itself'
  end

  def rule_type
    Violation::FAILING_VIOLATION
  end

  def rule_id
    'APPSEC-IAM-LeastPrivilege-ResourcePolicyStarVerb'
  end

  def audit_impl(cfn_model)
    logical_resource_ids = []
    cfn_model.resources.values.each do |resource|

      # If the resource has an IAM resource access policy
      unless (resource.accessPolicies.nil?) then
        parsed_resource_policy = PolicyDocumentParser.new().parse(resource.accessPolicies)
        parsed_resource_policy.statements.each do |statement|

          # If any statement allows access from "*" then the resource is effectively public
          if statement.effect == "Allow" then
            statement.actions.each do |action|
              if action.downcase.end_with?(":*") then
                logical_resource_ids << resource.logical_resource_id
              end
            end
          end
        end
      end
    end

    logical_resource_ids
  end
end