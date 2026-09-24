require 'cfn-nag/custom_rules/base'
require 'cfn-nag/violation'
require 'cfn-model/parser/policy_document_parser'


class StarResourceAccessPolicyRule < BaseRule
  def rule_text
    'A resource with an associated IAM resource policy is allowing world access'
  end

  def rule_type
    Violation::FAILING_VIOLATION
  end

  def rule_id
    'APPSEC-IAM-RestrictPublicAccess-StarAccessPolicy'
  end

  def audit_impl(cfn_model)
    logical_resource_ids = []

    cfn_model.resources.values.each do |resource|

      # If the resource has an IAM resource access policy
      unless (resource.accessPolicies.nil?) then
        # cfn_model is passed because PolicyDocumentParser#parse requires it: cfn-model
        # declares parse(cfn_model, raw_policy_document) and resolves Refs in the policy
        # through the model. The one-argument form this used to call was cfn-model 0.4.0's
        # signature; cfn-nag 0.8.10 pins cfn-model exactly at 0.6.6, so no reachable
        # version accepts it. Called with one argument Ruby raises ArgumentError, which
        # CustomRuleLoader re-raises unless --isolate-custom-rule-exceptions is passed and
        # which matches none of the rescue clauses above it, so the process exited before
        # rendering and every rule's verdict on the template was lost -- not just this
        # one's. cfn_model is already audit_impl's parameter, so nothing new is plumbed in.
        parsed_resource_policy = PolicyDocumentParser.new().parse(cfn_model, resource.accessPolicies)
        parsed_resource_policy.statements.each do |statement|

          # If any statement allows access from "*" then the resource is effectively public
          if statement.effect == "Allow" then
            if statement.principal.has_key?("AWS") and statement.principal.has_value?("*") then
              logical_resource_ids << resource.logical_resource_id
            end
          end
        end
      end
    end

    logical_resource_ids
  end
end
