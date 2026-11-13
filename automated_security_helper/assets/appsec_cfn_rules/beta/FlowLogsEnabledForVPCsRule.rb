require 'cfn-nag/custom_rules/base'
require 'cfn-nag/violation'


class FlowLogsEnabledForVPCsRule < BaseRule
  def rule_text
    'FlowLogs should be enabled for created VPCs'
  end

  def rule_type
    Violation::FAILING_VIOLATION
  end

  def rule_id
    'APPSEC-DC-LogEverywhere-VPCFlowLogs'
  end

  def audit_impl(cfn_model)
    vpc_ids = cfn_model.resources_by_type('AWS::EC2::VPC').map(&:logical_resource_id)
    flowlogs = cfn_model.resources_by_type('AWS::EC2::FlowLog')

    # Report violation on all VPC Ids that aren't referred to by FlowLogs.
    #
    # cfn-model keeps a resource's properties in instance variables named in lower
    # camel case (resourceId for ResourceId) and answers them through method_missing,
    # so the capitalized ResourceId named nothing and every VPC was reported. The
    # value is the template's, a Ref or a GetAtt to the VPC, not the VPC's logical
    # id, so the id it points at is read out of it before the subtraction.
    covered = flowlogs.map { |flowlog| referenced_logical_id(flowlog.resourceId) }.compact
    vpc_ids - covered
  end

  private

  # The logical id a property value points at: the target of a Ref, or the resource
  # of an Fn::GetAtt. nil for a literal id of a resource outside the template, and
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
