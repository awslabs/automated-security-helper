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

    # Report violation on all VPC Ids that aren't referred to by FlowLogs
    vpc_ids - flowlogs.map(&:ResourceId)
  end
end
