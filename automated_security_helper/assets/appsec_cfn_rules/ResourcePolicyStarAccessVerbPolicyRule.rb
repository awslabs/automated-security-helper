require 'json'
require 'cfn-nag/custom_rules/base'
require 'cfn-nag/violation'
require 'cfn-model/parser/policy_document_parser'
require_relative 'AccessPolicyReading'


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
    unread_actions = []
    unread_policies = []
    limited_resources = []
    cfn_model.resources.values.each do |resource|

      # If the resource has an IAM resource access policy. Only the AccessPolicies
      # property is read: it is the resource policy of an Elasticsearch or OpenSearch
      # domain. A policy a resource carries under another name (an S3 BucketPolicy's
      # PolicyDocument, a KMS key's KeyPolicy, an SQS QueuePolicy, an SNS TopicPolicy)
      # is not read here; cfn_nag ships rules of its own for those resources.
      unless (resource.accessPolicies.nil?) then
        # cfn_model is passed because PolicyDocumentParser#parse requires it; see the same
        # call in StarResourceAccessPolicyRule.rb for why the one-argument form was wrong
        # and what it cost. Both rules were written against cfn-model 0.4.0's signature.
        # The document is built from the policy as the template wrote it, with each branch of
        # every Fn::If present as a statement of its own: cfn-model resolves an Fn::If to its
        # first branch when it parses, so a public value in the second would not be seen.
        document, limited = AccessPolicyReading.policy_document(cfn_model, resource)
        limited_resources << resource.logical_resource_id if limited
        # A JSON string, or an Fn::Sub or Fn::Join cfn-model resolved to one, is parsed
        # before it reaches PolicyDocumentParser; see StarResourceAccessPolicyRule.rb.
        if document.is_a?(String) then
          document = parse_policy_text(document)
          if document.nil? then
            unread_policies << resource.logical_resource_id
            next
          end
        end
        parsed_resource_policy = PolicyDocumentParser.new().parse(cfn_model, document)
        parsed_resource_policy.statements.each do |statement|

          # If any statement allows access from "*" then the resource is effectively public
          if statement.effect == "Allow" then
            # Allow with NotAction grants every action except the ones listed, which is a
            # wildcard action in all but name. Before this the rule read only Action, so a
            # statement written with NotAction had no actions and was passed over.
            if AccessPolicyReading.listed?(statement.not_actions) then
              logical_resource_ids << resource.logical_resource_id
            end
            (statement.actions || []).each do |action|
              # cfn-model hands an action over as a String, or as a Hash when the template
              # writes it as Fn::ImportValue, Fn::GetAtt, Fn::Transform, Fn::Cidr or a Ref to
              # a parameter. It resolves Fn::Sub and Fn::If to a String, but it leaves the
              # ${Name} of an Fn::Sub in the text when Name is a parameter, because ASH gives
              # it no parameter values. downcase on a Hash raises, and a raise costs this
              # rule's result for every resource in the template.
              #
              # AccessPolicyReading.texts answers with the texts the action can be, or nil
              # when it cannot be read. For an Fn::Sub it fills each ${Name} that is a
              # parameter from the texts the parameter holds, so "es:${Verb}" with a Verb
              # whose Default is "*" is read as "es:*".
              #
              # A Ref to a parameter is read through the parameter: its Default, which
              # cfn-model applies only when it is given parameter values (ASH passes none),
              # and every entry of its AllowedValues when it lists any, because whoever
              # creates the stack may choose any of them. A parameter with no AllowedValues
              # is read through its Default alone, and a value supplied when the stack is
              # created can differ from it. Some Refs hold no action text to read: a
              # parameter of an SSM type, whose Default is the name of an SSM parameter, and
              # a parameter whose Default is empty or only commas. A Hash of any other shape
              # cannot be read at all either: the template does not say what an import or an
              # attribute holds. Such an entry is not checked for a star, so it is reported
              # as unread on stderr (see below), and the rest of the actions are still read.
              texts = AccessPolicyReading.texts(cfn_model, action)
              if texts.nil? then
                unread_actions << [resource.logical_resource_id, AccessPolicyReading.unread_shape(cfn_model, action)]
                next
              end
              texts.each do |text|
                verb = text.downcase
                # "service:*" grants every action of one service, and the bare "*" grants
                # every action of every service. The bare "*" ends in no ":*", so the suffix
                # test alone never saw it.
                if verb == "*" || verb.end_with?(":*") then
                  logical_resource_ids << resource.logical_resource_id
                end
              end
            end
          end
        end
      end
    end

    # One line per resource and shape, so a template with many unreadable actions is
    # not drowned in them and a reader can find the resource to look at.
    unread_actions.uniq.each do |logical_id, shape|
      $stderr.puts(
        format(
          "WARNING: ResourcePolicyStarAccessVerbPolicyRule: unread action in %s (%s); " \
          "the rule cannot read it, so the action was not checked",
          logical_id,
          shape
        )
      )
    end

    # A statement with more combinations of Fn::If branches than the helper reads is read as
    # cfn-model parses it, so the rule says so once per resource.
    limited_resources.uniq.each do |logical_id|
      $stderr.puts(AccessPolicyReading.limit_warning(self.class.name, logical_id))
    end

    unread_policies.uniq.each do |logical_id|
      $stderr.puts(
        format(
          "WARNING: ResourcePolicyStarAccessVerbPolicyRule: the AccessPolicies of %s is a " \
          "string that is not a JSON document; the rule cannot read it, so the policy was " \
          "not checked",
          logical_id
        )
      )
    end

    # A resource is added once per match: once per matching statement, and once per
    # matching action in a statement. The result lists each resource once.
    logical_resource_ids.uniq
  end

  private

  # The policy document a JSON string holds, or nil when the string is not one.
  def parse_policy_text(text)
    parsed = JSON.parse(text)
    parsed.is_a?(Hash) ? parsed : nil
  rescue JSON::ParserError
    nil
  end
end
