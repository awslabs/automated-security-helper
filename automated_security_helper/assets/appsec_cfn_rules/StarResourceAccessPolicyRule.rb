require 'json'
require 'cfn-nag/custom_rules/base'
require 'cfn-nag/violation'
require 'cfn-model/parser/policy_document_parser'
require_relative 'AccessPolicyReading'


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
    unread_principals = []
    unread_policies = []
    limited_resources = []

    cfn_model.resources.values.each do |resource|

      # If the resource has an IAM resource access policy. Only the AccessPolicies
      # property is read: it is the resource policy of an Elasticsearch or OpenSearch
      # domain. A policy a resource carries under another name (an S3 BucketPolicy's
      # PolicyDocument, a KMS key's KeyPolicy, an SQS QueuePolicy, an SNS TopicPolicy)
      # is not read here; cfn_nag ships rules of its own for those resources.
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
        #
        # The document is built from the policy as the template wrote it, with each branch of
        # every Fn::If present as a statement of its own: cfn-model resolves an Fn::If to its
        # first branch when it parses, so a public value in the second would not be seen.
        document, limited = AccessPolicyReading.policy_document(cfn_model, resource)
        limited_resources << resource.logical_resource_id if limited
        # AccessPolicies is a JSON property, so a template can write it as a JSON string,
        # or as an Fn::Sub or Fn::Join that cfn-model resolves to one. PolicyDocumentParser
        # indexes its document with [], which on a String answers a substring or nil, never
        # a statement, so such a policy was read as empty and never reported. The text is
        # parsed here; one that is not a JSON document (an Fn::Sub with a ${Name} left in
        # it) is reported as unread on stderr and not checked.
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
            # Allow with NotPrincipal grants access to everyone except the principals listed,
            # so it is public. Before this the rule read only Principal, which is nil on
            # such a statement, and passed it over.
            unread = []
            is_public = public_principal?(cfn_model, statement.principal, unread)
            unread.each { |shape| unread_principals << [resource.logical_resource_id, shape] }
            if is_public || AccessPolicyReading.listed?(statement.not_principal) then
              logical_resource_ids << resource.logical_resource_id
            end
          end
        end
      end
    end

    # One line per resource and shape, so a template with many unreadable principals is
    # not drowned in them and a reader can find the resource to look at.
    unread_principals.uniq.each do |logical_id, shape|
      $stderr.puts(
        format(
          "WARNING: StarResourceAccessPolicyRule: unread principal in %s (%s); " \
          "the rule cannot read it, so the principal was not checked",
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
          "WARNING: StarResourceAccessPolicyRule: the AccessPolicies of %s is a string " \
          "that is not a JSON document; the rule cannot read it, so the policy was not checked",
          logical_id
        )
      )
    end

    # A resource is added once per matching statement. The result lists each resource once.
    logical_resource_ids.uniq
  end

  private

  # The policy document a JSON string holds, or nil when the string is not one. A
  # document is a Hash; JSON text that parses to anything else is no policy either.
  def parse_policy_text(text)
    parsed = JSON.parse(text)
    parsed.is_a?(Hash) ? parsed : nil
  rescue JSON::ParserError
    nil
  end

  # True when a statement's principal names everyone. cfn-model's PolicyDocumentParser keeps
  # the principal in the shape the template wrote it, so it can be:
  #   a String   Principal: "*"
  #   a Hash     Principal: {AWS: "*"}, {AWS: ["*"]} or {AWS: ["arn:...", "*"]}
  #   an Array   Principal: ["*"] (cfn-model's own wildcard check raises on this shape,
  #              but its parser passes it through)
  #   nil        a statement with no Principal (one written with NotPrincipal instead is
  #              read through AccessPolicyReading.listed?)
  # This used to call has_key? and has_value? on the principal. Only a Hash answers those, so
  # a String made the rule raise NoMethodError, and {AWS: ["*"]} was passed over because the
  # Array is not equal to the String "*". With --isolate-custom-rule-exceptions a raise costs
  # this rule's result for every resource in the template, not only the one that raised.
  #
  # A Hash counts when any of its values is "*" or a list holding "*", under any key. The old
  # test read a Hash only when it had an "AWS" key, so {Service: "*"} was not reported while
  # {AWS: "arn:...", Service: "*"} was. Everything the old test reported is still reported.
  #
  # A value, or an entry of a list, is not always text. A Ref to a parameter arrives as a
  # Hash, because ASH gives cfn-model no parameter values, and an Fn::Sub that names a
  # parameter arrives with its ${Name} in it. AccessPolicyReading.read_principal reads
  # those through the parameter's Default and AllowedValues, as the verb rule reads an
  # action, so a parameter whose Default is "*" is reported. A principal that is itself a
  # Hash holding one intrinsic function (Principal: {Ref: P}) is one such value, not a map
  # of names to values. What cannot be read is added to unread, and audit_impl writes a
  # line to stderr for it.
  def public_principal?(cfn_model, principal, unread)
    if principal.is_a?(Hash) && !AccessPolicyReading.intrinsic?(principal) then
      principal.values.map { |value| star_or_list_holding_star?(cfn_model, value, unread) }.any?
    else
      star_or_list_holding_star?(cfn_model, principal, unread)
    end
  end

  # True when a value is "*" or a list holding "*" once its parameters are read. Every entry
  # is read, so a line is written for each entry that cannot be, even after a "*" is found.
  def star_or_list_holding_star?(cfn_model, value, unread)
    entries = value.is_a?(Array) ? value : [value]
    entries.map do |entry|
      texts, shape = AccessPolicyReading.read_principal(cfn_model, entry)
      unread << shape unless shape.nil?
      texts.include?("*")
    end.any?
  end
end
