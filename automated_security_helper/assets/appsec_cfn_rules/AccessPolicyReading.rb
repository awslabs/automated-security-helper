require 'cfn-model/model/references'

# Reading shared by StarResourceAccessPolicyRule and ResourcePolicyStarAccessVerbPolicyRule.
#
# This file is not a rule. cfn-nag loads the files of the rule directory whose names end in
# Rule.rb and treats each as a class to run, so this one is named for what it does and
# both rules load it with require_relative.
#
# Both rules decide from text that a template can write in several ways: as a String, or
# as a Hash that stands for a value cfn-model does not resolve (a Ref to a parameter, an
# Fn::ImportValue, an Fn::GetAtt). A Ref to a parameter is read here, once, so the two rules
# agree on what a parameter holds.
module AccessPolicyReading
  # The most texts an Fn::Sub with several parameters is read as. A text built from more
  # combinations of parameter values than this is reported as unread instead.
  MAX_TEXTS = 32

  # A ${Name} in the text of an Fn::Sub. ${!Name} is how CloudFormation writes a literal
  # ${Name}, so it is not a hole.
  SUB_HOLE = /\$\{(?!!)([^}]*)\}/

  # The fields of a statement whose Fn::If branches are read.
  STATEMENT_FIELDS = %w[Effect Action NotAction Principal NotPrincipal].freeze

  # The most combinations of Fn::If branches read in one statement. A statement with more is
  # left as cfn-model parses it, the first branch of each Fn::If, and reported as limited.
  MAX_BRANCHES = 32

  # Stands for a value that is not there: a field the statement does not have, or a branch
  # that is Ref AWS::NoValue.
  ABSENT = Object.new.freeze

  class TooManyBranches < StandardError; end

  module_function

  # The policy document of a resource with each branch of every Fn::If in it present, and
  # whether a statement had more combinations of branches than are read.
  #
  # cfn-model resolves an Fn::If to its first branch when PolicyDocumentParser parses a
  # policy, and when it builds the resource it resolves one around the whole AccessPolicies
  # property to its first branch too. A rule that reads the parsed statement therefore never
  # sees the second branch. The branches stay in the policy as the template wrote it, in
  # cfn-model's raw model, so this reads them from there and builds a document the parser
  # can read: an Fn::If around the property or around a statement becomes one statement
  # per branch, and one in the Effect, Action, NotAction, Principal or NotPrincipal of a
  # statement becomes one statement per combination of branches.
  #
  # The conditions are not evaluated. A statement is read as every combination of its
  # branches, so a rule reports it when any combination is public, which can include a
  # combination that no value of the condition produces.
  def policy_document(cfn_model, resource)
    documents = policy_documents(raw_policy(cfn_model, resource))
    return [resource.accessPolicies, false] if documents.empty?
    limited = false
    statements = documents.flat_map { |document| statement_hashes(document["Statement"]) }
    statements = statements.flat_map do |statement|
      begin
        expand_statement(statement)
      rescue TooManyBranches
        limited = true
        [statement]
      end
    end
    [{ "Version" => documents.first["Version"], "Statement" => statements }, limited]
  end

  # What a rule writes to stderr for a resource whose statement was left unexpanded.
  def limit_warning(rule_name, logical_id)
    format(
      "WARNING: %s: a statement of %s has more than %d combinations of Fn::If branches; " \
      "the rule read only the first branch of each Fn::If in it",
      rule_name,
      logical_id,
      MAX_BRANCHES
    )
  end

  # The AccessPolicies property as the template wrote it, from cfn-model's raw model, or the
  # property cfn-model built when the raw model has none.
  def raw_policy(cfn_model, resource)
    raw_model = cfn_model.raw_model
    resources = raw_model.is_a?(Hash) ? raw_model["Resources"] : nil
    entry = resources.is_a?(Hash) ? resources[resource.logical_resource_id] : nil
    properties = entry.is_a?(Hash) ? entry["Properties"] : nil
    raw = properties.is_a?(Hash) ? properties["AccessPolicies"] : nil
    raw.nil? ? resource.accessPolicies : raw
  end

  # The documents a property can be: the Hash itself, or one per branch of an Fn::If
  # around it. Anything else is not a document.
  def policy_documents(raw)
    if if_expression?(raw)
      branches(raw).flat_map { |branch| policy_documents(branch) }
    elsif raw.is_a?(Hash)
      [raw]
    else
      []
    end
  end

  # The statements a Statement value holds: a Hash, a list of them, or an Fn::If choosing
  # between either, to any depth. Each branch of an Fn::If contributes its statements.
  def statement_hashes(value)
    if if_expression?(value)
      branches(value).flat_map { |branch| statement_hashes(branch) }
    elsif value.is_a?(Array)
      value.flat_map { |element| statement_hashes(element) }
    elsif value.is_a?(Hash)
      [value]
    else
      []
    end
  end

  # One statement per combination of the branches of the Fn::If in its fields. Raises
  # TooManyBranches when there are more combinations than MAX_BRANCHES.
  def expand_statement(statement)
    choices = STATEMENT_FIELDS.map do |field|
      statement.key?(field) ? alternatives(statement[field]) : [ABSENT]
    end
    raise TooManyBranches if choices.map(&:size).reduce(1, :*) > MAX_BRANCHES
    choices.first.product(*choices.drop(1)).map do |combination|
      expanded = statement.reject { |key, _| STATEMENT_FIELDS.include?(key) }
      STATEMENT_FIELDS.zip(combination).each do |field, value|
        expanded[field] = value unless value.equal?(ABSENT)
      end
      expanded
    end
  end

  # Every value an expression can be once its Fn::If are chosen: one for a plain value, one
  # per branch for an Fn::If. A list is one value holding what each of its elements can be,
  # so a list with an Fn::If in it holds both branches, which is what a rule that asks
  # whether any element is public needs. A map is one value per combination of the
  # alternatives of its values. A Ref to AWS::NoValue is absent. The other intrinsic
  # functions are left as they are: cfn-model reads them.
  def alternatives(value)
    found =
      if no_value?(value)
        [ABSENT]
      elsif if_expression?(value)
        branches(value).flat_map { |branch| alternatives(branch) }
      elsif value.is_a?(Array)
        [list_alternative(value)]
      elsif value.is_a?(Hash) && !intrinsic?(value)
        map_alternatives(value)
      else
        [value]
      end
    raise TooManyBranches if found.size > MAX_BRANCHES
    found
  end

  # The list that holds what each element of a list can be. A branch that is itself a list
  # adds its elements, and a branch that is absent adds nothing.
  def list_alternative(list)
    list.flat_map do |element|
      choices = alternatives(element)
      if if_expression?(element)
        choices = choices.flat_map { |choice| choice.is_a?(Array) ? choice : [choice] }
      end
      choices.reject { |choice| choice.equal?(ABSENT) }
    end
  end

  # One map per combination of the alternatives of the values of a map; a key whose value
  # is absent is left out.
  def map_alternatives(map)
    keys = map.keys
    return [map] if keys.empty?
    choices = keys.map { |key| alternatives(map[key]) }
    raise TooManyBranches if choices.map(&:size).reduce(1, :*) > MAX_BRANCHES
    choices.first.product(*choices.drop(1)).map do |combination|
      keys.zip(combination).each_with_object({}) do |(key, value), expanded|
        expanded[key] = value unless value.equal?(ABSENT)
      end
    end
  end

  # The then and else branches of an Fn::If: elements 1 and 2 of its three-element list.
  def branches(expression)
    expression["Fn::If"][1..2]
  end

  def if_expression?(value)
    value.is_a?(Hash) && value.size == 1 &&
      value["Fn::If"].is_a?(Array) && value["Fn::If"].size == 3
  end

  def no_value?(value)
    value.is_a?(Hash) && value.size == 1 && value["Ref"] == "AWS::NoValue"
  end

  # A Hash that is one intrinsic function (Ref, Fn::Sub, Fn::GetAtt ...) and not a map of
  # names to values such as a principal.
  def intrinsic?(value)
    value.size == 1 && (value.keys.first == "Ref" || value.keys.first.to_s.start_with?("Fn::"))
  end

  # The texts a value stands for, or nil when it cannot be read.
  #
  # A String is its own text, unless it is an Fn::Sub that cfn-model left with ${Name}
  # holes in it: cfn-model fills a hole only for a parameter it was given a value for, and
  # ASH gives none. Each hole that is a parameter of the template is filled from the texts
  # the parameter holds, so "es:${Verb}" with a Verb whose Default is "*" reads as "es:*".
  # A hole that is not such a parameter (a pseudo parameter, a parameter with no text to
  # read, a name only a long-form substitution map defines) leaves the value unread.
  #
  # A Hash is read through the parameter it names with Ref, or is unread. Any other value
  # is unread.
  def texts(cfn_model, value)
    if value.is_a?(String)
      filled_texts(cfn_model, value)
    elsif value.is_a?(Hash)
      parameter_texts(cfn_model, value)
    end
  end

  # What a principal, or one entry of a principal's list, stands for: the texts it can be
  # and, when it cannot be read and should be reported, how to name it. [texts, shape].
  #
  # A String is read as texts() reads it. A Hash is read through the parameter it names
  # with Ref. The shape is set for what a template can fill with a value that is not in the
  # template: an Fn::ImportValue, a Ref to a parameter with no text to read, and an Fn::Sub
  # with a name that is not a parameter with text when the text around the names could
  # still make the whole principal "*". It is not set for an Fn::GetAtt or a Ref to a
  # resource of the template, which name something the template creates, nor for an Fn::Sub
  # whose text around the names cannot be "*", such as an ARN that holds the account id:
  # reporting those would write a line for most policies in use.
  def read_principal(cfn_model, entry)
    if entry.is_a?(String)
      filled = filled_texts(cfn_model, entry)
      return [filled, nil] unless filled.nil?
      return [[], nil] unless could_be_star?(entry)
      [[], unread_shape(cfn_model, entry)]
    elsif entry.is_a?(Hash)
      found = parameter_texts(cfn_model, entry)
      return [found, nil] unless found.nil?
      [[], unread_principal_shape(cfn_model, entry)]
    else
      [[], nil]
    end
  end

  # True when the text left after the ${Name} holes are removed could still be a bare "*".
  def could_be_star?(string)
    ["", "*"].include?(string.gsub(SUB_HOLE, "").strip)
  end

  # The shape to report for a Hash principal that cannot be read, or nil when it is not
  # worth a line (see read_principal).
  def unread_principal_shape(cfn_model, hash)
    key = hash.keys.first.to_s
    return unread_shape(cfn_model, hash) if key == "Fn::ImportValue"
    return unread_shape(cfn_model, hash) if key == "Ref" && !parameter_for(cfn_model, hash).nil?
    nil
  end

  # The names of the ${Name} holes in a text, each once.
  def holes(string)
    string.scan(SUB_HOLE).flatten.uniq
  end

  # Every text a String can stand for once its holes are filled from the template's
  # parameters, or nil when a hole cannot be filled or the combinations are too many.
  def filled_texts(cfn_model, string)
    names = holes(string)
    return [string] if names.empty?
    readings = names.map { |name| parameter_texts(cfn_model, { "Ref" => name }) }
    return nil if readings.any?(&:nil?)
    filled = [string]
    names.zip(readings).each do |name, entries|
      filled = filled.flat_map do |text|
        entries.uniq.map { |entry| text.gsub("${#{name}}") { entry } }
      end
      return nil if filled.size > MAX_TEXTS
    end
    filled
  end

  # The texts a Ref to a parameter names: the Default and every entry of AllowedValues,
  # each split at commas so a list parameter is read entry by entry. A parameter that
  # lists AllowedValues is read through all of them, since the creator of the stack may
  # choose any one; with none, the Default is the only text the template holds, and it is
  # the one read. nil when the value is any other Hash, or a Ref to something with no text
  # to read: a resource, a parameter of an SSM type (its Default is the name of an SSM
  # parameter, not the value), or a parameter whose Default and AllowedValues leave no
  # entry (none set, or empty, or only commas).
  def parameter_texts(cfn_model, value)
    parameter = parameter_for(cfn_model, value)
    return nil if parameter.nil? || ssm_parameter?(parameter)
    texts = split_entries(parameter_attribute(parameter, :default))
    allowed = parameter_attribute(parameter, :allowedValues)
    unless allowed.nil? then
      [allowed].flatten.each { |entry| texts += split_entries(entry) }
    end
    texts.empty? ? nil : texts
  end

  # The parameter a Ref names, or nil for any other value, and for a Ref to something that
  # is not a parameter.
  def parameter_for(cfn_model, value)
    return nil unless value.is_a?(Hash) && value.keys == ["Ref"]
    (cfn_model.parameters || {})[value["Ref"]]
  end

  # True for a parameter of an SSM type, such as AWS::SSM::Parameter::Value<String>. The
  # value of such a parameter is read from SSM when the stack is created, and its Default
  # is the name of that SSM parameter. cfn_nag_scan parses the template with line numbers,
  # and cfn-model then keeps a scalar Type as a Hash holding the text under "value" and the
  # line, so the type is a String only after "value" is read.
  def ssm_parameter?(parameter)
    type = parameter.type
    type = type["value"] if type.is_a?(Hash)
    type.to_s.start_with?("AWS::SSM::Parameter::Value")
  end

  # The entries of a comma separated value, stripped; none for an unset value, and no
  # blank entry from an empty value or a doubled comma.
  def split_entries(value)
    return [] if value.nil?
    value.to_s.split(",").map(&:strip).reject(&:empty?)
  end

  # A template attribute of a parameter, or nil when the template does not set it.
  # cfn-model's Parameter keeps each attribute in an instance variable of that name and
  # answers it through method_missing. It defines no respond_to_missing?, so respond_to?
  # is false for every attribute, a Default that is set included, and cannot be used to
  # tell a parameter that has one from a parameter that has none.
  def parameter_attribute(parameter, name)
    parameter.instance_variable_get("@#{name}")
  end

  # What to call a value the rule cannot read: the name of its function, or for a Ref the
  # name it points at and, when the parameter is there but holds no text, why: a Default
  # that is an SSM key, or an empty Default. For an Fn::Sub, the first hole that cannot be
  # filled, or the number of combinations when every hole can. The class of any other value
  # that is not a Hash is its own name.
  def unread_shape(cfn_model, value)
    if value.is_a?(String)
      name = holes(value).find { |hole| parameter_texts(cfn_model, { "Ref" => hole }).nil? }
      return format("Fn::Sub, ${%s} has no text to read", name) unless name.nil?
      return format("Fn::Sub, more than %d texts from its parameters", MAX_TEXTS)
    end
    return value.class.to_s unless value.is_a?(Hash)
    key = value.keys.first.to_s
    return key unless key == "Ref"
    named = format("Ref %s", value["Ref"])
    parameter = parameter_for(cfn_model, value)
    return named if parameter.nil?
    return format("%s, a parameter Default that is an SSM key", named) if ssm_parameter?(parameter)
    return named if parameter_attribute(parameter, :default).nil?
    format("%s, an empty Default", named)
  end

  # True when a statement names something to exclude (NotAction or NotPrincipal). cfn-model
  # keeps the value in the shape the template wrote, and leaves it empty or nil for a
  # statement that does not use the key.
  def listed?(excluded)
    !(excluded.nil? || (excluded.respond_to?(:empty?) && excluded.empty?))
  end
end
