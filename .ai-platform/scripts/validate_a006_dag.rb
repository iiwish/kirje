#!/usr/bin/env ruby
# frozen_string_literal: true

require "date"
require "open3"
require "psych"

ROOT = File.expand_path("../..", __dir__)
BASELINE = "6acd4f238618a3ed10a594ef66406b941cb9074f"
PACKET = ".ai-platform/specs/007-stable-v1-program/packets/T110-A006.yaml"
GRANT_REF = "refs/kirje/authority/T202C3-A006"
ROLES = %w[spec_compliance engineering_security qa_evidence].freeze
REVIEWS = {
  "spec_compliance" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F010-spec-review.yaml",
  "engineering_security" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F010-engineering-review.yaml",
  "qa_evidence" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F010-qa-review.yaml"
}.freeze
AUTH = ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F010-authorization.yaml"
IMPL_REVIEWS = {
  "spec_compliance" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F010-implementation-spec-review.yaml",
  "engineering_security" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F010-implementation-engineering-review.yaml",
  "qa_evidence" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F010-implementation-qa-review.yaml"
}.freeze
INTEGRATION = ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F010-integration.yaml"
A_PATHS = [*REVIEWS.values, AUTH].sort.freeze
I_PATHS = [*IMPL_REVIEWS.values, INTEGRATION].sort.freeze
MANDATORY = ["crates/kirje-store/src/authority.rs", "crates/kirje-store/tests/authority_registry.rs"].freeze
FIXTURES = "crates/kirje-store/tests/fixtures/authority/registry/account_credential_cleanup/"
ZERO = "0" * 40

class Failure < StandardError; end
def check(value, message)
  raise Failure, message unless value
end
def exact(hash, keys, label) = check(hash.is_a?(Hash) && hash.keys.sort == keys.sort, "#{label}: exact keys required")
def oid?(value) = value.is_a?(String) && value.match?(/\A[0-9a-f]{40}\z/)
def nonempty?(value) = value.is_a?(String) && !value.strip.empty?

def git(root, *args, ok: false)
  env = { "GIT_NO_REPLACE_OBJECTS" => "1" }
  out, err, status = Open3.capture3(env, "git", *args, chdir: root)
  return [out, status] if ok
  raise Failure, "git #{args.first}: #{err.strip}" unless status.success?
  out
end

def no_yaml_hazards(node, label)
  raise Failure, "#{label}: aliases forbidden" if node.is_a?(Psych::Nodes::Alias)
  if node.respond_to?(:tag) && node.tag&.start_with?("!")
    raise Failure, "#{label}: custom tags forbidden"
  end
  if node.is_a?(Psych::Nodes::Mapping)
    keys = []
    node.children.each_slice(2) do |key, value|
      check(key.is_a?(Psych::Nodes::Scalar), "#{label}: non-string key forbidden")
      check(key.tag.nil? || key.tag == "tag:yaml.org,2002:str", "#{label}: non-string key forbidden")
      check(!keys.include?(key.value), "#{label}: duplicate key #{key.value}")
      keys << key.value
      no_yaml_hazards(value, label)
    end
  elsif node.respond_to?(:children) && node.children
    node.children.each { |child| no_yaml_hazards(child, label) }
  end
end

def string_keys(value, label)
  case value
  when Hash
    value.each do |key, item|
      check(key.is_a?(String), "#{label}: non-string key forbidden")
      string_keys(item, label)
    end
  when Array then value.each { |item| string_keys(item, label) }
  end
end

def yaml(text, label)
  stream = Psych.parse_stream(text, filename: label)
  check(stream.children.length == 1, "#{label}: one document required")
  no_yaml_hazards(stream, label)
  value = Psych.safe_load(text, permitted_classes: [Date], permitted_symbols: [], aliases: false, filename: label)
  check(value.is_a?(Hash), "#{label}: mapping required")
  string_keys(value, label)
  value
rescue Psych::Exception => e
  raise Failure, "#{label}: #{e.message}"
end

def verify_oid(root, oid, label)
  check(oid?(oid), "#{label}: invalid oid")
  _out, status = git(root, "cat-file", "-e", "#{oid}^{commit}", ok: true)
  check(status.success?, "#{label}: missing commit")
end
def tree(root, oid) = git(root, "rev-parse", "#{oid}^{tree}").strip
def direct_values(parents, expected, label) = check(parents == [expected], "#{label}: wrong direct single parent")
def direct(root, child, expected, label)
  parents = git(root, "rev-list", "--parents", "-n", "1", child).split.drop(1)
  direct_values(parents, expected, label)
end
def blob(root, oid, path) = git(root, "show", "#{oid}:#{path}")

def git_integrity(root)
  git_dir = git(root, "rev-parse", "--git-dir").strip
  git_dir = File.expand_path(git_dir, root)
  check(!File.exist?(File.join(git_dir, "shallow")) || File.zero?(File.join(git_dir, "shallow")), "shallow repository forbidden")
  check(!File.exist?(File.join(git_dir, "info/grafts")) || File.zero?(File.join(git_dir, "info/grafts")), "grafts forbidden")
  check(git(root, "for-each-ref", "--format=%(refname)", "refs/replace").empty?, "replace refs forbidden")
end

def current_clean(root, oid)
  check(git(root, "rev-parse", "HEAD").strip == oid, "phase oid must equal HEAD")
  check(git(root, "status", "--porcelain=v1", "-z").empty?, "worktree/index must be clean")
end

def raw_diff(root, old, new)
  fields = git(root, "diff-tree", "--no-commit-id", "--raw", "-z", "-r", "--no-renames", old, new).split("\0").reject(&:empty?)
  check(fields.length.even?, "raw diff malformed")
  fields.each_slice(2).map do |header, path|
    match = header.match(/\A:(\d{6}) (\d{6}) ([0-9a-f]{40}) ([0-9a-f]{40}) ([A-Z])\z/)
    check(match, "raw diff entry malformed")
    { "path" => path, "status" => match[5], "old_mode" => match[1], "new_mode" => match[2] }
  end.sort_by { |entry| entry.fetch("path") }
end

def exact_added(entries, paths, label)
  check(entries.map { |e| e.fetch("path") } == paths, "#{label}: exact four paths required")
  entries.each { |e| check(e == { "path" => e.fetch("path"), "status" => "A", "old_mode" => "000000", "new_mode" => "100644" }, "#{label}: regular additions only") }
end

def validate_candidate_entries(entries)
  check(!entries.empty?, "candidate: empty diff")
  paths = entries.map { |e| e.fetch("path") }
  check(MANDATORY.all? { |path| paths.include?(path) }, "candidate: mandatory source/test missing")
  entries.each do |entry|
    allowed = MANDATORY.include?(entry.fetch("path")) || entry.fetch("path").start_with?(FIXTURES)
    check(allowed, "candidate: extra path")
    check(%w[A M].include?(entry.fetch("status")), "candidate: forbidden status")
    check(entry.fetch("new_mode") == "100644", "candidate: symlink/submodule/executable forbidden")
    check(entry.fetch("old_mode") == "100644" || (entry.fetch("status") == "A" && entry.fetch("old_mode") == "000000"), "candidate: old mode forbidden")
  end
  entries
end

def residual(value, findings, label)
  exact(value, %w[status items], "#{label}.residual_risk")
  check(%w[none accepted_nonblocking].include?(value.fetch("status")), "#{label}: residual status")
  items = value.fetch("items"); check(items.is_a?(Array), "#{label}: residual items array")
  items.each do |item|
    exact(item, %w[severity finding_id disposition blocking_dimension], "#{label}.residual_item")
    check(%w[MEDIUM LOW].include?(item.fetch("severity")), "#{label}: residual severity")
    check(nonempty?(item.fetch("finding_id")) && nonempty?(item.fetch("disposition")), "#{label}: residual text")
    check(item.fetch("blocking_dimension") == "none", "#{label}: blocking residual cannot pass")
  end
  check(items.count { |i| i["severity"] == "MEDIUM" } == findings.fetch("medium"), "#{label}: medium disposition count")
  check(items.count { |i| i["severity"] == "LOW" } == findings.fetch("low"), "#{label}: low disposition count")
  check((items.empty? && value["status"] == "none") || (!items.empty? && value["status"] == "accepted_nonblocking"), "#{label}: residual state mismatch")
end

def validate_review(doc, role, commit, commit_tree, label)
  exact(doc, %w[schema_version review_kind status reviewed_packet_commit reviewed_packet_tree findings residual_risk], label)
  check(doc["schema_version"] == 1 && doc["review_kind"] == role && doc["status"] == "PASS", "#{label}: role/status")
  check(doc["reviewed_packet_commit"] == commit && doc["reviewed_packet_tree"] == commit_tree, "#{label}: wrong commit/tree")
  findings = doc.fetch("findings"); exact(findings, %w[critical high medium low], "#{label}.findings")
  findings.each_value { |count| check(count.is_a?(Integer) && count >= 0, "#{label}: finding count") }
  check(findings["critical"].zero? && findings["high"].zero?, "#{label}: blocking finding")
  residual(doc.fetch("residual_risk"), findings, label)
end

def validate_impl_review(doc, role, commit, commit_tree, label)
  exact(doc, %w[schema_version review_kind status candidate_commit candidate_tree findings residual_risk], label)
  check(doc["schema_version"] == 1 && doc["review_kind"] == role && doc["status"] == "PASS", "#{label}: role/status")
  check(doc["candidate_commit"] == commit && doc["candidate_tree"] == commit_tree, "#{label}: wrong commit/tree")
  findings = doc.fetch("findings"); exact(findings, %w[critical high medium low], "#{label}.findings")
  findings.each_value { |count| check(count.is_a?(Integer) && count >= 0, "#{label}: finding count") }
  check(findings["critical"].zero? && findings["high"].zero?, "#{label}: blocking finding")
  residual(doc.fetch("residual_risk"), findings, label)
end

def validate_auth(doc, p_oid, p_tree)
  exact(doc, %w[schema_version status reviewed_packet_commit reviewed_packet_tree review_paths authority_basis grant_ref grant_state], "authorization")
  check(doc["schema_version"] == 1 && doc["status"] == "AUTHORIZED", "authorization: status")
  check(doc["reviewed_packet_commit"] == p_oid && doc["reviewed_packet_tree"] == p_tree, "authorization: wrong packet")
  check(doc["review_paths"] == REVIEWS && doc["authority_basis"] == "f010_packet_reviews", "authorization: basis/reviews")
  check(doc["grant_ref"] == GRANT_REF && doc["grant_state"] == "unspent_one_time", "authorization: grant")
end

def validate_packet(doc)
  check(doc["packet_id"] == "007-T110-T202C3-A006-F010" && doc["status"] == "ready_for_f010_packet_review", "packet: identity/status")
  check(doc.dig("codebase_context", "baseline_head") == BASELINE, "packet: baseline")
  permissions = doc.fetch("execution_constraints")
  %w[production_permission test_permission fixture_permission].each { |key| check(permissions[key] == "none_pending_f010_authorization_record", "packet: open permission") }
  check(permissions["future_allowed_files"] == [*MANDATORY, "#{FIXTURES}**"], "packet: scope")
  check(doc.dig("authority_dag", "grant_ref") == GRANT_REF, "packet: grant ref")
  check(doc.dig("review_schemas", "roles") == REVIEWS, "packet: packet review role paths")
  check(doc.dig("review_schemas", "implementation_review", "roles") == IMPL_REVIEWS, "packet: implementation role paths")
end

def structured_strings(value, strings = [])
  case value
  when Hash then value.each_value { |item| structured_strings(item, strings) }
  when Array then value.each { |item| structured_strings(item, strings) }
  when String then strings << value
  end
  strings
end

def command_result(item, keys, exit_zero, label)
  exact(item, keys, label)
  check(nonempty?(item["command"]), "#{label}: command")
  check(item["exit_code"].is_a?(Integer) && (exit_zero ? item["exit_code"].zero? : !item["exit_code"].zero?), "#{label}: exit code")
  text_key = keys.include?("summary") ? "summary" : "failure_summary"
  check(nonempty?(item[text_key]), "#{label}: summary")
end

def validate_integration(doc, packet, p_oid, a_oid, c_oid, c_tree, changes)
  keys = %w[schema_version status packet_commit authorization_commit candidate_commit candidate_tree candidate_changes red_observed green_passed validations cargo_deny implementation_review_paths grant_ref grant_state consumed_candidate]
  exact(doc, keys, "integration")
  check(doc["schema_version"] == 1 && doc["status"] == "review_complete", "integration: status")
  check(doc["packet_commit"] == p_oid && doc["authorization_commit"] == a_oid, "integration: P/A")
  check(doc["candidate_commit"] == c_oid && doc["candidate_tree"] == c_tree && doc["consumed_candidate"] == c_oid, "integration: C")
  check(doc["candidate_changes"] == changes, "integration: candidate changes")
  red = doc["red_observed"]; green = doc["green_passed"]
  check(red.is_a?(Array) && !red.empty? && green.is_a?(Array) && !green.empty?, "integration: RED/GREEN required")
  red.each { |item| command_result(item, %w[command exit_code failure_summary], false, "integration.red") }
  green.each { |item| command_result(item, %w[command exit_code summary], true, "integration.green") }
  commands = [*packet.dig("validation_loop", "focused"), *packet.dig("validation_loop", "complete")]
  validations = doc["validations"]; check(validations.is_a?(Array) && validations.length == commands.length, "integration: validation coverage")
  validations.each_with_index do |item, index|
    command_result(item, %w[command exit_code summary], true, "integration.validation")
    check(item["command"] == commands[index], "integration: validation command mismatch")
  end
  cargo = doc["cargo_deny"]; exact(cargo, %w[status summary], "integration.cargo_deny")
  check(cargo["status"] == "known_t111_blocker" && nonempty?(cargo["summary"]), "integration: cargo deny")
  check(doc["implementation_review_paths"] == IMPL_REVIEWS, "integration: implementation paths")
  check(doc["grant_ref"] == GRANT_REF && doc["grant_state"] == "spent_non_replayable", "integration: grant")
  structured_strings(doc).each { |text| check(!text.match?(/NOT[ _-]*VALIDATED|\bFAIL(?:ED|URE)?\b/i), "integration: contradictory structured text") }
end

def ref_value(root)
  out, status = git(root, "show-ref", "--verify", "--hash", GRANT_REF, ok: true)
  status.success? ? out.strip : nil
end
def expected_ref(actual, expected, label) = check(actual == expected, "#{label}: wrong dedicated ref")
def grant_reflog(root) = git(root, "reflog", "show", "--format=%H", GRANT_REF).lines.map(&:strip)

def read_phase(root, phase, ids)
  git_integrity(root); ids.each_with_index { |oid, index| verify_oid(root, oid, "oid#{index}") }
  current_clean(root, ids.last)
  p_oid = ids[0]; direct(root, p_oid, BASELINE, "P10")
  packet = yaml(blob(root, p_oid, PACKET), "packet"); validate_packet(packet)
  if phase == "preparation"
    expected_ref(ref_value(root), nil, "preparation")
    [*A_PATHS, *I_PATHS].each { |path| _out, status = git(root, "cat-file", "-e", "#{p_oid}:#{path}", ok: true); check(!status.success?, "preparation: premature artifact") }
    return
  end
  a_oid = ids[1]; direct(root, a_oid, p_oid, "A10"); exact_added(raw_diff(root, p_oid, a_oid), A_PATHS, "A10")
  ROLES.each { |role| validate_review(yaml(blob(root, a_oid, REVIEWS[role]), "review"), role, p_oid, tree(root, p_oid), "review.#{role}") }
  validate_auth(yaml(blob(root, a_oid, AUTH), "authorization"), p_oid, tree(root, p_oid))
  if phase == "authorization"
    expected_ref(ref_value(root), a_oid, "authorization")
    check(grant_reflog(root) == [a_oid], "authorization: grant reflog must contain only A10")
    return
  end
  c_oid = ids[2]; direct(root, c_oid, a_oid, "C10"); changes = validate_candidate_entries(raw_diff(root, a_oid, c_oid))
  expected_ref(ref_value(root), c_oid, "candidate")
  check(grant_reflog(root) == [c_oid, a_oid], "candidate: grant reflog must contain A10 then C10")
  return if phase == "candidate"
  i_oid = ids[3]; direct(root, i_oid, c_oid, "I10"); exact_added(raw_diff(root, c_oid, i_oid), I_PATHS, "I10")
  ROLES.each { |role| validate_impl_review(yaml(blob(root, i_oid, IMPL_REVIEWS[role]), "implementation review"), role, c_oid, tree(root, c_oid), "implementation_review.#{role}") }
  integration = yaml(blob(root, i_oid, INTEGRATION), "integration")
  validate_integration(integration, packet, p_oid, a_oid, c_oid, tree(root, c_oid), changes)
  check(grant_reflog(root) == [c_oid, a_oid], "integration: grant reflog must record only A10 then C10")
end

def sample_review
  { "schema_version" => 1, "review_kind" => "spec_compliance", "status" => "PASS", "reviewed_packet_commit" => "a" * 40, "reviewed_packet_tree" => "b" * 40, "findings" => { "critical" => 0, "high" => 0, "medium" => 0, "low" => 0 }, "residual_risk" => { "status" => "none", "items" => [] } }
end

def expect(label)
  yield; raise Failure, "self-test #{label}: expected failure"
rescue Failure => e
  raise if e.message.start_with?("self-test #{label}: expected failure")
end

def self_test
  cases = 0
  expect("duplicate status") { yaml("status: PASS\nstatus: PASS\n", "duplicate") }; cases += 1
  review = sample_review.merge("extra" => true); expect("unknown key") { validate_review(review, "spec_compliance", "a" * 40, "b" * 40, "review") }; cases += 1
  expect("wrong role") { validate_review(sample_review, "qa_evidence", "a" * 40, "b" * 40, "review") }; cases += 1
  expect("wrong commit tree") { validate_review(sample_review, "spec_compliance", "c" * 40, "b" * 40, "review") }; cases += 1
  expect("wrong ref") { expected_ref("a" * 40, "b" * 40, "ref") }; cases += 1
  expect("empty candidate") { validate_candidate_entries([]) }; cases += 1
  base = MANDATORY.map { |path| { "path" => path, "status" => "M", "old_mode" => "100644", "new_mode" => "100644" } }
  expect("extra candidate path") { validate_candidate_entries(base + [{ "path" => "rogue", "status" => "A", "old_mode" => "000000", "new_mode" => "100644" }]) }; cases += 1
  bad_mode = base.map(&:dup); bad_mode[0]["new_mode"] = "120000"; expect("symlink mode") { validate_candidate_entries(bad_mode) }; cases += 1
  expect("wrong parent") { direct_values(["a" * 40], "b" * 40, "edge") }; cases += 1
  expect("sibling candidate") { direct_values(["c" * 40], "a" * 40, "candidate") }; cases += 1
  packet = { "validation_loop" => { "focused" => ["focused"], "complete" => ["complete"] } }
  integration = { "schema_version" => 1, "status" => "review_complete", "packet_commit" => "a" * 40, "authorization_commit" => "b" * 40, "candidate_commit" => "c" * 40, "candidate_tree" => "d" * 40, "candidate_changes" => base, "red_observed" => [], "green_passed" => [], "validations" => [], "cargo_deny" => { "status" => "known_t111_blocker", "summary" => "baseline" }, "implementation_review_paths" => IMPL_REVIEWS, "grant_ref" => GRANT_REF, "grant_state" => "spent_non_replayable", "consumed_candidate" => "c" * 40 }
  expect("empty validation") { validate_integration(integration, packet, "a" * 40, "b" * 40, "c" * 40, "d" * 40, base) }; cases += 1
  expect("wrong review path") { validate_auth({ "schema_version" => 1, "status" => "AUTHORIZED", "reviewed_packet_commit" => "a" * 40, "reviewed_packet_tree" => "b" * 40, "review_paths" => {}, "authority_basis" => "f010_packet_reviews", "grant_ref" => GRANT_REF, "grant_state" => "unspent_one_time" }, "a" * 40, "b" * 40) }; cases += 1
  puts("a006_dag_validator_self_test=pass cases=#{cases}")
end

begin
  phase = ARGV.shift.to_s
  if phase == "--self-test"
    check(ARGV.empty?, "self-test takes no oids"); self_test
  else
    counts = { "preparation" => 1, "authorization" => 2, "candidate" => 3, "integration" => 4 }
    check(counts.key?(phase) && ARGV.length == counts[phase], "usage: phase plus explicit commit oids")
    read_phase(ROOT, phase, ARGV)
    puts("a006_dag_validator=#{phase} pass")
  end
rescue Failure, KeyError, TypeError, Errno::ENOENT => e
  warn("a006_dag_validator: #{e.message}"); exit(1)
end
