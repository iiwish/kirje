#!/usr/bin/env ruby
# frozen_string_literal: true

require "date"
require "digest"
require "fileutils"
require "tmpdir"
require "yaml"

ROOT = File.expand_path("../..", __dir__)
PACKET = ".ai-platform/specs/007-stable-v1-program/packets/T110-A006.yaml"
AGGREGATE = ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F007-packet-review.md"
ATTEMPT = ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F007.md"
SUMMARY = ".ai-platform/evidence/T202C3/summary.md"
TEST_RESULTS = ".ai-platform/evidence/T202C3/test-results.md"

ATTEMPT_PARTS = %w[T202C3 A006 F007].freeze
ATTEMPT_NAME = ATTEMPT_PARTS.join("-")
TOKEN_PREFIX = ATTEMPT_PARTS.join("_")
GATE_START = ["<!-- A006", "AUTHORITY", "GATE", "START"].join("_")
GATE_END = ["A006", "AUTHORITY", "GATE", "END -->"].join("_")
LINK_START = ["<!-- A006", "INTEGRATION", "LINK", "START"].join("_")
LINK_END = ["A006", "INTEGRATION", "LINK", "END -->"].join("_")

ACTIVE_PATHS = {
  "constitution" => ".ai-platform/memory/constitution.md",
  "product_contract" => ".ai-platform/specs/007-stable-v1-program/spec.md",
  "requirements_checklist" => ".ai-platform/specs/007-stable-v1-program/checklists/requirements.md",
  "program_plan" => ".ai-platform/specs/007-stable-v1-program/plan.md",
  "work_graph" => ".ai-platform/specs/007-stable-v1-program/tasks.md",
  "program_analysis" => ".ai-platform/specs/007-stable-v1-program/analysis.md",
  "security_spec" => ".ai-platform/specs/008-security-baseline/spec.md",
  "security_plan" => ".ai-platform/specs/008-security-baseline/plan.md",
  "security_analysis" => ".ai-platform/specs/008-security-baseline/analysis.md",
  "security_work_graph" => ".ai-platform/specs/008-security-baseline/tasks.md",
  "authority_contract" => ".ai-platform/specs/008-security-baseline/contracts/authority-store.md",
  "authorization_contract" => ".ai-platform/specs/008-security-baseline/contracts/authorization.md",
  "account_contract" => ".ai-platform/specs/008-security-baseline/contracts/account-config-v2.md",
  "data_model" => ".ai-platform/specs/008-security-baseline/data-model.md",
  "authority_audit_script" => ".ai-platform/scripts/audit_a006_authority.rb",
  "predecessor_evidence" => ".ai-platform/evidence/T202C3/attempts/T202C3-A005.md",
  "aggregate_packet_review" => AGGREGATE,
  "execution_packet" => PACKET,
  "attempt_status" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006.md",
  "evidence_summary" => SUMMARY,
  "test_results" => TEST_RESULTS
}.freeze

POST_INTEGRATION_PATHS = ACTIVE_PATHS.merge("attempt_evidence" => ATTEMPT).freeze

PACKET_GOVERNANCE_PATHS = {
  "constitution" => ACTIVE_PATHS.fetch("constitution"),
  "product_contract" => ACTIVE_PATHS.fetch("product_contract"),
  "requirements_checklist" => ACTIVE_PATHS.fetch("requirements_checklist"),
  "program_plan" => ACTIVE_PATHS.fetch("program_plan"),
  "work_graph" => ACTIVE_PATHS.fetch("work_graph"),
  "analysis" => ACTIVE_PATHS.fetch("program_analysis"),
  "security_spec" => ACTIVE_PATHS.fetch("security_spec"),
  "security_plan" => ACTIVE_PATHS.fetch("security_plan"),
  "security_analysis" => ACTIVE_PATHS.fetch("security_analysis"),
  "security_work_graph" => ACTIVE_PATHS.fetch("security_work_graph"),
  "authority_contract" => ACTIVE_PATHS.fetch("authority_contract"),
  "authorization_contract" => ACTIVE_PATHS.fetch("authorization_contract"),
  "account_contract" => ACTIVE_PATHS.fetch("account_contract"),
  "data_model" => ACTIVE_PATHS.fetch("data_model"),
  "authority_audit_script" => ACTIVE_PATHS.fetch("authority_audit_script"),
  "predecessor_evidence" => ACTIVE_PATHS.fetch("predecessor_evidence"),
  "historical_packet_review_evidence" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-packet-review.md",
  "failed_f001_packet_review_evidence" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F001-packet-review.md",
  "failed_f002_packet_review_evidence" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F002-packet-review.md",
  "failed_f003_packet_review_evidence" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F003-packet-review.md",
  "failed_f004_packet_review_evidence" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F004-packet-review.md",
  "failed_f005_packet_review_evidence" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F005-packet-review.md",
  "failed_f006_packet_review_evidence" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F006-packet-review.md",
  "f007_packet_review_evidence" => AGGREGATE
}.freeze

HISTORICAL_FAILED = {
  "f001" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F001-packet-review.md",
  "f002" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F002-packet-review.md",
  "f003" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F003-packet-review.md",
  "f004" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F004-packet-review.md",
  "f005" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F005-packet-review.md",
  "f006" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F006-packet-review.md"
}.freeze

HISTORICAL_PASS = {
  "initial_a006_packet_review" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-packet-review.md"
}.freeze

PRE_ACTIVE_COUNT = 21
POST_AUTH_ACTIVE_COUNT = 21
POST_INTEGRATION_ACTIVE_COUNT = 22
PRE_PRODUCTION_PERMISSION = "none_pending_three_independent_f007_packet_reviews"
PRE_TEST_PERMISSION = PRE_PRODUCTION_PERMISSION
POST_PRODUCTION_PERMISSION = "exact_authority_rs_scope_authorized"
POST_TEST_PERMISSION = "exact_registry_and_cleanup_fixture_scope_authorized"
FUTURE_ALLOWED_FILES = [
  "crates/kirje-store/src/authority.rs",
  "crates/kirje-store/tests/authority_registry.rs",
  "crates/kirje-store/tests/fixtures/authority/registry/account_credential_cleanup/**"
].freeze

REVIEW_NAMES = %w[spec_compliance engineering_security qa_evidence].freeze
FINDING_NAMES = %w[critical high medium low].freeze

class AuditFailure < StandardError; end

def assert_audit(condition, message)
  raise AuditFailure, message unless condition
end

def normalize(value)
  value.to_s.gsub(/[`*]/, "").strip.gsub(/\s+/, " ").upcase
end

def token(suffix)
  ([TOKEN_PREFIX] + Array(suffix)).join("_")
end

def current_tokens
  {
    "packet_review" => token(%w[PACKET REVIEW PASS]),
    "spec_compliance" => token(%w[SPEC REVIEW PASS]),
    "engineering_security" => token(%w[ENGINEERING SECURITY REVIEW PASS]),
    "qa_evidence" => token(%w[QA EVIDENCE REVIEW PASS]),
    "execution_authorization" => token(%w[EXECUTION AUTHORIZED]),
    "governance_followup" => token(%w[GOVERNANCE FOLLOWUP COMPLETE])
  }
end

def reject_duplicate_yaml_keys(node, label)
  if node.is_a?(Psych::Nodes::Mapping)
    keys = []
    node.children.each_slice(2) do |key_node, value_node|
      assert_audit(key_node.is_a?(Psych::Nodes::Scalar), "#{label}: non-scalar YAML key")
      key = key_node.value.to_s
      assert_audit(!keys.include?(key), "#{label}: duplicate YAML key #{key}")
      keys << key
      reject_duplicate_yaml_keys(value_node, label)
    end
  elsif node.respond_to?(:children) && node.children
    node.children.each { |child| reject_duplicate_yaml_keys(child, label) }
  end
end

def strict_yaml_load(content, label)
  stream = Psych.parse_stream(content, filename: label)
  assert_audit(stream.children.length == 1, "#{label}: expected one YAML document")
  reject_duplicate_yaml_keys(stream, label)
  value = YAML.safe_load(
    content,
    permitted_classes: [Date],
    permitted_symbols: [],
    aliases: false,
    filename: label
  )
  assert_audit(value.is_a?(Hash), "#{label}: YAML root must be a mapping")
  value
rescue Psych::SyntaxError, Psych::DisallowedClass => e
  raise AuditFailure, "#{label}: invalid YAML: #{e.message}"
end

def read_complete(root, relative_path)
  path = File.join(root, relative_path)
  assert_audit(File.file?(path), "missing path #{relative_path}")
  assert_audit(File.readable?(path), "unreadable path #{relative_path}")
  File.binread(path).force_encoding(Encoding::UTF_8).encode(
    Encoding::UTF_8,
    invalid: :replace,
    undef: :replace
  )
end

def audit_allowlist_definition(actual, expected, expected_count, label)
  assert_audit(actual.keys == expected.keys, "#{label}: exact key set mismatch")
  assert_audit(actual == expected, "#{label}: exact key/path map mismatch")
  assert_audit(actual.length == expected_count, "#{label}: count #{actual.length}, expected #{expected_count}")
  assert_audit(actual.values.uniq.length == actual.length, "#{label}: duplicate canonical path")
end

def read_allowlist(root, paths)
  paths.to_h { |key, path| [key, read_complete(root, path)] }
end

def visible_status(content, label)
  headings = content.scan(/^[ \t]*##[ \t]+Status[ \t]*$/)
  assert_audit(headings.length == 1, "#{label}: expected one visible Status heading")
  matches = content.scan(/^[ \t]*##[ \t]+Status[ \t]*\r?\n(?:[ \t]*\r?\n)*[ \t]*`([^`\r\n]+)`[ \t]*$/)
  assert_audit(matches.length == 1, "#{label}: expected one visible Status field")
  normalize(matches.first.first)
end

def visible_authority_fields(content, label)
  fields = Hash.new { |hash, key| hash[key] = [] }
  content.each_line do |line|
    match = line.match(/^[ \t]*- (Execution authorization|Review token|Governance follow-up):[ \t]*(.*?)[ \t]*\r?\n?$/i)
    next unless match

    key = {
      "execution authorization" => "execution_authorization",
      "review token" => "review_token",
      "governance follow-up" => "governance_followup"
    }.fetch(match[1].downcase)
    fields[key] << normalize(match[2])
  end
  fields.each do |key, values|
    assert_audit(values.length == 1, "#{label}: duplicate visible #{key} field")
  end
  fields.transform_values(&:first)
end

def visible_review_rows(content, label)
  labels = {
    "SPEC COMPLIANCE" => "spec_compliance",
    "ENGINEERING/SECURITY" => "engineering_security",
    "QA/EVIDENCE" => "qa_evidence"
  }
  rows = {}
  content.each_line do |line|
    match = line.match(/^\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*$/)
    next unless match

    name = labels[normalize(match[1])]
    next unless name

    assert_audit(!rows.key?(name), "#{label}: duplicate visible review row #{name}")
    rows[name] = { "status" => normalize(match[2]), "findings" => normalize(match[3]) }
  end
  assert_audit(rows.keys.sort == REVIEW_NAMES.sort, "#{label}: visible review rows mismatch")
  rows
end

def authority_blocks(content, label)
  starts = content.scan(Regexp.new(Regexp.escape(GATE_START))).length
  ends = content.scan(Regexp.new(Regexp.escape(GATE_END))).length
  assert_audit(starts == ends, "#{label}: unbalanced authority-gate markers")
  pattern = /#{Regexp.escape(GATE_START)}\r?\n(.*?)\r?\n#{Regexp.escape(GATE_END)}/m
  blocks = content.scan(pattern).map(&:first)
  assert_audit(blocks.length == starts, "#{label}: malformed authority-gate block")
  blocks
end

def integration_blocks(content, label)
  starts = content.scan(Regexp.new(Regexp.escape(LINK_START))).length
  ends = content.scan(Regexp.new(Regexp.escape(LINK_END))).length
  assert_audit(starts == ends, "#{label}: unbalanced integration-link markers")
  pattern = /#{Regexp.escape(LINK_START)}\r?\n(.*?)\r?\n#{Regexp.escape(LINK_END)}/m
  blocks = content.scan(pattern).map(&:first)
  assert_audit(blocks.length == starts, "#{label}: malformed integration-link block")
  blocks
end

def exact_keys(hash, expected, label)
  assert_audit(hash.is_a?(Hash), "#{label}: expected mapping")
  keys = hash.keys.map(&:to_s)
  assert_audit(keys.sort == expected.sort, "#{label}: field set mismatch")
end

def audit_gate_schema(gate, phase)
  exact_keys(
    gate,
    %w[state packet_review_token execution_authorization governance_followup reviews],
    "authority_gate"
  )
  reviews = gate.fetch("reviews")
  exact_keys(reviews, REVIEW_NAMES, "authority_gate.reviews")

  expected_tokens = current_tokens
  if phase == "pre-review"
    assert_audit(normalize(gate.fetch("state")) == "PENDING_REVIEW", "authority_gate: pending state mismatch")
    %w[packet_review_token execution_authorization governance_followup].each do |field|
      assert_audit(normalize(gate.fetch(field)) == "NONE", "authority_gate: pending #{field} mismatch")
    end
    REVIEW_NAMES.each do |name|
      review = reviews.fetch(name)
      exact_keys(review, %w[status token findings], "authority_gate.reviews.#{name}")
      assert_audit(normalize(review.fetch("status")) == "PENDING", "#{name}: pending status mismatch")
      assert_audit(normalize(review.fetch("token")) == "NONE", "#{name}: pending token mismatch")
      assert_audit(review.fetch("findings").nil?, "#{name}: pending findings must be null")
    end
    return
  end

  assert_audit(normalize(gate.fetch("state")) == "PASSED_AUTHORIZED_FOR_EXECUTION", "authority_gate: authorized state mismatch")
  assert_audit(normalize(gate.fetch("packet_review_token")) == expected_tokens.fetch("packet_review"), "authority_gate: packet-review token mismatch")
  assert_audit(normalize(gate.fetch("execution_authorization")) == expected_tokens.fetch("execution_authorization"), "authority_gate: execution token mismatch")
  assert_audit(normalize(gate.fetch("governance_followup")) == expected_tokens.fetch("governance_followup"), "authority_gate: follow-up token mismatch")
  REVIEW_NAMES.each do |name|
    review = reviews.fetch(name)
    exact_keys(review, %w[status token findings], "authority_gate.reviews.#{name}")
    assert_audit(normalize(review.fetch("status")) == "PASSED_ZERO_FINDINGS", "#{name}: authorized status mismatch")
    assert_audit(normalize(review.fetch("token")) == expected_tokens.fetch(name), "#{name}: review token mismatch")
    findings = review.fetch("findings")
    exact_keys(findings, FINDING_NAMES, "authority_gate.reviews.#{name}.findings")
    FINDING_NAMES.each do |finding|
      assert_audit(findings.fetch(finding) == 0, "#{name}: #{finding} must be zero")
    end
  end
end

def audit_aggregate(content, phase)
  blocks = authority_blocks(content, "aggregate")
  assert_audit(blocks.length == 1, "aggregate: expected one authority-gate block")
  gate_document = strict_yaml_load(blocks.first, "aggregate authority gate")
  exact_keys(gate_document, ["authority_gate"], "aggregate authority document")
  gate = gate_document.fetch("authority_gate")
  audit_gate_schema(gate, phase)

  status = visible_status(content, "aggregate")
  fields = visible_authority_fields(content, "aggregate")
  exact_keys(fields, %w[execution_authorization review_token governance_followup], "aggregate visible authority")
  rows = visible_review_rows(content, "aggregate")
  if phase == "pre-review"
    assert_audit(status == "PENDING_THREE_INDEPENDENT_REVIEWS", "aggregate: visible pending status mismatch")
    fields.each_value { |value| assert_audit(value == "NONE", "aggregate: visible pending authority mismatch") }
    rows.each_value do |row|
      assert_audit(row == { "status" => "PENDING", "findings" => "NOT ASSESSED" }, "aggregate: visible pending review mismatch")
    end
  else
    tokens = current_tokens
    assert_audit(status == "PASSED_AUTHORIZED_FOR_EXECUTION", "aggregate: visible authorized status mismatch")
    assert_audit(fields.fetch("execution_authorization") == tokens.fetch("execution_authorization"), "aggregate: visible execution mismatch")
    assert_audit(fields.fetch("review_token") == tokens.fetch("packet_review"), "aggregate: visible packet-review mismatch")
    assert_audit(fields.fetch("governance_followup") == tokens.fetch("governance_followup"), "aggregate: visible follow-up mismatch")
    rows.each_value do |row|
      assert_audit(row == { "status" => "PASS", "findings" => "C0/H0/M0/L0" }, "aggregate: visible authorized review mismatch")
    end
  end
  gate
end

def collect_ai_paths(value, paths = [])
  case value
  when Hash
    value.each_value { |nested| collect_ai_paths(nested, paths) }
  when Array
    value.each { |nested| collect_ai_paths(nested, paths) }
  when String
    paths << value if value.start_with?(".ai-platform/")
  end
  paths
end

def audit_packet_paths(packet)
  inputs = packet.fetch("governance_inputs")
  assert_audit(inputs.is_a?(Hash), "packet: governance_inputs must be a mapping")
  direct = inputs.each_with_object({}) do |(key, value), paths|
    paths[key.to_s] = value if value.is_a?(String) && value.start_with?(".ai-platform/")
  end
  assert_audit(direct == PACKET_GOVERNANCE_PATHS, "packet: governance key/path allowlist mismatch")
  all_paths = collect_ai_paths(inputs)
  assert_audit(all_paths.sort == PACKET_GOVERNANCE_PATHS.values.sort, "packet: nested or missing governance path")
  assert_audit(all_paths.uniq.length == all_paths.length, "packet: duplicate governance path")
end

def audit_packet(packet, phase)
  audit_packet_paths(packet)
  work_unit = packet.fetch("work_unit")
  assert_audit(work_unit.fetch("attempt") == ATTEMPT_NAME, "packet: attempt mismatch")
  constraints = packet.fetch("execution_constraints")
  allowed_files = constraints.fetch("future_allowed_files")
  assert_audit(allowed_files == FUTURE_ALLOWED_FILES, "packet: exact future scope mismatch")
  gate = packet.fetch("execution_gate")
  exact_keys(gate, %w[packet_review_token execution_authorization governance_followup], "packet.execution_gate")

  if phase == "pre-review"
    assert_audit(packet.fetch("status") == "ready_for_f007_packet_review", "packet: pre-review status mismatch")
    assert_audit(constraints.fetch("production_permission") == PRE_PRODUCTION_PERMISSION, "packet: pre-review production permission mismatch")
    assert_audit(constraints.fetch("test_permission") == PRE_TEST_PERMISSION, "packet: pre-review test permission mismatch")
    gate.each_value { |value| assert_audit(normalize(value) == "NONE", "packet: premature execution gate") }
  else
    tokens = current_tokens
    assert_audit(packet.fetch("status") == "ready", "packet: authorized status mismatch")
    assert_audit(constraints.fetch("production_permission") == POST_PRODUCTION_PERMISSION, "packet: authorized production permission mismatch")
    assert_audit(constraints.fetch("test_permission") == POST_TEST_PERMISSION, "packet: authorized test permission mismatch")
    assert_audit(normalize(gate.fetch("packet_review_token")) == tokens.fetch("packet_review"), "packet: authorized packet-review mismatch")
    assert_audit(normalize(gate.fetch("execution_authorization")) == tokens.fetch("execution_authorization"), "packet: authorized execution mismatch")
    assert_audit(normalize(gate.fetch("governance_followup")) == tokens.fetch("governance_followup"), "packet: authorized follow-up mismatch")
  end
end

def historical_authority_tokens(content, max_attempt: 6)
  content.scan(/\bT202C3_A006_F\d{3}_[A-Z0-9_]+\b/).select do |candidate|
    match = candidate.match(/\AT202C3_A006_F(\d{3})_(.+)\z/)
    next false unless match && match[1].to_i.between?(1, max_attempt)

    suffix = match[2]
    suffix.include?("PASS") || suffix.include?("READY") ||
      suffix.include?("AUTHORIZ") || suffix.include?("FOLLOWUP") ||
      suffix.include?("APPROVED")
  end
end

def audit_historical(contents)
  contents.each do |key, content|
    label = "historical #{key}"
    status = visible_status(content, label)
    assert_audit(%w[FAILED_NEEDS_CONTRACT_CLARIFICATION FAILED_NO_EXECUTION_AUTHORIZATION].include?(status), "#{label}: failed status mismatch")
    fields = visible_authority_fields(content, label)
    %w[execution_authorization review_token].each do |field|
      assert_audit(fields.key?(field), "#{label}: missing #{field}")
      assert_audit(fields.fetch(field) == "NONE", "#{label}: #{field} must be none")
    end
    assert_audit(historical_authority_tokens(content).empty?, "#{label}: stale execution/review authority token")
    assert_audit(authority_blocks(content, label).empty?, "#{label}: authority-gate block is forbidden")
  end
end

def audit_initial_historical_pass(contents)
  expected = ["T202C3", "A006", "PACKET", "REVIEW", "PASS"].join("_")
  contents.each do |key, content|
    assert_audit(content.scan(expected).length == 1, "historical pass #{key}: exact token mismatch")
    assert_audit(authority_blocks(content, "historical pass #{key}").empty?, "historical pass #{key}: authority gate forbidden")
  end
end

def audit_all_gate_placement(active_contents, historical_contents, pass_contents)
  combined = active_contents.merge(
    historical_contents.transform_keys { |key| "historical_failed:#{key}" },
    pass_contents.transform_keys { |key| "historical_pass:#{key}" }
  )
  combined.each do |key, content|
    blocks = authority_blocks(content, key)
    expected = key == "aggregate_packet_review" ? 1 : 0
    assert_audit(blocks.length == expected, "#{key}: authority-gate block count mismatch")
  end
end

def audit_script_source(active_contents)
  source = active_contents.fetch("authority_audit_script")
  leaked = current_tokens.values.select { |candidate| source.include?(candidate) }
  assert_audit(leaked.empty?, "authority audit script contains an exact current authority token")
end

def audit_old_active_authority(active_contents)
  active_contents.each do |key, content|
    stale = historical_authority_tokens(content)
    assert_audit(stale.empty?, "#{key}: stale F001-F006 active authority #{stale.uniq.join(', ')}")
  end
end

def expected_token_counts(phase)
  tokens = current_tokens
  expected = Hash.new { |hash, path_key| hash[path_key] = Hash.new(0) }
  return [tokens, expected] if phase == "pre-review"

  expected["aggregate_packet_review"][tokens.fetch("packet_review")] = 2
  expected["aggregate_packet_review"][tokens.fetch("execution_authorization")] = 2
  expected["aggregate_packet_review"][tokens.fetch("governance_followup")] = 2
  REVIEW_NAMES.each do |name|
    expected["aggregate_packet_review"][tokens.fetch(name)] = 1
  end
  expected["execution_packet"][tokens.fetch("packet_review")] = 1
  expected["execution_packet"][tokens.fetch("execution_authorization")] = 1
  expected["execution_packet"][tokens.fetch("governance_followup")] = 1

  if phase == "post-integration"
    tokens.each_value { |candidate| expected["attempt_evidence"][candidate] = 1 }
  end
  [tokens, expected]
end

def audit_current_token_placement(active_contents, phase)
  tokens, expected = expected_token_counts(phase)
  active_contents.each do |key, content|
    tokens.each_value do |candidate|
      count = content.scan(candidate).length
      wanted = expected[key][candidate]
      assert_audit(count == wanted, "#{key}: current token placement/count mismatch")
    end
  end
end

def sha256_file(root, relative_path)
  Digest::SHA256.file(File.join(root, relative_path)).hexdigest
end

def audit_integration(root, active_contents)
  attempt_content = active_contents.fetch("attempt_evidence")
  assert_audit(visible_status(attempt_content, "attempt evidence") == "REVIEW_COMPLETE", "attempt evidence: status mismatch")
  blocks = integration_blocks(attempt_content, "attempt evidence")
  assert_audit(blocks.length == 1, "attempt evidence: expected one integration-link block")
  document = strict_yaml_load(blocks.first, "attempt integration link")
  exact_keys(document, ["integration_link"], "attempt integration document")
  link = document.fetch("integration_link")
  exact_keys(
    link,
    %w[status attempt candidate_commit packet packet_sha256 aggregate_review aggregate_review_sha256 packet_review_token execution_authorization governance_followup review_tokens summary test_results],
    "attempt integration_link"
  )
  tokens = current_tokens
  expected = {
    "status" => "review_complete",
    "attempt" => ATTEMPT_NAME,
    "packet" => PACKET,
    "packet_sha256" => sha256_file(root, PACKET),
    "aggregate_review" => AGGREGATE,
    "aggregate_review_sha256" => sha256_file(root, AGGREGATE),
    "packet_review_token" => tokens.fetch("packet_review"),
    "execution_authorization" => tokens.fetch("execution_authorization"),
    "governance_followup" => tokens.fetch("governance_followup"),
    "summary" => SUMMARY,
    "test_results" => TEST_RESULTS
  }
  expected.each do |field, value|
    assert_audit(link.fetch(field).to_s == value, "attempt integration_link: #{field} mismatch")
  end
  candidate_commit = link.fetch("candidate_commit").to_s
  assert_audit(candidate_commit.match?(/\A[0-9a-f]{40}\z/), "attempt integration_link: candidate_commit mismatch")
  review_tokens = link.fetch("review_tokens")
  assert_audit(review_tokens.is_a?(Array), "attempt integration_link: review_tokens must be a list")
  expected_reviews = REVIEW_NAMES.map { |name| tokens.fetch(name) }.sort
  assert_audit(review_tokens.map(&:to_s).sort == expected_reviews, "attempt integration_link: review_tokens mismatch")
  %w[evidence_summary test_results].each do |key|
    content = active_contents.fetch(key)
    [ATTEMPT, AGGREGATE, candidate_commit].each do |needle|
      assert_audit(content.include?(needle), "#{key}: final integration linkage missing")
    end
  end
end

def audit_repository(root, phase)
  expected_paths = phase == "post-integration" ? POST_INTEGRATION_PATHS : ACTIVE_PATHS
  expected_count = {
    "pre-review" => PRE_ACTIVE_COUNT,
    "post-authorization" => POST_AUTH_ACTIVE_COUNT,
    "post-integration" => POST_INTEGRATION_ACTIVE_COUNT
  }.fetch(phase)
  expected_definition = phase == "post-integration" ? POST_INTEGRATION_PATHS : ACTIVE_PATHS
  audit_allowlist_definition(expected_paths, expected_definition, expected_count, "active canonical allowlist")
  audit_allowlist_definition(HISTORICAL_FAILED, HISTORICAL_FAILED, 6, "historical failed allowlist")

  active_contents = read_allowlist(root, expected_paths)
  historical_contents = read_allowlist(root, HISTORICAL_FAILED)
  pass_contents = read_allowlist(root, HISTORICAL_PASS)
  packet = strict_yaml_load(active_contents.fetch("execution_packet"), "execution packet")

  audit_packet(packet, phase == "pre-review" ? "pre-review" : "post-authorization")
  audit_historical(historical_contents)
  audit_initial_historical_pass(pass_contents)
  audit_all_gate_placement(active_contents, historical_contents, pass_contents)
  audit_script_source(active_contents)
  audit_old_active_authority(active_contents)
  audit_aggregate(active_contents.fetch("aggregate_packet_review"), phase == "pre-review" ? "pre-review" : "post-authorization")
  audit_current_token_placement(active_contents, phase)
  audit_integration(root, active_contents) if phase == "post-integration"

  {
    "phase" => phase,
    "active" => active_contents.length,
    "historical_failed" => historical_contents.length
  }
end

def fixture_packet(phase)
  authorized = phase == "post-authorization"
  tokens = current_tokens
  governance_inputs = PACKET_GOVERNANCE_PATHS.merge("approval_gates" => { "fixture" => "self-test" })
  {
    "schema_version" => 1,
    "packet_id" => "007-T110-#{ATTEMPT_NAME}",
    "task_id" => "T110",
    "feature_id" => "007-stable-v1-program",
    "mode" => "delegated_test_first_execution",
    "adapter" => "codex_worker",
    "status" => authorized ? "ready" : "ready_for_f007_packet_review",
    "governance_inputs" => governance_inputs,
    "work_unit" => { "attempt" => ATTEMPT_NAME },
    "execution_constraints" => {
      "production_permission" => authorized ? POST_PRODUCTION_PERMISSION : PRE_PRODUCTION_PERMISSION,
      "test_permission" => authorized ? POST_TEST_PERMISSION : PRE_TEST_PERMISSION,
      "future_allowed_files" => FUTURE_ALLOWED_FILES
    },
    "execution_gate" => {
      "packet_review_token" => authorized ? tokens.fetch("packet_review") : "none",
      "execution_authorization" => authorized ? tokens.fetch("execution_authorization") : "none",
      "governance_followup" => authorized ? tokens.fetch("governance_followup") : "none"
    }
  }
end

def fixture_gate(phase)
  authorized = phase == "post-authorization"
  tokens = current_tokens
  reviews = REVIEW_NAMES.to_h do |name|
    [
      name,
      {
        "status" => authorized ? "PASSED_ZERO_FINDINGS" : "PENDING",
        "token" => authorized ? tokens.fetch(name) : "none",
        "findings" => authorized ? FINDING_NAMES.to_h { |finding| [finding, 0] } : nil
      }
    ]
  end
  {
    "authority_gate" => {
      "state" => authorized ? "PASSED_AUTHORIZED_FOR_EXECUTION" : "PENDING_REVIEW",
      "packet_review_token" => authorized ? tokens.fetch("packet_review") : "none",
      "execution_authorization" => authorized ? tokens.fetch("execution_authorization") : "none",
      "governance_followup" => authorized ? tokens.fetch("governance_followup") : "none",
      "reviews" => reviews
    }
  }
end

def fixture_aggregate(phase)
  authorized = phase == "post-authorization"
  tokens = current_tokens
  status = authorized ? "PASSED_AUTHORIZED_FOR_EXECUTION" : "PENDING_THREE_INDEPENDENT_REVIEWS"
  execution = authorized ? tokens.fetch("execution_authorization") : "none"
  review = authorized ? tokens.fetch("packet_review") : "none"
  followup = authorized ? tokens.fetch("governance_followup") : "none"
  row_status = authorized ? "PASS" : "PENDING"
  findings = authorized ? "C0/H0/M0/L0" : "Not assessed"
  yaml = YAML.dump(fixture_gate(phase)).delete_prefix("---\n")
  <<~MARKDOWN
    # Fixture Packet Review

    ## Status

    `#{status}`

    - Execution authorization: #{execution}
    - Review token: #{review}
    - Governance follow-up: #{followup}

    #{GATE_START}
    #{yaml.rstrip}
    #{GATE_END}

    | Pass | Status | Findings |
    | --- | --- | --- |
    | Spec compliance | #{row_status} | #{findings} |
    | Engineering/security | #{row_status} | #{findings} |
    | QA/evidence | #{row_status} | #{findings} |
  MARKDOWN
end

def fixture_failed_record
  <<~MARKDOWN
    # Failed Review

    ## Status

    `FAILED_NO_EXECUTION_AUTHORIZATION`

    - Execution authorization: none
    - Review token: none
  MARKDOWN
end

def write_fixture(root)
  (ACTIVE_PATHS.values + HISTORICAL_FAILED.values + HISTORICAL_PASS.values).uniq.each do |relative_path|
    path = File.join(root, relative_path)
    FileUtils.mkdir_p(File.dirname(path))
    File.write(path, "fixture\n")
  end
  File.write(File.join(root, PACKET), YAML.dump(fixture_packet("pre-review")))
  File.write(File.join(root, AGGREGATE), fixture_aggregate("pre-review"))
  File.write(File.join(root, ACTIVE_PATHS.fetch("authority_audit_script")), "fixture audit source\n")
  HISTORICAL_FAILED.each_value do |relative_path|
    File.write(File.join(root, relative_path), fixture_failed_record)
  end
  initial_pass = ["T202C3", "A006", "PACKET", "REVIEW", "PASS"].join("_")
  HISTORICAL_PASS.each_value do |relative_path|
    File.write(File.join(root, relative_path), "historical #{initial_pass}\n")
  end
end

def with_fixture
  Dir.mktmpdir("a006-authority-audit") do |root|
    write_fixture(root)
    yield root
  end
end

def expect_failure(label, match = nil)
  yield
  raise AuditFailure, "self-test #{label}: expected failure"
rescue AuditFailure => e
  if e.message.start_with?("self-test #{label}: expected failure")
    raise
  end
  assert_audit(match.nil? || e.message.include?(match), "self-test #{label}: wrong failure #{e.message}")
  true
end

def run_self_test
  tests = 0

  with_fixture do |root|
    result = audit_repository(root, "pre-review")
    assert_audit(result.fetch("active") == PRE_ACTIVE_COUNT, "self-test positive pre-review count")
  end
  tests += 1

  with_fixture do |root|
    File.write(File.join(root, PACKET), YAML.dump(fixture_packet("post-authorization")))
    File.write(File.join(root, AGGREGATE), fixture_aggregate("post-authorization"))
    result = audit_repository(root, "post-authorization")
    assert_audit(result.fetch("active") == POST_AUTH_ACTIVE_COUNT, "self-test positive post-authorization count")
  end
  tests += 1

  substituted_allowlist = ACTIVE_PATHS.merge(
    "product_contract" => ".ai-platform/substituted/spec.md"
  )
  expect_failure("substituted canonical allowlist path", "exact key/path map") do
    audit_allowlist_definition(
      substituted_allowlist,
      ACTIVE_PATHS,
      PRE_ACTIVE_COUNT,
      "active canonical allowlist"
    )
  end
  tests += 1

  with_fixture do |root|
    packet = fixture_packet("pre-review")
    packet.fetch("governance_inputs")["product_contract"] = ".ai-platform/substituted/spec.md"
    File.write(File.join(root, PACKET), YAML.dump(packet))
    expect_failure("substituted canonical path", "governance key/path") { audit_repository(root, "pre-review") }
  end
  tests += 1

  with_fixture do |root|
    File.delete(File.join(root, ACTIVE_PATHS.fetch("product_contract")))
    expect_failure("missing path", "missing path") { audit_repository(root, "pre-review") }
  end
  tests += 1

  with_fixture do |root|
    path = File.join(root, ACTIVE_PATHS.fetch("product_contract"))
    File.chmod(0o000, path)
    expect_failure("unreadable path", "unreadable path") { audit_repository(root, "pre-review") }
  ensure
    File.chmod(0o600, path) if path && File.exist?(path)
  end
  tests += 1

  duplicate_paths = { "one" => "a", "two" => "a" }
  expect_failure("duplicate allowlist path", "duplicate canonical path") do
    audit_allowlist_definition(duplicate_paths, duplicate_paths, 2, "fixture allowlist")
  end
  tests += 1

  expect_failure("duplicate YAML key", "duplicate YAML key") do
    strict_yaml_load("authority_gate:\n  state: one\n  state: two\n", "duplicate fixture")
  end
  tests += 1

  with_fixture do |root|
    path = File.join(root, AGGREGATE)
    File.open(path, "a") { |file| file.write("\n#{fixture_aggregate('pre-review')}\n") }
    expect_failure("duplicate authority block", "authority-gate block count") { audit_repository(root, "pre-review") }
  end
  tests += 1

  with_fixture do |root|
    path = File.join(root, AGGREGATE)
    content = File.read(path).sub("- Review token: none", "- Execution authorization: none\n- Review token: none")
    File.write(path, content)
    expect_failure("duplicate visible authority field", "duplicate visible execution_authorization") { audit_repository(root, "pre-review") }
  end
  tests += 1

  old_token = (["T202C3", "A006", "F001"] + %w[SPEC REVIEW PASS]).join("_")
  with_fixture do |root|
    path = File.join(root, HISTORICAL_FAILED.fetch("f001"))
    File.open(path, "a") { |file| file.write("\nmultiline evidence\n#{old_token}\n") }
    expect_failure("multiline historical stale token", "stale execution/review authority") { audit_repository(root, "pre-review") }
  end
  tests += 1

  with_fixture do |root|
    path = File.join(root, ACTIVE_PATHS.fetch("evidence_summary"))
    File.open(path, "a") { |file| file.write("\nmultiline active evidence\n#{old_token}\n") }
    expect_failure("multiline active stale token", "stale F001-F006 active authority") { audit_repository(root, "pre-review") }
  end
  tests += 1

  with_fixture do |root|
    path = File.join(root, ACTIVE_PATHS.fetch("evidence_summary"))
    File.open(path, "a") { |file| file.write("\npremature\n#{current_tokens.fetch('packet_review')}\n") }
    expect_failure("premature current token", "current token placement/count") { audit_repository(root, "pre-review") }
  end
  tests += 1

  with_fixture do |root|
    path = File.join(root, ACTIVE_PATHS.fetch("authority_audit_script"))
    File.open(path, "a") { |file| file.write("\n#{current_tokens.fetch('execution_authorization')}\n") }
    expect_failure("script self-token trap", "exact current authority token") { audit_repository(root, "pre-review") }
  end
  tests += 1

  with_fixture do |root|
    File.write(File.join(root, AGGREGATE), fixture_aggregate("post-authorization"))
    expect_failure("packet pending while aggregate authorized", "authorized status") do
      audit_repository(root, "post-authorization")
    end
  end
  tests += 1

  wrong_permission = fixture_packet("post-authorization")
  wrong_permission.fetch("execution_constraints")["production_permission"] = "wrong"
  expect_failure("wrong permission", "authorized production permission") do
    audit_packet(wrong_permission, "post-authorization")
  end
  tests += 1

  missing_review = fixture_gate("post-authorization").fetch("authority_gate")
  missing_review.fetch("reviews").delete("qa_evidence")
  expect_failure("missing review", "field set mismatch") do
    audit_gate_schema(missing_review, "post-authorization")
  end
  tests += 1

  puts("a006_authority_audit_self_test=pass cases=#{tests}")
end

begin
  argument = ARGV.fetch(0, "")
  if argument == "--self-test"
    assert_audit(ARGV.length == 1, "--self-test accepts no additional arguments")
    run_self_test
  else
    assert_audit(%w[pre-review post-authorization post-integration].include?(argument), "phase must be pre-review, post-authorization, post-integration, or --self-test")
    assert_audit(ARGV.length == 1, "phase accepts no additional arguments")
    result = audit_repository(ROOT, argument)
    puts("a006_authority_audit=#{result.fetch('phase')} active=#{result.fetch('active')} historical_failed=#{result.fetch('historical_failed')}")
  end
rescue AuditFailure => e
  warn("a006_authority_audit: #{e.message}")
  exit(1)
end
