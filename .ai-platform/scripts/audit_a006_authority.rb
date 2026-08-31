#!/usr/bin/env ruby
# frozen_string_literal: true

require "date"
require "digest"
require "fileutils"
require "find"
require "json"
require "open3"
require "tmpdir"
require "yaml"

ROOT = File.expand_path("../..", __dir__)
BASELINE_HEAD = "0bfc1c37c6cf383c255b90cee0f22bfced6d8850"
PACKET = ".ai-platform/specs/007-stable-v1-program/packets/T110-A006.yaml"
AGGREGATE = ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F008-packet-review.md"
ATTEMPT = ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F008.md"
SUMMARY = ".ai-platform/evidence/T202C3/summary.md"
TEST_RESULTS = ".ai-platform/evidence/T202C3/test-results.md"
STATUS_EVIDENCE = ".ai-platform/evidence/T202C3/attempts/T202C3-A006.md"
SCRIPT = ".ai-platform/scripts/audit_a006_authority.rb"
REVIEW_PATHS = {
  "spec_compliance" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F008-spec-review.md",
  "engineering_security" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F008-engineering-review.md",
  "qa_evidence" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F008-qa-review.md"
}.freeze

# These two maps are intentionally independent and verbatim. Neither is built
# from the other, and both are checked before any content is trusted.
ACTIVE_ALLOWLIST_PRIMARY = {
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
  "aggregate_packet_review" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F008-packet-review.md",
  "spec_review" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F008-spec-review.md",
  "engineering_review" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F008-engineering-review.md",
  "qa_review" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F008-qa-review.md",
  "execution_packet" => ".ai-platform/specs/007-stable-v1-program/packets/T110-A006.yaml",
  "attempt_status" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006.md",
  "evidence_summary" => ".ai-platform/evidence/T202C3/summary.md",
  "test_results" => ".ai-platform/evidence/T202C3/test-results.md"
}.freeze

ACTIVE_ALLOWLIST_SECONDARY = {
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
  "aggregate_packet_review" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F008-packet-review.md",
  "spec_review" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F008-spec-review.md",
  "engineering_review" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F008-engineering-review.md",
  "qa_review" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F008-qa-review.md",
  "execution_packet" => ".ai-platform/specs/007-stable-v1-program/packets/T110-A006.yaml",
  "attempt_status" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006.md",
  "evidence_summary" => ".ai-platform/evidence/T202C3/summary.md",
  "test_results" => ".ai-platform/evidence/T202C3/test-results.md"
}.freeze

HISTORICAL_FAILED = {
  "f001" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F001-packet-review.md",
  "f002" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F002-packet-review.md",
  "f003" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F003-packet-review.md",
  "f004" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F004-packet-review.md",
  "f005" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F005-packet-review.md",
  "f006" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F006-packet-review.md",
  "f007" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F007-packet-review.md"
}.freeze

INITIAL_PASS = {
  "initial_a006_packet_review" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-packet-review.md"
}.freeze

INITIAL_PASS_ALLOWED_COUNTS = {
  ".ai-platform/evidence/T202C3/attempts/T202C3-A006-contract-A004.md" => 1,
  ".ai-platform/evidence/T202C3/attempts/T202C3-A006-contract.md" => 1,
  ".ai-platform/evidence/T202C3/attempts/T202C3-A006-packet-review.md" => 1,
  ".ai-platform/specs/007-stable-v1-program/analysis.md" => 1,
  ".ai-platform/specs/007-stable-v1-program/packets/T110-A006.yaml" => 3,
  ".ai-platform/specs/007-stable-v1-program/tasks.md" => 1,
  ".ai-platform/specs/008-security-baseline/analysis.md" => 2,
  ".ai-platform/specs/008-security-baseline/plan.md" => 1,
  ".ai-platform/specs/008-security-baseline/spec.md" => 1,
  ".ai-platform/specs/008-security-baseline/tasks.md" => 1
}.freeze

INITIAL_PASS_SEMANTIC_ALLOWED_COUNTS = {
  ".ai-platform/evidence/T202C3/attempts/T202C3-A006-contract-A004.md" => 1,
  ".ai-platform/evidence/T202C3/attempts/T202C3-A006-contract.md" => 1,
  ".ai-platform/evidence/T202C3/attempts/T202C3-A006-packet-review.md" => 2,
  ".ai-platform/specs/007-stable-v1-program/analysis.md" => 1,
  ".ai-platform/specs/007-stable-v1-program/packets/T110-A006.yaml" => 3,
  ".ai-platform/specs/007-stable-v1-program/tasks.md" => 1,
  ".ai-platform/specs/008-security-baseline/analysis.md" => 2,
  ".ai-platform/specs/008-security-baseline/plan.md" => 1,
  ".ai-platform/specs/008-security-baseline/spec.md" => 1,
  ".ai-platform/specs/008-security-baseline/tasks.md" => 1
}.freeze

PACKET_PATH_DECLARATIONS = {
  "governance_inputs.constitution" => ".ai-platform/memory/constitution.md",
  "governance_inputs.product_contract" => ".ai-platform/specs/007-stable-v1-program/spec.md",
  "governance_inputs.requirements_checklist" => ".ai-platform/specs/007-stable-v1-program/checklists/requirements.md",
  "governance_inputs.program_plan" => ".ai-platform/specs/007-stable-v1-program/plan.md",
  "governance_inputs.work_graph" => ".ai-platform/specs/007-stable-v1-program/tasks.md",
  "governance_inputs.analysis" => ".ai-platform/specs/007-stable-v1-program/analysis.md",
  "governance_inputs.security_spec" => ".ai-platform/specs/008-security-baseline/spec.md",
  "governance_inputs.security_plan" => ".ai-platform/specs/008-security-baseline/plan.md",
  "governance_inputs.security_analysis" => ".ai-platform/specs/008-security-baseline/analysis.md",
  "governance_inputs.security_work_graph" => ".ai-platform/specs/008-security-baseline/tasks.md",
  "governance_inputs.authority_contract" => ".ai-platform/specs/008-security-baseline/contracts/authority-store.md",
  "governance_inputs.authorization_contract" => ".ai-platform/specs/008-security-baseline/contracts/authorization.md",
  "governance_inputs.account_contract" => ".ai-platform/specs/008-security-baseline/contracts/account-config-v2.md",
  "governance_inputs.data_model" => ".ai-platform/specs/008-security-baseline/data-model.md",
  "governance_inputs.authority_audit_script" => ".ai-platform/scripts/audit_a006_authority.rb",
  "governance_inputs.predecessor_evidence" => ".ai-platform/evidence/T202C3/attempts/T202C3-A005.md",
  "governance_inputs.historical_packet_review_evidence" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-packet-review.md",
  "governance_inputs.failed_f001_packet_review_evidence" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F001-packet-review.md",
  "governance_inputs.failed_f002_packet_review_evidence" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F002-packet-review.md",
  "governance_inputs.failed_f003_packet_review_evidence" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F003-packet-review.md",
  "governance_inputs.failed_f004_packet_review_evidence" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F004-packet-review.md",
  "governance_inputs.failed_f005_packet_review_evidence" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F005-packet-review.md",
  "governance_inputs.failed_f006_packet_review_evidence" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F006-packet-review.md",
  "governance_inputs.failed_f007_packet_review_evidence" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F007-packet-review.md",
  "governance_inputs.f008_packet_review_evidence" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F008-packet-review.md",
  "governance_inputs.f008_spec_review_evidence" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F008-spec-review.md",
  "governance_inputs.f008_engineering_review_evidence" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F008-engineering-review.md",
  "governance_inputs.f008_qa_review_evidence" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F008-qa-review.md",
  "evidence_contract.attempt_path" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F008.md",
  "evidence_contract.packet_review_path" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F008-packet-review.md",
  "evidence_contract.review_paths.spec_compliance" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F008-spec-review.md",
  "evidence_contract.review_paths.engineering_security" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F008-engineering-review.md",
  "evidence_contract.review_paths.qa_evidence" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F008-qa-review.md",
  "evidence_contract.summary_path" => ".ai-platform/evidence/T202C3/summary.md",
  "evidence_contract.test_results_path" => ".ai-platform/evidence/T202C3/test-results.md",
  "authority_audit_contract.post_integration.attempt_path" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F008.md"
}.freeze

PACKET_REVIEW_REF_DECLARATIONS = {
  "authority_review_binding.review_refs[0].path" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F008-spec-review.md",
  "authority_review_binding.review_refs[1].path" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F008-engineering-review.md",
  "authority_review_binding.review_refs[2].path" => ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F008-qa-review.md"
}.freeze

FUTURE_ALLOWED_FILES = [
  "crates/kirje-store/src/authority.rs",
  "crates/kirje-store/tests/authority_registry.rs",
  "crates/kirje-store/tests/fixtures/authority/registry/account_credential_cleanup/**"
].freeze
EXACT_PRODUCTION_FILES = ["crates/kirje-store/src/authority.rs"].freeze
EXACT_TEST_FILES = ["crates/kirje-store/tests/authority_registry.rs"].freeze
FIXTURE_PREFIX = "crates/kirje-store/tests/fixtures/authority/registry/account_credential_cleanup/"
REVIEW_NAMES = %w[spec_compliance engineering_security qa_evidence].freeze
FINDING_NAMES = %w[critical high medium low].freeze
PRE_PERMISSION = "none_pending_three_independent_f008_packet_reviews"
POST_PRODUCTION_PERMISSION = "exact_authority_rs_scope_authorized"
POST_TEST_PERMISSION = "exact_authority_registry_scope_authorized"
POST_FIXTURE_PERMISSION = "exact_cleanup_fixture_scope_authorized"
TERMINAL_PERMISSION = "closed_spent_non_replayable"

GATE_START = ["<!-- A006", "AUTHORITY", "GATE", "START"].join("_")
GATE_END = ["A006", "AUTHORITY", "GATE", "END -->"].join("_")
REVIEW_START = ["<!-- A006", "F00" + "8", "REVIEW", "RECORD", "START"].join("_")
REVIEW_END = ["A006", "F00" + "8", "REVIEW", "RECORD", "END -->"].join("_")
INTEGRATION_START = ["<!-- A006", "F00" + "8", "INTEGRATION", "START"].join("_")
INTEGRATION_END = ["A006", "F00" + "8", "INTEGRATION", "END -->"].join("_")
REFERENCE_START = ["<!-- A006", "F00" + "8", "INTEGRATION", "REFERENCE", "START"].join("_")
REFERENCE_END = ["A006", "F00" + "8", "INTEGRATION", "REFERENCE", "END -->"].join("_")

class AuditFailure < StandardError; end

def assert_audit(condition, message)
  raise AuditFailure, message unless condition
end

def sha256(content)
  Digest::SHA256.hexdigest(content)
end

def exact_token_components(number, kind)
  prefix = ["T202C" + "3", "A00" + "6", format("F%03d", number)]
  suffixes = {
    "packet_review" => %w[PACKET REVIEW PASS],
    "spec_compliance" => %w[SPEC REVIEW PASS],
    "engineering_security" => %w[ENGINEERING SECURITY REVIEW PASS],
    "qa_evidence" => %w[QA EVIDENCE REVIEW PASS],
    "execution_authorization" => %w[EXECUTION AUTHORIZED],
    "governance_followup" => %w[GOVERNANCE FOLLOWUP COMPLETE],
    "ready_authority" => %w[READY FOR EXECUTION]
  }
  prefix + suffixes.fetch(kind)
end

def exact_token(kind)
  exact_token_components(8, kind).join("_")
end

def semantic_token_pattern(number, kind)
  components = exact_token_components(number, kind)
  separator = "[^[:alnum:]]*"
  Regexp.new("(?<![[:alnum:]])#{components.map { |part| Regexp.escape(part) }.join(separator)}(?![[:alnum:]])", Regexp::IGNORECASE)
end

def semantic_count(content, number, kind)
  content.scan(semantic_token_pattern(number, kind)).length
end

def reject_duplicate_yaml_keys(node, label)
  if node.is_a?(Psych::Nodes::Mapping)
    keys = []
    node.children.each_slice(2) do |key_node, value_node|
      assert_audit(key_node.is_a?(Psych::Nodes::Scalar), "#{label}: non-scalar key")
      key = key_node.value.to_s
      assert_audit(!keys.include?(key), "#{label}: duplicate YAML key #{key}")
      keys << key
      reject_duplicate_yaml_keys(value_node, label)
    end
  elsif node.respond_to?(:children) && node.children
    node.children.each { |child| reject_duplicate_yaml_keys(child, label) }
  end
end

def strict_yaml(content, label)
  stream = Psych.parse_stream(content, filename: label)
  assert_audit(stream.children.length == 1, "#{label}: expected one YAML document")
  reject_duplicate_yaml_keys(stream, label)
  value = YAML.safe_load(content, permitted_classes: [Date], permitted_symbols: [], aliases: false, filename: label)
  assert_audit(value.is_a?(Hash), "#{label}: root must be a mapping")
  value
rescue Psych::SyntaxError, Psych::DisallowedClass => e
  raise AuditFailure, "#{label}: invalid YAML: #{e.message}"
end

def exact_keys(value, keys, label)
  assert_audit(value.is_a?(Hash), "#{label}: expected mapping")
  assert_audit(value.keys.map(&:to_s).sort == keys.sort, "#{label}: exact key/shape mismatch")
end

def secure_read_paths(root, mapping, label)
  root_real = File.realpath(root)
  physical = {}
  result = {}
  mapping.each do |key, relative|
    path = File.join(root, relative)
    stat = File.lstat(path)
    assert_audit(!stat.symlink?, "#{label}: symlink forbidden #{relative}")
    assert_audit(stat.file?, "#{label}: non-regular file #{relative}")
    real = File.realpath(path)
    assert_audit(real == root_real || real.start_with?(root_real + File::SEPARATOR), "#{label}: path escapes repository #{relative}")
    identity = [stat.dev, stat.ino]
    assert_audit(!physical.key?(identity), "#{label}: physical file alias #{relative} and #{physical[identity]}")
    physical[identity] = relative
    result[key] = File.open(path, "rb", &:read).force_encoding(Encoding::UTF_8).encode(Encoding::UTF_8, invalid: :replace, undef: :replace)
  rescue Errno::ENOENT
    raise AuditFailure, "#{label}: missing path #{relative}"
  rescue Errno::EACCES
    raise AuditFailure, "#{label}: unreadable path #{relative}"
  end
  result
end

def secure_stage_contents(root)
  base = File.join(root, ".ai-platform")
  root_real = File.realpath(root)
  contents = {}
  Find.find(base) do |path|
    next if path == base

    stat = File.lstat(path)
    if stat.symlink?
      raise AuditFailure, "stage scan: symlink forbidden #{path.delete_prefix(root + '/') }"
    elsif stat.directory?
      next
    end
    assert_audit(stat.file?, "stage scan: non-regular file")
    real = File.realpath(path)
    assert_audit(real.start_with?(root_real + File::SEPARATOR), "stage scan: path escapes repository")
    relative = path.delete_prefix(root + File::SEPARATOR)
    contents[relative] = File.open(path, "rb", &:read).force_encoding(Encoding::UTF_8).encode(Encoding::UTF_8, invalid: :replace, undef: :replace)
  end
  contents
end

def validate_independent_allowlists(primary = ACTIVE_ALLOWLIST_PRIMARY, secondary = ACTIVE_ALLOWLIST_SECONDARY)
  assert_audit(primary.length == 24 && secondary.length == 24, "active allowlist count mismatch")
  assert_audit(primary.keys == secondary.keys, "independent allowlist key mismatch")
  assert_audit(primary == secondary, "independent allowlist path mismatch")
  [primary, secondary].each_with_index do |mapping, index|
    assert_audit(mapping.values.uniq.length == mapping.length, "allowlist #{index + 1}: duplicate path")
  end
end

def visible_status(content, label)
  headings = content.scan(/^[ \t]*##[ \t]+Status[ \t]*$/)
  assert_audit(headings.length == 1, "#{label}: one visible status heading required")
  matches = content.scan(/^[ \t]*##[ \t]+Status[ \t]*\r?\n(?:[ \t]*\r?\n)*[ \t]*`([^`\r\n]+)`[ \t]*$/)
  assert_audit(matches.length == 1, "#{label}: one visible status scalar required")
  matches.first.first.strip
end

def visible_authority_fields(content, label, required_keys: nil, allowed_keys: nil)
  fields = Hash.new { |hash, key| hash[key] = [] }
  names = {
    "execution authorization" => "execution_authorization",
    "review token" => "packet_review_token",
    "governance follow-up" => "governance_followup"
  }
  content.each_line do |line|
    match = line.match(/^[ \t]*- (Execution authorization|Review token|Governance follow-up):[ \t]*(.*?)[ \t]*\r?\n?$/i)
    next unless match

    fields[names.fetch(match[1].downcase)] << match[2].gsub(/\A`|`\z/, "").strip
  end
  required_keys ||= names.values
  allowed_keys ||= names.values
  assert_audit((fields.keys - allowed_keys).empty?, "#{label}: unknown visible authority field")
  assert_audit((required_keys - fields.keys).empty?, "#{label}: missing visible authority field")
  fields.each do |key, values|
    assert_audit(values.length == 1, "#{label}: duplicate visible #{key}")
  end
  fields.transform_values(&:first)
end

def extract_block(content, start_marker, end_marker, label, exact_count: 1)
  starts = content.scan(Regexp.new(Regexp.escape(start_marker))).length
  ends = content.scan(Regexp.new(Regexp.escape(end_marker))).length
  assert_audit(starts == ends, "#{label}: unbalanced markers")
  pattern = /#{Regexp.escape(start_marker)}\r?\n(.*?)\r?\n#{Regexp.escape(end_marker)}/m
  blocks = content.scan(pattern).map(&:first)
  assert_audit(blocks.length == starts, "#{label}: malformed block")
  assert_audit(blocks.length == exact_count, "#{label}: block count mismatch")
  blocks.first
end

def parse_review_table(content, phase)
  section_match = content.match(/^## Review Matrix[ \t]*$\n(.*?)(?=^## |\z)/m)
  assert_audit(section_match, "aggregate: review matrix missing")
  rows = {}
  section_match[1].each_line do |line|
    next unless line.lstrip.start_with?("|")
    cells = line.strip.delete_prefix("|").delete_suffix("|").split("|").map(&:strip)
    next if cells.first == "Pass" || cells.all? { |cell| cell.match?(/\A-+\z/) }
    assert_audit(cells.length == 4, "aggregate: review row shape mismatch")
    name = {
      "Spec compliance" => "spec_compliance",
      "Engineering/security" => "engineering_security",
      "QA/evidence" => "qa_evidence"
    }[cells[0]]
    assert_audit(name, "aggregate: unknown/shadow review row #{cells[0]}")
    assert_audit(!rows.key?(name), "aggregate: duplicate review row #{name}")
    rows[name] = { "status" => cells[1], "findings" => cells[2], "token" => cells[3] }
  end
  assert_audit(rows.keys.sort == REVIEW_NAMES.sort, "aggregate: review row set mismatch")
  expected = case phase
             when "pre-review"
               { "status" => "PENDING", "findings" => "Not assessed", "token" => "none" }
             else
               nil
             end
  if expected
    rows.each_value { |row| assert_audit(row == expected, "aggregate: pending review row mismatch") }
  else
    REVIEW_NAMES.each do |name|
      row = rows.fetch(name)
      assert_audit(row.fetch("status") == "PASS", "aggregate: review status mismatch")
      assert_audit(row.fetch("findings") == "C0/H0/M0/L0", "aggregate: review findings mismatch")
      assert_audit(row.fetch("token") == exact_token(name), "aggregate: review token field mismatch")
    end
  end
  rows
end

def collect_path_declarations(value, prefix = nil, result = {})
  case value
  when Hash
    value.each do |key, nested|
      path = [prefix, key.to_s].compact.join(".")
      collect_path_declarations(nested, path, result)
    end
  when Array
    value.each_with_index do |nested, index|
      collect_path_declarations(nested, "#{prefix}[#{index}]", result)
    end
  when String
    result[prefix] = value if value.start_with?(".ai-platform/")
  end
  result
end

def audit_packet_path_declarations(packet, phase)
  expected = phase == "pre-review" ? PACKET_PATH_DECLARATIONS : PACKET_PATH_DECLARATIONS.merge(PACKET_REVIEW_REF_DECLARATIONS)
  declarations = collect_path_declarations(packet)
  unless declarations == expected
    missing = expected.keys - declarations.keys
    extra = declarations.keys - expected.keys
    changed = (expected.keys & declarations.keys).select { |key| expected.fetch(key) != declarations.fetch(key) }
    raise AuditFailure, "packet: exact path declaration map mismatch missing=#{missing.join(',')} extra=#{extra.join(',')} changed=#{changed.join(',')}"
  end
end

def governance_inputs_shape(packet)
  expected = PACKET_PATH_DECLARATIONS.keys.filter_map do |key|
    key.delete_prefix("governance_inputs.") if key.start_with?("governance_inputs.")
  end + ["approval_gates"]
  inputs = packet.fetch("governance_inputs")
  exact_keys(inputs, expected, "governance_inputs")
  assert_audit(inputs.fetch("approval_gates").is_a?(Hash), "governance_inputs.approval_gates: expected mapping")
end

def permission_shape(constraints)
  exact_keys(
    constraints,
    %w[production_permission test_permission fixture_permission future_allowed_files forbidden_changes write_rules],
    "execution_constraints"
  )
  assert_audit(constraints.fetch("future_allowed_files") == FUTURE_ALLOWED_FILES, "execution_constraints: future files mismatch")
  assert_audit(constraints.fetch("forbidden_changes").is_a?(Array), "execution_constraints: forbidden changes shape")
  assert_audit(constraints.fetch("write_rules").is_a?(Array), "execution_constraints: write rules shape")
end

def evidence_contract_shape(packet)
  evidence = packet.fetch("evidence_contract")
  exact_keys(evidence, %w[attempt_path packet_review_path review_paths summary_path test_results_path required prohibited], "evidence_contract")
  exact_keys(evidence.fetch("review_paths"), REVIEW_NAMES, "evidence_contract.review_paths")
  assert_audit(evidence.fetch("attempt_path") == ATTEMPT, "evidence_contract: attempt path mismatch")
  assert_audit(evidence.fetch("packet_review_path") == AGGREGATE, "evidence_contract: aggregate path mismatch")
  assert_audit(evidence.fetch("review_paths") == REVIEW_PATHS, "evidence_contract: review paths mismatch")
  assert_audit(evidence.fetch("summary_path") == SUMMARY, "evidence_contract: summary path mismatch")
  assert_audit(evidence.fetch("test_results_path") == TEST_RESULTS, "evidence_contract: test results path mismatch")
  assert_audit(evidence.fetch("required").is_a?(Array) && evidence.fetch("prohibited").is_a?(Array), "evidence_contract: list shape mismatch")
end

def pending_binding
  {
    "state" => "pending",
    "preparation_commit" => "none",
    "audit_script_sha256" => "none",
    "packet_sha256" => "none",
    "canonical_manifest_sha256" => "none",
    "review_refs" => []
  }
end

def audit_packet(packet, phase, binding: nil, baseline: BASELINE_HEAD)
  audit_packet_path_declarations(packet, phase)
  governance_inputs_shape(packet)
  evidence_contract_shape(packet)
  assert_audit(packet.fetch("packet_id") == "007-T110-T202C3-A006-F008", "packet: packet id mismatch")
  assert_audit(packet.fetch("work_unit").fetch("attempt") == "T202C3-A006-F008", "packet: attempt mismatch")
  assert_audit(packet.fetch("codebase_context").fetch("baseline_head") == baseline, "packet: stale baseline")
  constraints = packet.fetch("execution_constraints")
  permission_shape(constraints)
  gate = packet.fetch("execution_gate")
  exact_keys(gate, %w[grant_state packet_review_token execution_authorization governance_followup], "execution_gate")
  review_binding = packet.fetch("authority_review_binding")
  exact_keys(review_binding, pending_binding.keys, "authority_review_binding")

  case phase
  when "pre-review"
    assert_audit(packet.fetch("status") == "ready_for_f008_packet_review", "packet: pending status mismatch")
    %w[production_permission test_permission fixture_permission].each do |key|
      assert_audit(constraints.fetch(key) == PRE_PERMISSION, "packet: pending permission mismatch")
    end
    assert_audit(gate == { "grant_state" => "closed", "packet_review_token" => "none", "execution_authorization" => "none", "governance_followup" => "none" }, "packet: pending gate mismatch")
    assert_audit(review_binding == pending_binding, "packet: pending review binding mismatch")
  when "post-authorization"
    assert_audit(packet.fetch("status") == "ready", "packet: authorized status mismatch")
    assert_audit(constraints.fetch("production_permission") == POST_PRODUCTION_PERMISSION, "packet: production permission mismatch")
    assert_audit(constraints.fetch("test_permission") == POST_TEST_PERMISSION, "packet: test permission mismatch")
    assert_audit(constraints.fetch("fixture_permission") == POST_FIXTURE_PERMISSION, "packet: fixture permission mismatch")
    expected_gate = {
      "grant_state" => "authorized_unspent",
      "packet_review_token" => exact_token("packet_review"),
      "execution_authorization" => exact_token("execution_authorization"),
      "governance_followup" => exact_token("governance_followup")
    }
    assert_audit(gate == expected_gate, "packet: authorized gate mismatch")
    assert_audit(review_binding == binding, "packet: authorized review binding mismatch")
  when "post-integration"
    assert_audit(packet.fetch("status") == "review_complete", "packet: terminal status mismatch")
    %w[production_permission test_permission fixture_permission].each do |key|
      assert_audit(constraints.fetch(key) == TERMINAL_PERMISSION, "packet: terminal permission replayable")
    end
    expected_gate = {
      "grant_state" => "spent_non_replayable",
      "packet_review_token" => "spent",
      "execution_authorization" => "spent",
      "governance_followup" => "spent"
    }
    assert_audit(gate == expected_gate, "packet: terminal gate mismatch")
    assert_audit(review_binding == binding, "packet: terminal review binding mismatch")
  else
    raise AuditFailure, "packet: unknown phase"
  end
end

def manifest_hash(entries)
  sha256(JSON.generate(entries))
end

def git_capture(root, *args)
  output, error, status = Open3.capture3("git", *args, chdir: root)
  raise AuditFailure, "git #{args.join(' ')} failed: #{error.strip}" unless status.success?
  output
end

def verify_commit(root, commit)
  assert_audit(commit.to_s.match?(/\A[0-9a-f]{40}\z/), "git: commit format mismatch")
  git_capture(root, "cat-file", "-e", "#{commit}^{commit}")
  resolved = git_capture(root, "rev-parse", "#{commit}^{commit}").strip
  assert_audit(resolved == commit, "git: commit does not resolve exactly")
end

def git_file(root, commit, path)
  git_capture(root, "show", "#{commit}:#{path}")
end

def canonical_manifest(root, preparation_commit)
  ACTIVE_ALLOWLIST_PRIMARY.sort.map do |key, path|
    { "key" => key, "path" => path, "sha256" => sha256(git_file(root, preparation_commit, path)) }
  end
end

def binding_for_commit(root, preparation_commit, baseline)
  verify_commit(root, preparation_commit)
  parent = git_capture(root, "rev-parse", "#{preparation_commit}^").strip
  assert_audit(parent == baseline, "review binding: stale preparation baseline")
  manifest = canonical_manifest(root, preparation_commit)
  {
    "state" => "reviewed_authorized",
    "preparation_commit" => preparation_commit,
    "audit_script_sha256" => sha256(git_file(root, preparation_commit, SCRIPT)),
    "packet_sha256" => sha256(git_file(root, preparation_commit, PACKET)),
    "canonical_manifest_sha256" => manifest_hash(manifest),
    "canonical_manifest" => manifest
  }
end

def review_record(content, expected_kind, phase, binding: nil)
  block = extract_block(content, REVIEW_START, REVIEW_END, "review #{expected_kind}")
  document = strict_yaml(block, "review #{expected_kind}")
  exact_keys(document, ["review_record"], "review #{expected_kind}.document")
  record = document.fetch("review_record")
  exact_keys(record, %w[schema_version kind status preparation_commit audit_script_sha256 packet_sha256 canonical_manifest_sha256 canonical_manifest findings review_token], "review #{expected_kind}.record")
  assert_audit(record.fetch("schema_version") == 1 && record.fetch("kind") == expected_kind, "review #{expected_kind}: identity mismatch")
  if phase == "pre-review"
    assert_audit(visible_status(content, "review #{expected_kind}") == "PENDING_REVIEW", "review #{expected_kind}: visible pending mismatch")
    expected = {
      "schema_version" => 1, "kind" => expected_kind, "status" => "PENDING",
      "preparation_commit" => "none", "audit_script_sha256" => "none",
      "packet_sha256" => "none", "canonical_manifest_sha256" => "none",
      "canonical_manifest" => [], "findings" => nil, "review_token" => "none"
    }
    assert_audit(record == expected, "review #{expected_kind}: pending record mismatch")
  else
    assert_audit(visible_status(content, "review #{expected_kind}") == "PASSED_ZERO_FINDINGS", "review #{expected_kind}: visible pass mismatch")
    assert_audit(record.fetch("status") == "PASSED_ZERO_FINDINGS", "review #{expected_kind}: status mismatch")
    assert_audit(record.fetch("preparation_commit") == binding.fetch("preparation_commit"), "review #{expected_kind}: preparation mismatch")
    %w[audit_script_sha256 packet_sha256 canonical_manifest_sha256 canonical_manifest].each do |key|
      assert_audit(record.fetch(key) == binding.fetch(key), "review #{expected_kind}: #{key} mismatch")
    end
    expected_findings = FINDING_NAMES.to_h { |name| [name, 0] }
    assert_audit(record.fetch("findings") == expected_findings, "review #{expected_kind}: findings mismatch")
    assert_audit(record.fetch("review_token") == exact_token(expected_kind), "review #{expected_kind}: token mismatch")
  end
  record
end

def aggregate_gate(content)
  block = extract_block(content, GATE_START, GATE_END, "aggregate")
  document = strict_yaml(block, "aggregate gate")
  exact_keys(document, ["authority_gate"], "aggregate document")
  document.fetch("authority_gate")
end

def aggregate_binding_shape(binding, baseline)
  exact_keys(binding, %w[baseline_head preparation_commit audit_script_sha256 packet_sha256 canonical_manifest_sha256 canonical_manifest], "aggregate.preparation_binding")
  assert_audit(binding.fetch("baseline_head") == baseline, "aggregate: stale baseline")
end

def audit_aggregate(content, phase, binding: nil, review_contents: nil, baseline: BASELINE_HEAD)
  gate = aggregate_gate(content)
  exact_keys(gate, %w[schema_version state grant_state packet_review_token execution_authorization governance_followup preparation_binding reviews], "authority_gate")
  assert_audit(gate.fetch("schema_version") == 2, "authority_gate: schema version mismatch")
  aggregate_binding_shape(gate.fetch("preparation_binding"), baseline)
  exact_keys(gate.fetch("reviews"), REVIEW_NAMES, "authority_gate.reviews")
  fields = visible_authority_fields(content, "aggregate")
  rows = parse_review_table(content, phase)

  if phase == "pre-review"
    assert_audit(visible_status(content, "aggregate") == "PENDING_THREE_INDEPENDENT_REVIEWS", "aggregate: visible pending status mismatch")
    expected_fields = { "execution_authorization" => "none", "packet_review_token" => "none", "governance_followup" => "none" }
    assert_audit(fields == expected_fields, "aggregate: visible pending fields mismatch")
    pending_preparation = {
      "baseline_head" => baseline, "preparation_commit" => "none",
      "audit_script_sha256" => "none", "packet_sha256" => "none",
      "canonical_manifest_sha256" => "none", "canonical_manifest" => []
    }
    assert_audit(gate.fetch("state") == "PENDING_REVIEW" && gate.fetch("grant_state") == "closed", "aggregate: pending state mismatch")
    assert_audit(gate.fetch("packet_review_token") == "none" && gate.fetch("execution_authorization") == "none" && gate.fetch("governance_followup") == "none", "aggregate: pending tokens mismatch")
    assert_audit(gate.fetch("preparation_binding") == pending_preparation, "aggregate: pending binding mismatch")
    REVIEW_NAMES.each do |name|
      review = gate.fetch("reviews").fetch(name)
      exact_keys(review, %w[status token findings evidence_path evidence_sha256], "aggregate.reviews.#{name}")
      expected = { "status" => "PENDING", "token" => "none", "findings" => nil, "evidence_path" => REVIEW_PATHS.fetch(name), "evidence_sha256" => "none" }
      assert_audit(review == expected, "aggregate: pending review mismatch #{name}")
    end
  else
    terminal = phase == "post-integration"
    expected_status = terminal ? "REVIEW_COMPLETE" : "PASSED_AUTHORIZED_FOR_EXECUTION"
    expected_grant = terminal ? "spent_non_replayable" : "authorized_unspent"
    assert_audit(visible_status(content, "aggregate") == expected_status, "aggregate: visible state mismatch")
    assert_audit(gate.fetch("state") == expected_status && gate.fetch("grant_state") == expected_grant, "aggregate: structured state mismatch")
    assert_audit(gate.fetch("packet_review_token") == exact_token("packet_review"), "aggregate: packet review token mismatch")
    if terminal
      assert_audit(gate.fetch("execution_authorization") == "spent" && gate.fetch("governance_followup") == "spent", "aggregate: terminal grant replayable")
      expected_fields = { "execution_authorization" => "spent", "packet_review_token" => exact_token("packet_review"), "governance_followup" => "spent" }
    else
      assert_audit(gate.fetch("execution_authorization") == exact_token("execution_authorization"), "aggregate: execution token mismatch")
      assert_audit(gate.fetch("governance_followup") == exact_token("governance_followup"), "aggregate: follow-up token mismatch")
      expected_fields = { "execution_authorization" => exact_token("execution_authorization"), "packet_review_token" => exact_token("packet_review"), "governance_followup" => exact_token("governance_followup") }
    end
    assert_audit(fields == expected_fields, "aggregate: visible authority mismatch")
    prep = gate.fetch("preparation_binding")
    expected_prep = binding.reject { |key, _| key == "state" || key == "review_refs" }.merge("baseline_head" => baseline)
    assert_audit(prep == expected_prep, "aggregate: preparation binding mismatch")
    REVIEW_NAMES.each do |name|
      review = gate.fetch("reviews").fetch(name)
      exact_keys(review, %w[status token findings evidence_path evidence_sha256], "aggregate.reviews.#{name}")
      expected = {
        "status" => "PASSED_ZERO_FINDINGS", "token" => exact_token(name),
        "findings" => FINDING_NAMES.to_h { |finding| [finding, 0] },
        "evidence_path" => REVIEW_PATHS.fetch(name),
        "evidence_sha256" => sha256(review_contents.fetch(name))
      }
      assert_audit(review == expected, "aggregate: review binding mismatch #{name}")
    end
  end
  [gate, rows]
end

def review_refs(review_contents)
  REVIEW_NAMES.map do |name|
    { "kind" => name, "path" => REVIEW_PATHS.fetch(name), "sha256" => sha256(review_contents.fetch(name)) }
  end
end

def packet_binding(binding, review_contents)
  {
    "state" => "reviewed_authorized",
    "preparation_commit" => binding.fetch("preparation_commit"),
    "audit_script_sha256" => binding.fetch("audit_script_sha256"),
    "packet_sha256" => binding.fetch("packet_sha256"),
    "canonical_manifest_sha256" => binding.fetch("canonical_manifest_sha256"),
    "review_refs" => review_refs(review_contents)
  }
end

def deep_diff_paths(left, right, prefix = nil, paths = [])
  if left.class != right.class
    paths << prefix
  elsif left.is_a?(Hash)
    (left.keys | right.keys).each do |key|
      path = [prefix, key.to_s].compact.join(".")
      if !left.key?(key) || !right.key?(key)
        paths << path
      else
        deep_diff_paths(left[key], right[key], path, paths)
      end
    end
  elsif left.is_a?(Array)
    paths << prefix unless left == right
  elsif left != right
    paths << prefix
  end
  paths
end

def verify_packet_delta(prep_content, current_content)
  prep = strict_yaml(prep_content, "preparation packet")
  current = strict_yaml(current_content, "current packet")
  allowed = [
    "status", "execution_constraints.production_permission",
    "execution_constraints.test_permission", "execution_constraints.fixture_permission"
  ]
  differences = deep_diff_paths(prep, current)
  unexpected = differences.reject do |path|
    allowed.include?(path) || path.start_with?("execution_gate.") || path.start_with?("authority_review_binding.")
  end
  assert_audit(unexpected.empty?, "review binding: unauthorized packet delta #{unexpected.join(', ')}")
end

def aggregate_projection(content)
  projected = content.dup
  projected.gsub!(/(^## Status[ \t]*\r?\n(?:[ \t]*\r?\n)*[ \t]*`)[^`\r\n]+(`)/, '\\1<STATE>\\2')
  projected.gsub!(/^([ \t]*- (?:Execution authorization|Review token|Governance follow-up):)[^\r\n]*$/i, '\\1 <AUTHORITY>')
  projected.gsub!(/#{Regexp.escape(GATE_START)}\r?\n.*?\r?\n#{Regexp.escape(GATE_END)}/m, "#{GATE_START}\n<GATE>\n#{GATE_END}")
  section = projected.match(/^## Review Matrix[ \t]*$\n(.*?)(?=^## |\z)/m)
  assert_audit(section, "aggregate projection: review matrix missing")
  replacement = "\n| <REVIEW_ROWS> |\n\n"
  projected[section.begin(1)...section.end(1)] = replacement
  projected
end

def review_projection(content)
  projected = content.dup
  projected.gsub!(/(^## Status[ \t]*\r?\n(?:[ \t]*\r?\n)*[ \t]*`)[^`\r\n]+(`)/, '\\1<STATE>\\2')
  projected.gsub!(/#{Regexp.escape(REVIEW_START)}\r?\n.*?\r?\n#{Regexp.escape(REVIEW_END)}/m, "#{REVIEW_START}\n<REVIEW>\n#{REVIEW_END}")
  projected
end

def verify_reviewed_artifacts(root, active_contents, binding, phase)
  preparation = binding.fetch("preparation_commit")
  verify_commit(root, preparation)
  manifest = canonical_manifest(root, preparation)
  assert_audit(binding.fetch("canonical_manifest") == manifest, "review binding: canonical manifest mismatch")
  assert_audit(binding.fetch("canonical_manifest_sha256") == manifest_hash(manifest), "review binding: manifest hash mismatch")
  assert_audit(binding.fetch("audit_script_sha256") == sha256(git_file(root, preparation, SCRIPT)), "review binding: reviewed script hash mismatch")
  assert_audit(binding.fetch("packet_sha256") == sha256(git_file(root, preparation, PACKET)), "review binding: reviewed packet hash mismatch")
  assert_audit(sha256(active_contents.fetch("authority_audit_script")) == binding.fetch("audit_script_sha256"), "review binding: post-review script mutation")

  verify_packet_delta(git_file(root, preparation, PACKET), active_contents.fetch("execution_packet"))
  prep_aggregate = git_file(root, preparation, AGGREGATE)
  assert_audit(aggregate_projection(prep_aggregate) == aggregate_projection(active_contents.fetch("aggregate_packet_review")), "review binding: aggregate substantive mutation")
  REVIEW_NAMES.each do |name|
    key = name == "spec_compliance" ? "spec_review" : (name == "engineering_security" ? "engineering_review" : "qa_review")
    prep_review = git_file(root, preparation, REVIEW_PATHS.fetch(name))
    assert_audit(review_projection(prep_review) == review_projection(active_contents.fetch(key)), "review binding: review evidence substantive mutation #{name}")
  end

  manifest.each do |entry|
    key = entry.fetch("key")
    next if %w[execution_packet aggregate_packet_review spec_review engineering_review qa_review].include?(key)
    next if phase == "post-integration" && %w[evidence_summary test_results].include?(key)

    assert_audit(sha256(active_contents.fetch(key)) == entry.fetch("sha256"), "review binding: canonical input mutation #{key}")
  end
end

def token_expected_counts(phase)
  expected = Hash.new { |hash, path| hash[path] = Hash.new(0) }
  return expected if phase == "pre-review"

  expected[AGGREGATE]["packet_review"] = 2
  REVIEW_NAMES.each { |name| expected[AGGREGATE][name] = 2 }
  REVIEW_NAMES.each { |name| expected[REVIEW_PATHS.fetch(name)][name] = 1 }
  unless phase == "post-integration"
    expected[AGGREGATE]["execution_authorization"] = 2
    expected[AGGREGATE]["governance_followup"] = 2
    expected[PACKET]["packet_review"] = 1
    expected[PACKET]["execution_authorization"] = 1
    expected[PACKET]["governance_followup"] = 1
  end
  if phase == "post-integration"
    expected[ATTEMPT]["packet_review"] = 1
    REVIEW_NAMES.each { |name| expected[ATTEMPT][name] = 1 }
  end
  expected
end

def audit_tokens(stage_contents, phase)
  kinds = %w[packet_review spec_compliance engineering_security qa_evidence execution_authorization governance_followup ready_authority]
  stage_contents.each do |path, content|
    (1..7).each do |number|
      kinds.each do |kind|
        assert_audit(semantic_count(content, number, kind).zero?, "token scan: old authority token in #{path}")
      end
    end
  end
  expected = token_expected_counts(phase)
  stage_contents.each do |path, content|
    kinds.each do |kind|
      count = semantic_count(content, 8, kind)
      wanted = expected[path][kind]
      assert_audit(count == wanted, "token scan: current #{kind} placement mismatch in #{path}")
    end
    initial_components = ["T202C" + "3", "A00" + "6", "PACKET", "REVIEW", "PASS"]
    initial_pattern = Regexp.new("(?<![[:alnum:]])#{initial_components.map { |part| Regexp.escape(part) }.join('[^[:alnum:]]*')}(?![[:alnum:]])", Regexp::IGNORECASE)
    expected_semantic_initial = INITIAL_PASS_SEMANTIC_ALLOWED_COUNTS.fetch(path, 0)
    assert_audit(content.scan(initial_pattern).length == expected_semantic_initial, "token scan: initial PASS placement mismatch in #{path}")
    exact_initial = initial_components.join("_")
    expected_initial = INITIAL_PASS_ALLOWED_COUNTS.fetch(path, 0)
    assert_audit(content.scan(exact_initial).length == expected_initial, "token scan: decorated initial PASS token in #{path}")
  end
end

def historical_audit(historical_contents, initial_contents)
  historical_contents.each do |key, content|
    status = visible_status(content, "historical #{key}")
    assert_audit(%w[FAILED_NEEDS_CONTRACT_CLARIFICATION FAILED_NO_EXECUTION_AUTHORIZATION].include?(status), "historical #{key}: failed status mismatch")
    fields = visible_authority_fields(
      content,
      "historical #{key}",
      required_keys: %w[execution_authorization packet_review_token],
      allowed_keys: %w[execution_authorization packet_review_token governance_followup]
    )
    assert_audit(fields.fetch("execution_authorization") == "none", "historical #{key}: execution authority exists")
    assert_audit(fields.fetch("packet_review_token") == "none", "historical #{key}: review authority exists")
    assert_audit(fields.fetch("governance_followup") == "none", "historical #{key}: follow-up authority exists") if fields.key?("governance_followup")
  end
  initial_token = ["T202C" + "3", "A00" + "6", "PACKET", "REVIEW", "PASS"].join("_")
  initial_contents.each do |key, content|
    fields = content.scan(/^[ \t]*- Review token:[ \t]*`?([^`\r\n]+)`?[ \t]*$/i)
    assert_audit(fields.length == 1 && fields.first.first.strip == initial_token, "initial pass #{key}: review token field mismatch")
    assert_audit(content.scan(initial_token).length == 1, "initial pass #{key}: token mismatch")
  end
end

def parse_reference(content, label)
  block = extract_block(content, REFERENCE_START, REFERENCE_END, label)
  document = strict_yaml(block, label)
  exact_keys(document, ["integration_reference"], "#{label}.document")
  reference = document.fetch("integration_reference")
  exact_keys(reference, %w[status attempt_path aggregate_path candidate_commit], "#{label}.reference")
  reference
end

def production_diff_paths(root, preparation_commit, candidate_commit)
  paths = git_capture(root, "diff", "--name-only", "#{preparation_commit}..#{candidate_commit}").lines.map(&:strip).reject(&:empty?)
  paths.reject { |path| path.start_with?(".ai-platform/") }
end

def allowed_production_path?(path)
  EXACT_PRODUCTION_FILES.include?(path) || EXACT_TEST_FILES.include?(path) || path.start_with?(FIXTURE_PREFIX)
end

def audit_integration(root, active_contents, packet_content, aggregate_content, review_contents, binding)
  attempt_content = active_contents.fetch("attempt_evidence")
  assert_audit(visible_status(attempt_content, "attempt") == "REVIEW_COMPLETE", "integration: attempt visible status mismatch")
  block = extract_block(attempt_content, INTEGRATION_START, INTEGRATION_END, "attempt integration")
  document = strict_yaml(block, "attempt integration")
  exact_keys(document, ["integration_evidence"], "attempt integration document")
  evidence = document.fetch("integration_evidence")
  exact_keys(evidence, %w[schema_version status validation_status attempt preparation_commit candidate_commit expected_head production_diff_paths packet aggregate summary test_results review_refs packet_review_token review_tokens execution_authorization_sha256 governance_followup_sha256], "integration_evidence")
  assert_audit(evidence.fetch("schema_version") == 1, "integration: schema mismatch")
  assert_audit(evidence.fetch("status") == "review_complete", "integration: terminal status mismatch")
  assert_audit(evidence.fetch("validation_status") == "VALIDATED", "integration: validation not exact")
  assert_audit(evidence.fetch("attempt") == "T202C3-A006-F008", "integration: attempt mismatch")
  assert_audit(evidence.fetch("preparation_commit") == binding.fetch("preparation_commit"), "integration: preparation mismatch")
  candidate = evidence.fetch("candidate_commit")
  verify_commit(root, candidate)
  head = git_capture(root, "rev-parse", "HEAD").strip
  assert_audit(candidate == head && evidence.fetch("expected_head") == head, "integration: candidate not expected HEAD")
  git_capture(root, "merge-base", "--is-ancestor", binding.fetch("preparation_commit"), candidate)
  diff_paths = production_diff_paths(root, binding.fetch("preparation_commit"), candidate)
  assert_audit(diff_paths.all? { |path| allowed_production_path?(path) }, "integration: production diff outside exact scope")
  assert_audit(evidence.fetch("production_diff_paths") == diff_paths, "integration: production diff evidence mismatch")

  expected_files = {
    "packet" => [PACKET, packet_content],
    "aggregate" => [AGGREGATE, aggregate_content],
    "summary" => [SUMMARY, active_contents.fetch("evidence_summary")],
    "test_results" => [TEST_RESULTS, active_contents.fetch("test_results")]
  }
  expected_files.each do |field, (path, content)|
    record = evidence.fetch(field)
    exact_keys(record, %w[path sha256], "integration.#{field}")
    assert_audit(record == { "path" => path, "sha256" => sha256(content) }, "integration: #{field} binding mismatch")
  end
  refs = review_refs(review_contents)
  assert_audit(evidence.fetch("review_refs") == refs, "integration: review refs mismatch")
  assert_audit(evidence.fetch("packet_review_token") == exact_token("packet_review"), "integration: packet review token mismatch")
  expected_reviews = REVIEW_NAMES.to_h { |name| [name, exact_token(name)] }
  assert_audit(evidence.fetch("review_tokens") == expected_reviews, "integration: review token mismatch")
  assert_audit(evidence.fetch("execution_authorization_sha256") == sha256(exact_token("execution_authorization")), "integration: execution digest mismatch")
  assert_audit(evidence.fetch("governance_followup_sha256") == sha256(exact_token("governance_followup")), "integration: follow-up digest mismatch")

  { "summary" => SUMMARY, "test_results" => TEST_RESULTS }.each do |key, _path|
    reference = parse_reference(active_contents.fetch(key == "summary" ? "evidence_summary" : "test_results"), "#{key} reference")
    expected = { "status" => "VALIDATED", "attempt_path" => ATTEMPT, "aggregate_path" => AGGREGATE, "candidate_commit" => candidate }
    assert_audit(reference == expected, "integration: #{key} exact reference mismatch")
  end
end

def audit_repository(root, phase, baseline: BASELINE_HEAD)
  validate_independent_allowlists
  active_map = phase == "post-integration" ? ACTIVE_ALLOWLIST_PRIMARY.merge("attempt_evidence" => ATTEMPT) : ACTIVE_ALLOWLIST_PRIMARY
  expected_count = phase == "post-integration" ? 25 : 24
  assert_audit(active_map.length == expected_count, "active phase count mismatch")
  declared = {}
  active_map.each { |key, path| declared["active:#{key}"] = path }
  HISTORICAL_FAILED.each { |key, path| declared["historical:#{key}"] = path }
  INITIAL_PASS.each { |key, path| declared["initial:#{key}"] = path }
  declared_contents = secure_read_paths(root, declared, "declared allowlists")
  active_contents = active_map.to_h { |key, _path| [key, declared_contents.fetch("active:#{key}")] }
  historical_contents = HISTORICAL_FAILED.to_h { |key, _path| [key, declared_contents.fetch("historical:#{key}")] }
  initial_contents = INITIAL_PASS.to_h { |key, _path| [key, declared_contents.fetch("initial:#{key}")] }
  stage_contents = secure_stage_contents(root)
  historical_audit(historical_contents, initial_contents)
  audit_tokens(stage_contents, phase)

  packet_content = active_contents.fetch("execution_packet")
  packet = strict_yaml(packet_content, "execution packet")
  review_contents = {
    "spec_compliance" => active_contents.fetch("spec_review"),
    "engineering_security" => active_contents.fetch("engineering_review"),
    "qa_evidence" => active_contents.fetch("qa_review")
  }

  if phase == "pre-review"
    REVIEW_NAMES.each { |name| review_record(review_contents.fetch(name), name, phase) }
    audit_aggregate(active_contents.fetch("aggregate_packet_review"), phase, baseline: baseline)
    audit_packet(packet, phase, baseline: baseline)
    return { "phase" => phase, "active" => active_contents.length, "historical" => historical_contents.length }
  end

  raw_gate = aggregate_gate(active_contents.fetch("aggregate_packet_review"))
  prep_binding = raw_gate.fetch("preparation_binding")
  binding = prep_binding.reject { |key, _| key == "baseline_head" }.merge("state" => "reviewed_authorized")
  REVIEW_NAMES.each { |name| review_record(review_contents.fetch(name), name, phase, binding: binding) }
  refs_binding = packet_binding(binding, review_contents)
  audit_aggregate(active_contents.fetch("aggregate_packet_review"), phase, review_contents: review_contents, baseline: baseline, binding: binding)
  audit_packet(packet, phase, binding: refs_binding, baseline: baseline)
  verify_reviewed_artifacts(root, active_contents, binding, phase)
  audit_integration(root, active_contents, packet_content, active_contents.fetch("aggregate_packet_review"), review_contents, binding) if phase == "post-integration"

  { "phase" => phase, "active" => active_contents.length, "historical" => historical_contents.length }
end

# Self-test fixture builders intentionally create complete temporary repositories.
def fixture_governance_inputs
  initial_token = ["T202C" + "3", "A00" + "6", "PACKET", "REVIEW", "PASS"].join("_")
  PACKET_PATH_DECLARATIONS.select { |key, _| key.start_with?("governance_inputs.") }.to_h do |key, path|
    [key.delete_prefix("governance_inputs."), path]
  end.merge("approval_gates" => { "fixture" => "self-test", "historical_initial_pass_mentions" => [initial_token, initial_token, initial_token] })
end

def fixture_packet(phase, baseline, binding: nil, review_contents: nil)
  constraints = {
    "production_permission" => PRE_PERMISSION,
    "test_permission" => PRE_PERMISSION,
    "fixture_permission" => PRE_PERMISSION,
    "future_allowed_files" => FUTURE_ALLOWED_FILES,
    "forbidden_changes" => ["fixture"],
    "write_rules" => ["fixture"]
  }
  gate = { "grant_state" => "closed", "packet_review_token" => "none", "execution_authorization" => "none", "governance_followup" => "none" }
  status = "ready_for_f008_packet_review"
  review_binding = pending_binding
  if phase == "post-authorization"
    status = "ready"
    constraints.merge!("production_permission" => POST_PRODUCTION_PERMISSION, "test_permission" => POST_TEST_PERMISSION, "fixture_permission" => POST_FIXTURE_PERMISSION)
    gate = { "grant_state" => "authorized_unspent", "packet_review_token" => exact_token("packet_review"), "execution_authorization" => exact_token("execution_authorization"), "governance_followup" => exact_token("governance_followup") }
    review_binding = packet_binding(binding, review_contents)
  elsif phase == "post-integration"
    status = "review_complete"
    constraints.merge!("production_permission" => TERMINAL_PERMISSION, "test_permission" => TERMINAL_PERMISSION, "fixture_permission" => TERMINAL_PERMISSION)
    gate = { "grant_state" => "spent_non_replayable", "packet_review_token" => "spent", "execution_authorization" => "spent", "governance_followup" => "spent" }
    review_binding = packet_binding(binding, review_contents)
  end
  {
    "schema_version" => 1,
    "packet_id" => "007-T110-T202C3-A006-F008",
    "task_id" => "T110",
    "feature_id" => "007-stable-v1-program",
    "mode" => "delegated_test_first_execution",
    "adapter" => "codex_worker",
    "status" => status,
    "governance_inputs" => fixture_governance_inputs,
    "work_unit" => { "attempt" => "T202C3-A006-F008" },
    "codebase_context" => { "baseline_head" => baseline },
    "execution_gate" => gate,
    "authority_review_binding" => review_binding,
    "execution_constraints" => constraints,
    "evidence_contract" => {
      "attempt_path" => ATTEMPT,
      "packet_review_path" => AGGREGATE,
      "review_paths" => REVIEW_PATHS,
      "summary_path" => SUMMARY,
      "test_results_path" => TEST_RESULTS,
      "required" => ["fixture"],
      "prohibited" => ["fixture"]
    },
    "authority_audit_contract" => { "post_integration" => { "attempt_path" => ATTEMPT } }
  }
end

def fixture_review(name, phase, binding: nil)
  passed = phase != "pre-review"
  record = {
    "schema_version" => 1,
    "kind" => name,
    "status" => passed ? "PASSED_ZERO_FINDINGS" : "PENDING",
    "preparation_commit" => passed ? binding.fetch("preparation_commit") : "none",
    "audit_script_sha256" => passed ? binding.fetch("audit_script_sha256") : "none",
    "packet_sha256" => passed ? binding.fetch("packet_sha256") : "none",
    "canonical_manifest_sha256" => passed ? binding.fetch("canonical_manifest_sha256") : "none",
    "canonical_manifest" => passed ? binding.fetch("canonical_manifest") : [],
    "findings" => passed ? FINDING_NAMES.to_h { |finding| [finding, 0] } : nil,
    "review_token" => passed ? exact_token(name) : "none"
  }
  yaml = YAML.dump("review_record" => record).delete_prefix("---\n")
  status = passed ? "PASSED_ZERO_FINDINGS" : "PENDING_REVIEW"
  <<~MARKDOWN
    # Fixture #{name}

    ## Status

    `#{status}`

    #{REVIEW_START}
    #{yaml.rstrip}
    #{REVIEW_END}

    No review result or execution authority exists.
  MARKDOWN
end

def fixture_aggregate(phase, baseline, binding: nil, review_contents: nil)
  passed = phase != "pre-review"
  terminal = phase == "post-integration"
  state = passed ? (terminal ? "REVIEW_COMPLETE" : "PASSED_AUTHORIZED_FOR_EXECUTION") : "PENDING_REVIEW"
  visible = passed ? (terminal ? "REVIEW_COMPLETE" : "PASSED_AUTHORIZED_FOR_EXECUTION") : "PENDING_THREE_INDEPENDENT_REVIEWS"
  grant = passed ? (terminal ? "spent_non_replayable" : "authorized_unspent") : "closed"
  execution = passed ? (terminal ? "spent" : exact_token("execution_authorization")) : "none"
  followup = passed ? (terminal ? "spent" : exact_token("governance_followup")) : "none"
  packet_token = passed ? exact_token("packet_review") : "none"
  prep = if passed
           binding.reject { |key, _| key == "state" || key == "review_refs" }.merge("baseline_head" => baseline)
         else
           { "baseline_head" => baseline, "preparation_commit" => "none", "audit_script_sha256" => "none", "packet_sha256" => "none", "canonical_manifest_sha256" => "none", "canonical_manifest" => [] }
         end
  reviews = REVIEW_NAMES.to_h do |name|
    if passed
      [name, { "status" => "PASSED_ZERO_FINDINGS", "token" => exact_token(name), "findings" => FINDING_NAMES.to_h { |finding| [finding, 0] }, "evidence_path" => REVIEW_PATHS.fetch(name), "evidence_sha256" => sha256(review_contents.fetch(name)) }]
    else
      [name, { "status" => "PENDING", "token" => "none", "findings" => nil, "evidence_path" => REVIEW_PATHS.fetch(name), "evidence_sha256" => "none" }]
    end
  end
  gate = { "authority_gate" => { "schema_version" => 2, "state" => state, "grant_state" => grant, "packet_review_token" => packet_token, "execution_authorization" => execution, "governance_followup" => followup, "preparation_binding" => prep, "reviews" => reviews } }
  yaml = YAML.dump(gate).delete_prefix("---\n")
  rows = REVIEW_NAMES.map do |name|
    label = { "spec_compliance" => "Spec compliance", "engineering_security" => "Engineering/security", "qa_evidence" => "QA/evidence" }.fetch(name)
    passed ? "| #{label} | PASS | C0/H0/M0/L0 | #{exact_token(name)} |" : "| #{label} | PENDING | Not assessed | none |"
  end.join("\n")
  <<~MARKDOWN
    # Fixture Aggregate

    ## Status

    `#{visible}`

    - Execution authorization: #{execution}
    - Review token: #{packet_token}
    - Governance follow-up: #{followup}

    #{GATE_START}
    #{yaml.rstrip}
    #{GATE_END}

    ## Review Matrix

    | Pass | Status | Findings | Review token |
    | --- | --- | --- | --- |
    #{rows}

    Stable narrative.
  MARKDOWN
end

def fixture_failed
  <<~MARKDOWN
    # Failed

    ## Status

    `FAILED_NO_EXECUTION_AUTHORIZATION`

    - Execution authorization: none
    - Review token: none
    - Governance follow-up: none
  MARKDOWN
end

def write_base_fixture(root, baseline)
  all_paths = ACTIVE_ALLOWLIST_PRIMARY.values + HISTORICAL_FAILED.values + INITIAL_PASS.values + INITIAL_PASS_ALLOWED_COUNTS.keys
  all_paths.uniq.each do |relative|
    path = File.join(root, relative)
    FileUtils.mkdir_p(File.dirname(path))
    File.write(path, "fixture\n")
  end
  File.write(File.join(root, PACKET), YAML.dump(fixture_packet("pre-review", baseline)))
  File.write(File.join(root, AGGREGATE), fixture_aggregate("pre-review", baseline))
  REVIEW_NAMES.each { |name| File.write(File.join(root, REVIEW_PATHS.fetch(name)), fixture_review(name, "pre-review")) }
  File.write(File.join(root, SCRIPT), "fixture audit script\n")
  HISTORICAL_FAILED.each_value { |relative| File.write(File.join(root, relative), fixture_failed) }
  initial_token = ["T202C" + "3", "A00" + "6", "PACKET", "REVIEW", "PASS"].join("_")
  initial_title = [["T202C" + "3", "A00" + "6"].join("-"), %w[Packet Review Pass].join(" ")].join(" ")
  INITIAL_PASS.each_value do |relative|
    File.write(File.join(root, relative), "# #{initial_title}\n\n- Review token: `#{initial_token}`\n")
  end
  INITIAL_PASS_ALLOWED_COUNTS.each do |relative, count|
    next if relative == PACKET || INITIAL_PASS.value?(relative)

    File.write(File.join(root, relative), Array.new(count, initial_token).join("\n") + "\n")
  end
end

def git!(root, *args)
  git_capture(root, *args)
end

def with_git_fixture
  Dir.mktmpdir("a006-f008-audit") do |root|
    git!(root, "init", "-q")
    git!(root, "config", "user.email", "fixture@example.invalid")
    git!(root, "config", "user.name", "Fixture")
    File.write(File.join(root, ".baseline"), "baseline\n")
    git!(root, "add", ".baseline")
    git!(root, "commit", "-q", "-m", "baseline")
    baseline = git!(root, "rev-parse", "HEAD").strip
    write_base_fixture(root, baseline)
    git!(root, "add", ".ai-platform")
    git!(root, "commit", "-q", "-m", "prepare")
    preparation = git!(root, "rev-parse", "HEAD").strip
    yield root, baseline, preparation
  end
end

def authorize_fixture(root, baseline, preparation)
  binding = binding_for_commit(root, preparation, baseline)
  reviews = REVIEW_NAMES.to_h { |name| [name, fixture_review(name, "post-authorization", binding: binding)] }
  reviews.each { |name, content| File.write(File.join(root, REVIEW_PATHS.fetch(name)), content) }
  File.write(File.join(root, AGGREGATE), fixture_aggregate("post-authorization", baseline, binding: binding, review_contents: reviews))
  File.write(File.join(root, PACKET), YAML.dump(fixture_packet("post-authorization", baseline, binding: binding, review_contents: reviews)))
  [binding, reviews]
end

def integration_reference(candidate)
  yaml = YAML.dump("integration_reference" => { "status" => "VALIDATED", "attempt_path" => ATTEMPT, "aggregate_path" => AGGREGATE, "candidate_commit" => candidate }).delete_prefix("---\n")
  <<~MARKDOWN
    #{REFERENCE_START}
    #{yaml.rstrip}
    #{REFERENCE_END}
  MARKDOWN
end

def terminal_fixture(root, baseline, preparation, binding, reviews)
  git!(root, "add", ".ai-platform")
  git!(root, "commit", "-q", "-m", "authorize")
  production = File.join(root, EXACT_PRODUCTION_FILES.first)
  FileUtils.mkdir_p(File.dirname(production))
  File.write(production, "production fixture\n")
  git!(root, "add", EXACT_PRODUCTION_FILES.first)
  git!(root, "commit", "-q", "-m", "candidate")
  candidate = git!(root, "rev-parse", "HEAD").strip

  packet_content = YAML.dump(fixture_packet("post-integration", baseline, binding: binding, review_contents: reviews))
  aggregate_content = fixture_aggregate("post-integration", baseline, binding: binding, review_contents: reviews)
  File.write(File.join(root, PACKET), packet_content)
  File.write(File.join(root, AGGREGATE), aggregate_content)
  summary_content = "# Summary\n\n#{integration_reference(candidate)}"
  test_content = "# Tests\n\n#{integration_reference(candidate)}"
  File.write(File.join(root, SUMMARY), summary_content)
  File.write(File.join(root, TEST_RESULTS), test_content)
  refs = review_refs(reviews)
  evidence = {
    "integration_evidence" => {
      "schema_version" => 1, "status" => "review_complete", "validation_status" => "VALIDATED",
      "attempt" => "T202C3-A006-F008", "preparation_commit" => preparation,
      "candidate_commit" => candidate, "expected_head" => candidate,
      "production_diff_paths" => [EXACT_PRODUCTION_FILES.first],
      "packet" => { "path" => PACKET, "sha256" => sha256(packet_content) },
      "aggregate" => { "path" => AGGREGATE, "sha256" => sha256(aggregate_content) },
      "summary" => { "path" => SUMMARY, "sha256" => sha256(summary_content) },
      "test_results" => { "path" => TEST_RESULTS, "sha256" => sha256(test_content) },
      "review_refs" => refs, "packet_review_token" => exact_token("packet_review"),
      "review_tokens" => REVIEW_NAMES.to_h { |name| [name, exact_token(name)] },
      "execution_authorization_sha256" => sha256(exact_token("execution_authorization")),
      "governance_followup_sha256" => sha256(exact_token("governance_followup"))
    }
  }
  yaml = YAML.dump(evidence).delete_prefix("---\n")
  attempt_content = <<~MARKDOWN
    # Attempt

    ## Status

    `REVIEW_COMPLETE`

    #{INTEGRATION_START}
    #{yaml.rstrip}
    #{INTEGRATION_END}
  MARKDOWN
  path = File.join(root, ATTEMPT)
  FileUtils.mkdir_p(File.dirname(path))
  File.write(path, attempt_content)
  [candidate, attempt_content]
end

def expect_failure(label, contains = nil)
  yield
  raise AuditFailure, "self-test #{label}: expected failure"
rescue AuditFailure => e
  raise if e.message.start_with?("self-test #{label}: expected failure")
  assert_audit(contains.nil? || e.message.include?(contains), "self-test #{label}: wrong failure #{e.message}")
  true
end

def replace_file(root, relative)
  path = File.join(root, relative)
  original = File.binread(path)
  yield path, original
ensure
  File.binwrite(path, original) if original && path
end

def run_self_test
  cases = 0

  with_git_fixture do |root, baseline, _preparation|
    audit_repository(root, "pre-review", baseline: baseline)
  end
  cases += 1

  with_git_fixture do |root, baseline, preparation|
    authorize_fixture(root, baseline, preparation)
    audit_repository(root, "post-authorization", baseline: baseline)
  end
  cases += 1

  with_git_fixture do |root, baseline, preparation|
    binding, reviews = authorize_fixture(root, baseline, preparation)
    terminal_fixture(root, baseline, preparation, binding, reviews)
    audit_repository(root, "post-integration", baseline: baseline)
  end
  cases += 1

  primary = ACTIVE_ALLOWLIST_PRIMARY.merge("product_contract" => ".ai-platform/substitute.md")
  expect_failure("modified literal and packet", "independent allowlist path") do
    validate_independent_allowlists(primary, ACTIVE_ALLOWLIST_SECONDARY)
  end
  cases += 1

  with_git_fixture do |root, baseline, _preparation|
    packet = fixture_packet("pre-review", baseline)
    packet.fetch("governance_inputs")["product_contract"] = ".ai-platform/substitute.md"
    File.write(File.join(root, PACKET), YAML.dump(packet))
    expect_failure("modified packet path", "path declaration") { audit_repository(root, "pre-review", baseline: baseline) }
  end
  cases += 1

  with_git_fixture do |root, baseline, _preparation|
    target = File.join(root, ACTIVE_ALLOWLIST_PRIMARY.fetch("product_contract"))
    File.delete(target)
    File.symlink(File.join(root, ACTIVE_ALLOWLIST_PRIMARY.fetch("program_plan")), target)
    expect_failure("symlink alias", "symlink forbidden") { audit_repository(root, "pre-review", baseline: baseline) }
  end
  cases += 1

  with_git_fixture do |root, baseline, _preparation|
    File.delete(File.join(root, ACTIVE_ALLOWLIST_PRIMARY.fetch("product_contract")))
    expect_failure("missing declared path", "missing path") { audit_repository(root, "pre-review", baseline: baseline) }
  end
  cases += 1

  with_git_fixture do |root, baseline, _preparation|
    path = File.join(root, ACTIVE_ALLOWLIST_PRIMARY.fetch("product_contract"))
    File.delete(path)
    Dir.mkdir(path)
    expect_failure("non-regular declared path", "non-regular file") { audit_repository(root, "pre-review", baseline: baseline) }
  end
  cases += 1

  with_git_fixture do |root, baseline, _preparation|
    packet = fixture_packet("pre-review", baseline)
    packet.fetch("execution_constraints")["permission_override"] = "allow"
    File.write(File.join(root, PACKET), YAML.dump(packet))
    expect_failure("extra permission", "exact key/shape") { audit_repository(root, "pre-review", baseline: baseline) }
  end
  cases += 1

  with_git_fixture do |root, baseline, _preparation|
    path = File.join(root, PACKET)
    content = File.read(path).sub("status: ready_for_f008_packet_review", "status: ready_for_f008_packet_review\nstatus: ready_for_f008_packet_review")
    File.write(path, content)
    expect_failure("duplicate YAML field", "duplicate YAML key") { audit_repository(root, "pre-review", baseline: baseline) }
  end
  cases += 1

  with_git_fixture do |root, baseline, _preparation|
    path = File.join(root, AGGREGATE)
    File.open(path, "a") { |file| file.write("\n- Execution authorization: none\n") }
    expect_failure("duplicate visible authority field", "duplicate visible execution_authorization") { audit_repository(root, "pre-review", baseline: baseline) }
  end
  cases += 1

  with_git_fixture do |root, baseline, _preparation|
    path = File.join(root, AGGREGATE)
    block = File.read(path).match(/#{Regexp.escape(GATE_START)}\r?\n.*?\r?\n#{Regexp.escape(GATE_END)}/m).to_s
    File.open(path, "a") { |file| file.write("\n#{block}\n") }
    expect_failure("duplicate authority block", "block count mismatch") { audit_repository(root, "pre-review", baseline: baseline) }
  end
  cases += 1

  with_git_fixture do |root, baseline, _preparation|
    File.delete(File.join(root, REVIEW_PATHS.fetch("qa_evidence")))
    expect_failure("missing review", "missing path") { audit_repository(root, "pre-review", baseline: baseline) }
  end
  cases += 1

  with_git_fixture do |root, baseline, _preparation|
    path = File.join(root, AGGREGATE)
    content = File.read(path).sub("| QA/evidence | PENDING | Not assessed | none |", "| QA/evidence shadow | PENDING | Not assessed | none |\n| QA/evidence | PENDING | Not assessed | none |")
    File.write(path, content)
    expect_failure("shadow review row", "unknown/shadow review row") { audit_repository(root, "pre-review", baseline: baseline) }
  end
  cases += 1

  with_git_fixture do |root, baseline, _preparation|
    packet = fixture_packet("pre-review", baseline)
    packet.fetch("evidence_contract")["attempt_path"] = ".ai-platform/evidence/wrong.md"
    File.write(File.join(root, PACKET), YAML.dump(packet))
    expect_failure("wrong evidence path", "path declaration") { audit_repository(root, "pre-review", baseline: baseline) }
  end
  cases += 1

  old_token = exact_token_components(7, "packet_review").join("_")
  with_git_fixture do |root, baseline, _preparation|
    path = File.join(root, HISTORICAL_FAILED.fetch("f007"))
    File.open(path, "a") { |file| file.write("\n#{old_token}\n") }
    expect_failure("underscore old token", "old authority token") { audit_repository(root, "pre-review", baseline: baseline) }
  end
  cases += 1

  with_git_fixture do |root, baseline, _preparation|
    path = File.join(root, HISTORICAL_FAILED.fetch("f001"))
    File.open(path, "a") { |file| file.write("\n#{exact_token('packet_review')}\n") }
    expect_failure("historical current token", "current packet_review placement") { audit_repository(root, "pre-review", baseline: baseline) }
  end
  cases += 1

  with_git_fixture do |root, baseline, _preparation|
    path = File.join(root, INITIAL_PASS.fetch("initial_a006_packet_review"))
    content = File.read(path).sub("- Review token:", "- Historical token:")
    File.write(path, content)
    expect_failure("initial PASS decoy placement", "review token field mismatch") { audit_repository(root, "pre-review", baseline: baseline) }
  end
  cases += 1

  with_git_fixture do |root, baseline, _preparation|
    path = File.join(root, ATTEMPT)
    FileUtils.mkdir_p(File.dirname(path))
    File.write(path, "premature\n#{exact_token('execution_authorization')}\n")
    expect_failure("premature attempt token", "current execution_authorization placement") { audit_repository(root, "pre-review", baseline: baseline) }
  end
  cases += 1

  with_git_fixture do |root, baseline, _preparation|
    path = File.join(root, AGGREGATE)
    content = File.read(path).sub("- Execution authorization: none", "- Execution authorization: #{exact_token('execution_authorization').downcase}\n\n#{exact_token('execution_authorization')}")
    File.write(path, content)
    expect_failure("lowercase field uppercase decoy", "placement mismatch") { audit_repository(root, "pre-review", baseline: baseline) }
  end
  cases += 1

  with_git_fixture do |root, baseline, _preparation|
    path = File.join(root, SUMMARY)
    decorated = exact_token_components(8, "packet_review").join("\n***___")
    File.open(path, "a") { |file| file.write("\n#{decorated}\n") }
    expect_failure("cross-line decorated token", "current packet_review placement") { audit_repository(root, "pre-review", baseline: baseline) }
  end
  cases += 1

  with_git_fixture do |root, baseline, _preparation|
    path = File.join(root, SCRIPT)
    File.open(path, "a") { |file| file.write("\n#{exact_token('packet_review')}\n") }
    expect_failure("script self-token trap", "current packet_review placement") { audit_repository(root, "pre-review", baseline: baseline) }
  end
  cases += 1

  with_git_fixture do |root, baseline, preparation|
    _binding, _reviews = authorize_fixture(root, baseline, preparation)
    File.write(File.join(root, PACKET), YAML.dump(fixture_packet("pre-review", baseline)))
    expect_failure("pending packet with authorized aggregate", "current packet_review placement") { audit_repository(root, "post-authorization", baseline: baseline) }
  end
  cases += 1

  with_git_fixture do |root, baseline, preparation|
    _binding, _reviews = authorize_fixture(root, baseline, preparation)
    path = File.join(root, SCRIPT)
    File.open(path, "a") { |file| file.write("mutation\n") }
    expect_failure("post-review script mutation", "post-review script mutation") { audit_repository(root, "post-authorization", baseline: baseline) }
  end
  cases += 1

  with_git_fixture do |root, baseline, preparation|
    authorize_fixture(root, baseline, preparation)
    packet = strict_yaml(File.read(File.join(root, PACKET)), "fixture packet")
    packet["unreviewed"] = true
    File.write(File.join(root, PACKET), YAML.dump(packet))
    expect_failure("post-review packet mutation", "unauthorized packet delta") { audit_repository(root, "post-authorization", baseline: baseline) }
  end
  cases += 1

  with_git_fixture do |root, baseline, preparation|
    binding, reviews = authorize_fixture(root, baseline, preparation)
    stale = binding.merge("preparation_commit" => baseline)
    File.write(File.join(root, AGGREGATE), fixture_aggregate("post-authorization", baseline, binding: stale, review_contents: reviews))
    expect_failure("stale reviewed head", "preparation") { audit_repository(root, "post-authorization", baseline: baseline) }
  end
  cases += 1

  with_git_fixture do |root, baseline, preparation|
    binding, reviews = authorize_fixture(root, baseline, preparation)
    bad = binding.merge("packet_sha256" => "1" * 64)
    File.write(File.join(root, AGGREGATE), fixture_aggregate("post-authorization", baseline, binding: bad, review_contents: reviews))
    expect_failure("stale reviewed hash", "packet_sha256") { audit_repository(root, "post-authorization", baseline: baseline) }
  end
  cases += 1

  with_git_fixture do |root, baseline, preparation|
    binding, reviews = authorize_fixture(root, baseline, preparation)
    terminal_fixture(root, baseline, preparation, binding, reviews)
    packet = fixture_packet("post-integration", baseline, binding: binding, review_contents: reviews)
    packet.fetch("execution_constraints")["fixture_permission"] = POST_FIXTURE_PERMISSION
    File.write(File.join(root, PACKET), YAML.dump(packet))
    expect_failure("replayable terminal permission", "terminal permission replayable") { audit_repository(root, "post-integration", baseline: baseline) }
  end
  cases += 1

  with_git_fixture do |root, baseline, preparation|
    binding, reviews = authorize_fixture(root, baseline, preparation)
    terminal_fixture(root, baseline, preparation, binding, reviews)
    path = File.join(root, ATTEMPT)
    content = File.read(path).sub(/candidate_commit: [0-9a-f]{40}/, "candidate_commit: #{'0' * 40}")
    File.write(path, content)
    expect_failure("all-zero commit", "git:") { audit_repository(root, "post-integration", baseline: baseline) }
  end
  cases += 1

  with_git_fixture do |root, baseline, preparation|
    binding, reviews = authorize_fixture(root, baseline, preparation)
    terminal_fixture(root, baseline, preparation, binding, reviews)
    path = File.join(root, ATTEMPT)
    content = File.read(path).sub(/candidate_commit: [0-9a-f]{40}/, "candidate_commit: #{'1' * 40}")
    File.write(path, content)
    expect_failure("nonexistent commit", "git cat-file") { audit_repository(root, "post-integration", baseline: baseline) }
  end
  cases += 1

  with_git_fixture do |root, baseline, preparation|
    binding, reviews = authorize_fixture(root, baseline, preparation)
    terminal_fixture(root, baseline, preparation, binding, reviews)
    path = File.join(root, ATTEMPT)
    content = File.read(path).sub(/(packet:\s+path:[^\r\n]+\r?\n\s+sha256: )[0-9a-f]{64}/m, "\\1#{'2' * 64}")
    File.write(path, content)
    expect_failure("wrong evidence hash", "packet binding") { audit_repository(root, "post-integration", baseline: baseline) }
  end
  cases += 1

  with_git_fixture do |root, baseline, preparation|
    binding, reviews = authorize_fixture(root, baseline, preparation)
    terminal_fixture(root, baseline, preparation, binding, reviews)
    path = File.join(root, SUMMARY)
    changed = File.read(path).sub("status: VALIDATED", "status: NOT VALIDATED")
    File.write(path, changed)
    attempt_path = File.join(root, ATTEMPT)
    attempt = File.read(attempt_path).sub(/(summary:\s+path:[^\r\n]+\r?\n\s+sha256: )[0-9a-f]{64}/m, "\\1#{sha256(changed)}")
    File.write(attempt_path, attempt)
    expect_failure("negated validation reference", "summary exact reference") { audit_repository(root, "post-integration", baseline: baseline) }
  end
  cases += 1

  puts("a006_authority_audit_self_test=pass cases=#{cases}")
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
    puts("a006_authority_audit=#{result.fetch('phase')} active=#{result.fetch('active')} historical_failed=#{result.fetch('historical')}")
  end
rescue AuditFailure, KeyError, TypeError => e
  warn("a006_authority_audit: #{e.message}")
  exit(1)
end
