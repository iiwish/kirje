#!/usr/bin/env ruby
# frozen_string_literal: true

require "yaml"

ROOT = File.expand_path("../..", __dir__)
PACKET = ".ai-platform/specs/007-stable-v1-program/packets/T110-A006.yaml"
AGGREGATE = ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F006-packet-review.md"
ATTEMPT = ".ai-platform/evidence/T202C3/attempts/T202C3-A006-F006.md"
SUMMARY = ".ai-platform/evidence/T202C3/summary.md"
TEST_RESULTS = ".ai-platform/evidence/T202C3/test-results.md"
CURRENT_STATUS = [
  ".ai-platform/evidence/T202C3/attempts/T202C3-A006.md",
  SUMMARY,
  TEST_RESULTS
].freeze
HISTORICAL_PASS = {
  ".ai-platform/evidence/T202C3/attempts/T202C3-A006-packet-review.md" =>
    "T202C3_A006_PACKET_REVIEW_PASS"
}.freeze
HISTORICAL_FAILED = (1..5).to_h do |number|
  [
    format(".ai-platform/evidence/T202C3/attempts/T202C3-A006-F%03d-packet-review.md", number),
    { "status_prefix" => "FAILED", "execution_authorization" => "NONE", "review_token" => "NONE" }
  ]
end.freeze

REVIEW_TOKENS = {
  "spec_compliance" => "T202C3_A006_F006_SPEC_REVIEW_PASS",
  "engineering_security" => "T202C3_A006_F006_ENGINEERING_SECURITY_REVIEW_PASS",
  "qa_evidence" => "T202C3_A006_F006_QA_EVIDENCE_REVIEW_PASS"
}.freeze
EXECUTION_TOKEN = "T202C3_A006_F006_EXECUTION_AUTHORIZED"
FOLLOWUP_TOKEN = "T202C3_A006_F006_GOVERNANCE_FOLLOWUP_COMPLETE"
PRE_REVIEW_ACTIVE_COUNT = 21
POST_INTEGRATION_ACTIVE_COUNT = 22

def fail_audit(message)
  warn("a006_authority_audit: #{message}")
  exit(1)
end

def normalize(value)
  value.to_s.gsub(/[`*]/, "").strip.gsub(/\s+/, " ").upcase
end

def read_complete(relative_path)
  path = File.join(ROOT, relative_path)
  fail_audit("missing path #{relative_path}") unless File.file?(path)
  fail_audit("unreadable path #{relative_path}") unless File.readable?(path)

  File.binread(path).force_encoding(Encoding::UTF_8).encode(
    Encoding::UTF_8,
    invalid: :replace,
    undef: :replace
  )
end

def collect_paths(value, paths = [])
  case value
  when Hash
    value.each_value { |nested| collect_paths(nested, paths) }
  when Array
    value.each { |nested| collect_paths(nested, paths) }
  when String
    paths << value if value.start_with?(".ai-platform/")
  end
  paths
end

def markdown_metadata(content)
  status_match = content.match(/^## Status\s*$\n+(?:\s*\n)*`([^`]+)`/m)
  fields = {}
  content.each_line do |line|
    next unless line.start_with?("- ") && line.include?(":")

    key, value = line.delete_prefix("- ").split(":", 2)
    fields[normalize(key).downcase.tr(" ", "_")] = normalize(value)
  end
  {
    "status" => normalize(status_match&.captures&.first),
    "execution_authorization" => fields.fetch("execution_authorization", ""),
    "review_token" => fields.fetch("review_token", "")
  }
end

def structured_block(content, start_marker, end_marker)
  start_at = content.index(start_marker)
  finish_at = content.index(end_marker)
  fail_audit("missing structured block #{start_marker}") unless start_at && finish_at && finish_at > start_at

  yaml_start = start_at + start_marker.length
  YAML.safe_load(content[yaml_start...finish_at], aliases: false)
end

def expected_active_paths(packet, include_attempt:)
  inputs = collect_paths(packet.fetch("governance_inputs"))
  excluded = HISTORICAL_PASS.keys + HISTORICAL_FAILED.keys
  paths = (inputs - excluded) + [PACKET] + CURRENT_STATUS
  paths << ATTEMPT if include_attempt
  fail_audit("active path enumeration contains duplicates") unless paths.length == paths.uniq.length

  paths.sort
end

def audit_path_set(paths, expected_count)
  fail_audit("active path count #{paths.length}, expected #{expected_count}") unless paths.length == expected_count
  contents = paths.to_h { |path| [path, read_complete(path)] }
  fail_audit("active path enumeration is not unique") unless contents.length == paths.length
  contents
end

def audit_historical
  HISTORICAL_PASS.each do |path, token|
    content = read_complete(path)
    fail_audit("historical PASS token mismatch #{path}") unless content.scan(token).length == 1
  end

  HISTORICAL_FAILED.each do |path, expected|
    metadata = markdown_metadata(read_complete(path))
    fail_audit("failed status mismatch #{path}") unless metadata.fetch("status").start_with?(expected.fetch("status_prefix"))
    %w[execution_authorization review_token].each do |key|
      fail_audit("failed #{key} mismatch #{path}") unless metadata.fetch(key) == expected.fetch(key)
    end
  end
end

def audit_no_legacy_active_authority(contents)
  forbidden = (1..5).flat_map do |number|
    prefix = format("T202C3_A006_F%03d_", number)
    ["PASS", "APPROVED", "AUTHORIZED"].map { |suffix| [prefix, suffix] }
  end
  contents.each do |path, content|
    tokens = content.scan(/T202C3_A006_F\d{3}_[A-Z0-9_]+/).uniq
    stale = tokens.select do |token|
      forbidden.any? { |prefix, suffix| token.start_with?(prefix) && token.include?(suffix) }
    end
    fail_audit("stale active authority #{path}: #{stale.join(', ')}") unless stale.empty?
  end
end

def audit_gate(content, phase)
  block = structured_block(content, "<!-- A006_AUTHORITY_GATE_START\n", "A006_AUTHORITY_GATE_END -->")
  gate = block.fetch("authority_gate")
  reviews = gate.fetch("reviews")

  if phase == "pre-review"
    fail_audit("pre-review state") unless normalize(gate.fetch("state")) == "PENDING_REVIEW"
    fail_audit("pre-review authorization") unless normalize(gate.fetch("execution_authorization")) == "NONE"
    fail_audit("pre-review follow-up") unless normalize(gate.fetch("governance_followup")) == "NONE"
    REVIEW_TOKENS.each_key do |name|
      review = reviews.fetch(name)
      fail_audit("pre-review #{name} status") unless normalize(review.fetch("status")) == "PENDING"
      fail_audit("pre-review #{name} token") unless normalize(review.fetch("token")) == "NONE"
    end
    return
  end

  fail_audit("authorized state") unless normalize(gate.fetch("state")) == "PASSED_AUTHORIZED_FOR_EXECUTION"
  fail_audit("execution token") unless normalize(gate.fetch("execution_authorization")) == EXECUTION_TOKEN
  fail_audit("follow-up token") unless normalize(gate.fetch("governance_followup")) == FOLLOWUP_TOKEN
  REVIEW_TOKENS.each do |name, token|
    review = reviews.fetch(name)
    fail_audit("#{name} status") unless normalize(review.fetch("status")) == "PASSED_ZERO_FINDINGS"
    fail_audit("#{name} token") unless normalize(review.fetch("token")) == token
    counts = review.fetch("findings").transform_keys(&:to_s)
    fail_audit("#{name} findings") unless %w[critical high medium low].all? { |key| counts.fetch(key) == 0 }
  end
end

def audit_authorized_tokens(contents)
  allowed = REVIEW_TOKENS.values + [EXECUTION_TOKEN, FOLLOWUP_TOKEN]
  contents.each do |path, content|
    tokens = allowed.select { |token| content.include?(token) }
    if path == AGGREGATE || path == PACKET
      fail_audit("aggregate F006 token set") unless tokens.sort == allowed.sort
      if path == AGGREGATE
        fail_audit("aggregate F006 token cardinality") unless allowed.all? { |token| content.scan(token).length == 1 }
      end
    elsif path == ATTEMPT
      attempt_tokens = REVIEW_TOKENS.values + [EXECUTION_TOKEN, FOLLOWUP_TOKEN]
      fail_audit("attempt F006 token set") unless tokens.sort == attempt_tokens.sort
      fail_audit("attempt F006 token cardinality") unless attempt_tokens.all? { |token| content.scan(token).length == 1 }
    else
      fail_audit("F006 authority outside aggregate #{path}") unless tokens.empty?
    end
  end
end

def audit_integration(contents)
  block = structured_block(contents.fetch(ATTEMPT), "<!-- A006_INTEGRATION_LINK_START\n", "A006_INTEGRATION_LINK_END -->")
  link = block.fetch("integration_link")
  expected = {
    "attempt" => "T202C3-A006-F006",
    "packet" => PACKET,
    "aggregate_review" => AGGREGATE,
    "execution_authorization" => EXECUTION_TOKEN,
    "governance_followup" => FOLLOWUP_TOKEN,
    "summary" => SUMMARY,
    "test_results" => TEST_RESULTS
  }
  expected.each do |key, value|
    fail_audit("integration #{key}") unless normalize(link.fetch(key)) == normalize(value)
  end
  fail_audit("integration review tokens") unless link.fetch("review_tokens").map { |token| normalize(token) }.sort == REVIEW_TOKENS.values.sort
  [SUMMARY, TEST_RESULTS].each do |path|
    content = contents.fetch(path)
    fail_audit("integration path linkage #{path}") unless content.include?(ATTEMPT) && content.include?(AGGREGATE)
  end
end

phase = ARGV.fetch(0, "")
fail_audit("phase must be pre-review, post-authorization, or post-integration") unless %w[pre-review post-authorization post-integration].include?(phase)

packet = YAML.safe_load(read_complete(PACKET), aliases: true)
audit_historical
include_attempt = phase == "post-integration"
expected_count = include_attempt ? POST_INTEGRATION_ACTIVE_COUNT : PRE_REVIEW_ACTIVE_COUNT
contents = audit_path_set(expected_active_paths(packet, include_attempt: include_attempt), expected_count)
audit_no_legacy_active_authority(contents)
audit_gate(contents.fetch(AGGREGATE), phase == "pre-review" ? "pre-review" : "post-authorization")
audit_authorized_tokens(contents) unless phase == "pre-review"
audit_integration(contents) if phase == "post-integration"

puts("a006_authority_audit=#{phase} active=#{contents.length} historical_failed=#{HISTORICAL_FAILED.length}")
