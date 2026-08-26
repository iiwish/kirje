# Provider Presets

Kirje ships a versioned provider registry at
`crates/kirje-core/data/provider-presets.json`. The JSON file is embedded into
the binary, parsed once, validated before use, and is the sole source for
built-in `account discover` results.

## Data Contract

Each profile contains:

- a unique profile `id` and stable provider-family `provider_id`;
- exact mailbox domains and the expected credential class;
- encrypted IMAP, SMTP, POP3, or JMAP endpoint facts;
- `runtime_default`, which separates configuration defaults from
  reference-only protocols;
- agent-facing setup guidance;
- provider-owned source URLs and ISO verification dates.

Only one IMAP and one SMTP endpoint may be a runtime default for a profile.
Kirje currently configures IMAP accounts and reserves SMTP data for the planned
send workflow. POP3 and JMAP entries are reference-only until their adapters and
authorization contracts exist.

## Inspection

```bash
kirje provider list
kirje provider show netease-163
kirje provider show 163.com
kirje account discover agent@163.com
```

`provider list` is intentionally summarized and bounded. `provider show` returns
the complete non-secret profile. Account discovery selects only encrypted
runtime defaults and retains an explicit unmatched result for unknown domains.

## Source Policy

Add or change a preset only with current provider-owned documentation. Record
the source and verification date in the same change, add a provider-specific
regression assertion, and run an opt-in read-only smoke check when a dedicated
test account is available. Do not infer endpoints from common port conventions,
DNS naming patterns, third-party setup blogs, or another provider in the same
corporate family.

Plaintext ports are intentionally omitted even when provider documentation
lists them. A source can document multiple secure ports, but exactly one may be
the runtime default. Compatibility claims require live evidence; a documented
preset alone is not a claim that authentication or provider quirks have been
verified end to end.
