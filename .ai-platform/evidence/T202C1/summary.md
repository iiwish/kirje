# T202C1 Evidence Summary

T202C1 is accepted under the delegated project-owner authority at production
commit `aa53efb`. Three bounded, test-first attempts delivered one canonical
grant-use substrate and exact owner-authorized config-store enrollment over the
unchanged Authority SQLite v1 schema.

The accepted implementation derives durable grant, store, and event time from
checked effective authority time. It binds exact immutable grant and
time-independent enrollment-intent transcripts, commits authorized-unclaimed
expiry before returning its stable error, preserves exact recovery after
response loss, and keeps store IDs and sealed location digests immutable and
one-to-one. Fresh challenge issuance checks current occupancy only after exact
pending reuse; historical pending, authorized, expired, used, and sibling
challenges remain intrinsic history.

Grant use, its event, store enrollment, its event, and the paired clock update
commit under one fixed lock and one `BEGIN IMMEDIATE` transaction. Deterministic
fault, stale-handle, expiry, alias, and concurrency matrices prove rollback or
exact recovery with zero enrollment entropy. Restart validation checks exact
challenge, receipt, grant, store, transcript, and event causality without
accepting any later-stage row.

The final 128-row legal-history path performs each of six whole-table
preflights once, four registry streams, and exactly `20 * 128` bounded indexed
lookups. Independent `EXPLAIN QUERY PLAN` review found only primary, unique,
entity-event, and lifecycle indexes, with no temporary sort, correlated scan,
history-proportional collection, or quadratic preflight chain.

Independent final review returned zero Critical, High, or Medium finding and
one accepted Low watch item: the test-only trait scanner could false-positive
on a future raw string containing code-like text. Current production source has
no such raw string and independent source review found no prohibited trait.

The orchestrator independently reran every packet and repository gate. Results
include 15/15 registry, 33/33 authorization, 27/27 schema, 94/94 kirje-store,
19/19 no-default-feature, and 203/203 workspace tests. Format, Clippy, build,
Rust 1.88, schema digest, cargo-deny license/ban/source, artifact, scope,
whitespace, privacy, and secret gates pass.

The canonical DDL remains SHA-256
`572a73ba5fa83c763188d804ce9767a3c21373410d8b170f6d97b49be0a86454`
with 17 tables, 15 indexes, and 3 triggers. Advisory-only checking still
reports only the pre-existing yanked `chacha20 0.10.1` through the unchanged
`io-imap` dependency chain. T202C2 owns account-create issuance and transition
validation and remains Draft pending its independently reviewed packet.
