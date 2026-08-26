# T009 Evidence

- Result: complete
- Scope: bounded attachment reads
- RED: core/protocol compilation failed with the expected missing
  `read_attachment` adapter method.
- GREEN: domain tests enforce `attachment-1..100` and 1 MiB bounds; MIME tests
  verify exact selection, decoded size, base64 prefix, truncation, and untrusted
  marking. Existing transcript coverage proves the shared raw fetch is
  `BODY.PEEK[]` and capped before allocation.
- Review: Kirje never writes, opens, converts, or executes attachment content.
- Residual risk: attachments in raw messages larger than the 10 MiB message cap
  are rejected even when the selected attachment itself is small.
