# Boundless patches

Base: imap-codec 2.0.0-alpha.9 (imap-types 2.0.0-alpha.7), upstream
`4f2395e767b521d2dff6821e7032e093e5ca5586`.

Boundless is an IMAP client. It drives imap-next (the XiiTang fork, pinned to
this revision) over its own transport and admits each command through
`ClientCapabilities` before sending it. Each patch below says why Boundless
needs it and which tests keep it. Unless another command is named, fork tests
run with `cargo test -p imap-types -p imap-codec --all-features`; Boundless
tests live under its `protocols::imap` and `protocols::smtp` modules.

## Kept patches

### Security-layer handoff (e900627)

`Fragmentizer::take_unparsed_after_message` hands the bytes after a completely
decoded message to a newly installed layer (SASL security layer, COMPRESS) and
refuses while a message is partial. Without it, bytes the server sent after the
tagged OK would be parsed as plaintext IMAP. Fork test:
`handoff_requires_a_complete_message_and_retains_next_layer_bytes`. Boundless:
`independent_zlib_compression_boundary_refusal_invalid_data_and_cancel`.

### IMAP4rev2 syntax and client capability state (8d8f83c)

RFC 9051 commands and responses Boundless sends and reads: ESEARCH and
SEARCHRES (`$` is never expanded locally), LIST-EXTENDED selection and RETURN
options, 63-bit sizes and partial offsets, UTF-8 response text and empty
response text. `client_capabilities::ClientCapabilities` admits a command only
under advertised and explicitly enabled capabilities (advertising never enables;
IMAP4rev2's intrinsic extensions need ENABLE on a dual server). Upstream has
neither. Fork tests: `rev2_commands_survive_every_fragment_boundary_and_roundtrip`,
`rev2_responses_preserve_extensions_and_wide_sizes`,
`rejects_invalid_sets_bounds_options_and_utf8`,
`test_parse_empty_rev2_response_text`,
`rev2_intrinsic_capabilities_require_explicit_enable_on_dual_server`,
`utf8_enable_is_distinct_from_advertisement_and_rev2`.

### Wide fetch offsets in every feature set (a09ca7b)

8d8f83c encodes 63-bit partial offsets for every build, so the `NonZeroU64`
encoder must not be gated on `ext_condstore_qresync`. Evidence:
`cargo check -p imap-codec --no-default-features` compiles.

### Complete response boundaries and unambiguous RETURN options (part of 25c307a)

`Fragmentizer::complete_if_decodable` ends a message whose line merely ends in
literal-like text (`* OK text {123}`) when it already decodes completely, so the
next response is not swallowed as a literal; imap-next calls it on every
announced literal. ESEARCH and LIST RETURN refuse a standard option name used as
an extension, and body extensions carry 63-bit numbers. Fork test: the RETURN
cases in `rejects_invalid_sets_bounds_options_and_utf8`. imap-next test:
`text_ending_in_literal_syntax_does_not_consume_the_next_response`.

### CONDSTORE and QRESYNC bounds (28ceb94)

MODSEQ values are RFC 7162's positive 63-bit range, and QRESYNC match data keeps
its ordering without expanding ranges; Boundless sends both and reads server
deltas. Fork tests: `modseq_uses_rfc7162_positive_63_bit_range`,
`qresync_is_enabled_explicitly_and_match_data_is_checked_without_expanding_ranges`.
Boundless: `qresync_requires_enabled_and_preserves_server_deltas`.

### URLAUTH and extended URLFETCH (2afb8ed, 175211e, 11e97b7, 2b684e3)

RFC 4467 GENURLAUTH, URLFETCH, RESETKEY and URLMECH, RFC 5524 URLAUTH=BINARY and
validated RFC 5092 message URLs; Boundless uses them for IMAP URLAUTH and SMTP
BURL. 11e97b7 serializes URLFETCH parameters and metadata without cloning them.
2b684e3, as reworked later, decodes response URLs as the astrings the server
sent. [URLAUTH.md](URLAUTH.md) states the behavior and its regressions.
Boundless: the `urlauth`, `urlauth_binary` and `burl` tests, including the
independent Dovecot ones.

### ENABLE correlation and security-layer reset (ff43ee0)

`begin_command` records each ENABLE about to be sent, and an ENABLED response
enables only what an outstanding ENABLE asked for; `reset_security` clears
advertised and enabled state when STARTTLS or a SASL layer starts a new trust
boundary. The fork's capability tests issue ENABLE through `begin_command`.
Boundless: `state_validation_imap_starttls_resets_enabled`,
`state_validation_imap_unsolicited_enabled_requires_enable_exchange`.

### UTF-8 quoted validation (fe8c6f8, 2026-10-02)

Backport of upstream #730 (6ddee598e7b58d9d195973999a9d891a0a43b282): reject
NUL, CR and LF in construction, decoding and serde; keep valid UTF-8, quoting
and escapes. The unchecked constructor remains explicitly unchecked. Fork tests:
`test_quoted_utf8_*`, `test_arbitrary_quoted_utf8`,
`test_kat_inverse_create_utf8`, `parse_namespace_response_nul`. Drop it when
moving to an upstream release that contains #730.

## Upstream changes not taken

The MODSEQ parenthesis encoding is already identical to upstream ad06aac38;
retain one implementation and the fork's additional command/capability checks.
Do not revert that multi-purpose local commit. STATUS SIZE is independently
implemented; adopting the upstream feature/type split is not a maintenance-only
replacement. WITHIN remains outside this patch set.

## Removed (2026-10-10)

Boundless holds every response and APPEND literal whole within its size limit,
so the streaming response decoder with its literal references and 63-bit
literal lengths (5a5e505), streamed APPEND encoding (from 25c307a) and response
URL literal provenance (from 2b684e3) are gone.
