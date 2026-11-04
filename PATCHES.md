# Boundless patches

Base: imap-codec 2.0.0-alpha.9 (imap-types 2.0.0-alpha.7), upstream
`4f2395e767b521d2dff6821e7032e093e5ca5586`.

Boundless is an IMAP client. It drives imap-next (the XiiTang fork, pinned to
this revision) over its own transport. Boundless `src/protocols/imap/capabilities.rs`
owns command admission, capability aliases, ENABLE state and incoming UTF-8
checks; this fork owns syntax, encoding and framing. Each patch below says why
Boundless needs it and which tests keep it. Unless another command is named, fork tests
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

### IMAP4rev2 syntax (8d8f83c)

RFC 9051 commands and responses Boundless sends and reads: ESEARCH and
SEARCHRES (`$` is never expanded locally), LIST-EXTENDED selection and RETURN
options, 63-bit sizes and partial offsets, UTF-8 response text and empty
response text. Boundless `src/protocols/imap/{input,command,output,download}.rs`
uses these types and wide fields; `capabilities.rs` inspects encoded fragments
and `session.rs` sends ENABLE using the retained wire types. Upstream at the
base lacks these syntax additions. Fork tests:
`rev2_commands_survive_every_fragment_boundary_and_roundtrip`,
`rev2_responses_preserve_extensions_and_wide_sizes`,
`rejects_invalid_sets_bounds_options_and_utf8`,
`test_parse_empty_rev2_response_text`.

### Wide fetch offsets in every feature set (a09ca7b)

8d8f83c encodes 63-bit partial offsets for every build, so the `NonZeroU64`
encoder must not be gated on `ext_condstore_qresync`. Boundless
`src/protocols/imap/{input,command,download}.rs` uses these wide fields. Evidence:
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

MODSEQ parsing retains RFC 7162's positive or zero-allowed 63-bit bounds where
the grammar requires each; response encoding retains `MODSEQ (<value>)`, as
upstream does. Boundless `src/protocols/imap/{input,command,output}.rs` sends
and reads these values. Fork test: `modseq_uses_rfc7162_positive_63_bit_range`.
QRESYNC enablement, ordering and range cardinality admission now live solely in
Boundless `capabilities.rs`, covered by
`qresync_is_enabled_explicitly_and_match_data_is_checked_without_expanding_ranges`
and `qresync_requires_enabled_and_preserves_server_deltas`.

### URLAUTH and extended URLFETCH (2afb8ed, 175211e, 11e97b7, 2b684e3)

RFC 4467 GENURLAUTH, URLFETCH, RESETKEY and URLMECH, RFC 5524 URLAUTH=BINARY and
validated RFC 5092 message URLs; Boundless uses them for IMAP URLAUTH and SMTP
BURL, through `src/protocols/imap/{input,command,output}.rs` and
`src/protocols/smtp/command.rs`. 11e97b7 serializes URLFETCH parameters and
metadata without cloning them.
2b684e3, as reworked later, decodes response URLs as the astrings the server
sent. [URLAUTH.md](URLAUTH.md) states the behavior and its regressions.
Boundless: the `urlauth`, `urlauth_binary` and `burl` tests, including the
independent Dovecot ones.

### UTF-8 quoted validation (fe8c6f8, 2026-10-02)

Backport of upstream #730 (6ddee598e7b58d9d195973999a9d891a0a43b282): reject
NUL, CR and LF in construction, decoding and serde; keep valid UTF-8, quoting
and escapes. The unchecked constructor remains explicitly unchecked. Fork tests:
`test_quoted_utf8_*`, `test_arbitrary_quoted_utf8`,
`test_kat_inverse_create_utf8`, `parse_namespace_response_nul`. Drop it when
moving to an upstream release that contains #730.

### BINARY response origin (2026-11-01)

A server answers a partial `BINARY[<section>]<<partial>>` fetch with the
origin, `* 1 FETCH (BINARY[1]<0> ~{5}\r\nhello)`, as it does for BODY:
Dovecot 2.4.5 sends exactly this (`src/imap/imap-fetch-body.c`,
`get_body_name`), and RFC 3516 section 4.2 and RFC 9051 section 7.5.2 describe
the result as `BINARY[<section-binary>]<<number>>`, although their ABNF leaves
the origin out. Upstream follows the ABNF, so the whole response fails to
decode and Boundless's connection ends (Boundless #432).
`MessageDataItem::Binary` gains `origin: Option<u64>`; `msg_att_static`
parses an optional `<number63>` after the section, and the encoder writes it,
both exactly as for `BodyExt`. Fork test:
`fetch::tests::binary_response_keeps_its_partial_origin`. Boundless:
`each_operation_answers_the_server_data_it_asked_for` (out-of-order partial
BINARY replies placed by origin) and the independent Dovecot test's partial
`binary_sections`.

## Upstream changes not taken

The MODSEQ parenthesis encoding is already identical to upstream ad06aac38;
retain that encoding and the required syntax/bounds changes. Command capability
and QRESYNC admission now belong only to Boundless. Do not revert the
multi-purpose local commit. STATUS SIZE is independently
implemented; adopting the upstream feature/type split is not a maintenance-only
replacement. WITHIN remains outside this patch set.

## Removed (2026-10-10)

Boundless holds every response and APPEND literal whole within its size limit,
so the streaming response decoder with its literal references and 63-bit
literal lengths (5a5e505), streamed APPEND encoding (from 25c307a) and response
URL literal provenance (from 2b684e3) are gone.

## Fixed certificate verification in the 0.103 test graph (#312)

Update the root workspace lockfile's rustls-webpki 0.103.8 to 0.103.16, the
smallest fixed patch for RUSTSEC-2026-0382. This rejects distrusted emSign
intermediate public keys in that TLS graph without changing codec code,
generated protocol definitions or public types. Regression coverage:
`cargo test -p imap-codec -p imap-types --all-features --locked`, plus
Boundless's IMAP and SMTP tests in its complete library suite.

## Retired capability owner (Boundless #43)

Remove `imap-codec/src/client_capabilities.rs` and its public export: the
`ClientCapabilities`/`Version` types, advertised/enabled/pending-ENABLE state,
aliases, command and response validators, and private helpers. This retires
the capability part of 8d8f83c and its extensions in a09ca7b, 28ceb94, ff43ee0,
2afb8ed and 175211e. Boundless already checks every command rule with typed
refusals; two validators could disagree and the second produced only Strings.
Boundless `src/protocols/imap/capabilities.rs` now owns the sole command
checkpoint, the transferred state/aliases and incoming UTF-8 check. Its
`command.rs`, `download.rs`, `session.rs` and serial worker in `mod.rs` use
that owner. Preserve existing ENABLE correlation and STARTTLS reset behavior.

Move the three owner tests to Boundless's capability module, preserving their
boundary cases and asserting typed refusal facts. Remove the capability loop
from the extended URLFETCH test; retain its syntax round trips and invalid
parameter assertions as `extended_arguments_round_trip_and_reject_invalid_parameters`.
The fork keeps all wire syntax/types, encoding, framing, numeric bounds,
URLAUTH, quoted UTF-8 and partial BINARY origins. Upstream has no equivalent
capability-state module, so removing it brings this fork closer to upstream.
The streamed APPEND validator/encoder was already removed by dfa77e9 and stays
removed. No cancellation, timeout, close or retry path changes here.

Regression coverage: the fork all-features tests and minimal-feature wide
encoding check above; Boundless's transferred capability tests, capability
admission, rev2/ENABLE, STARTTLS reset, incoming response encoding, download
and URLAUTH tests under `protocols::imap`, plus SMTP BURL tests.
