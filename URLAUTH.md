# URLAUTH extension

The `ext_urlauth` feature implements RFC 4467 GENURLAUTH, URLFETCH,
RESETKEY, URLMECH, capability admission, and RFC 5092 absolute message URLs.
URL wrappers validate percent escapes, IMAP userinfo (which has no password
slot), message identifiers, sections, ranges, expiration syntax, access scopes,
mechanisms and tokens. They preserve original octets for URLAUTH signing.
Serde cannot bypass validation. URLFETCH NIL and empty literals remain distinct.

`ImapMessageUrl::matches_trusted_server` compares BURL trusted authorities,
including the default IMAP port. It does not authorize a network connection.
Expiration, authorization identity, mailbox ownership and token validity remain
server decisions.

RFC 5524 URLAUTH=BINARY uses per-URL `UrlFetchArgument::Extended` requests
with BODY, BINARY or BODYPARTSTRUCTURE parameters. Bare URL strings retain
RFC 4467 behavior and may be mixed with extended requests in the same command.
Extended syntax requires the advertised URLAUTH=BINARY capability. Parameters
and response metadata cannot contain duplicates or combine BODY with BINARY.
Binary responses reuse NString8/literal8; body structure uses the existing
bounded recursive parser. URL failure NIL, BINARY NIL and empty literals are
distinct. The codec does not decode MIME content or change server responses.

Validation: `cargo test -p imap-types -p imap-codec --all-features`.

Response URL astrings retain literal provenance, including incremental literal
references. Atom/quoted response URLs serialize as text; literal URLs use the
usual literal representation. These observed peer values are validated again
when supplied as an outgoing command URL. This allows streamed URLFETCH and
GENURLAUTH literals without interpreting internal stream references as URLs.

RFC 5524 regressions cover mixed/empty parameter lists, capability admission,
serde validation, structured metadata, NUL-containing literal8, empty content,
both NIL forms, malformed duplicate metadata, and truncated response prefixes.
