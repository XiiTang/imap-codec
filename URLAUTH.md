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
server decisions. This does not implement URLAUTH=BINARY (RFC 5524).

Validation: `cargo test -p imap-types -p imap-codec --all-features`.
