use std::num::NonZeroU64;

use abnf_core::streaming::sp;
#[cfg(feature = "ext_condstore_qresync")]
use imap_types::extensions::condstore_qresync::{AttributeFlag, EntryTypeReq};
use nom::{
    branch::alt,
    bytes::streaming::{tag, tag_no_case},
    character::streaming::char,
    combinator::{map, map_res, opt, value},
    sequence::{delimited, preceded, tuple},
};

use crate::{core::atom, decode::IMAPResult, extensions::rev2::number63};

/// ```abnf
/// mod-sequence-valzer = "0" / mod-sequence-value
/// ```
pub(crate) fn mod_sequence_valzer(input: &[u8]) -> IMAPResult<&[u8], u64> {
    number63(input)
}

/// RFC 7162 positive unsigned 63-bit integer (1 <= n <= 9,223,372,036,854,775,807).
///
/// ```abnf
/// mod-sequence-value  = 1*DIGIT
/// ```
pub(crate) fn mod_sequence_value(input: &[u8]) -> IMAPResult<&[u8], NonZeroU64> {
    map_res(number63, NonZeroU64::try_from)(input)
}

/// ```abnf
/// search-sort-mod-seq = "(" "MODSEQ" SP mod-sequence-value ")"
/// ```
pub(crate) fn search_sort_mod_seq(input: &[u8]) -> IMAPResult<&[u8], NonZeroU64> {
    delimited(
        char('('),
        preceded(tag_no_case("MODSEQ "), mod_sequence_value),
        char(')'),
    )(input)
}

/// ```abnf
/// search-modsequence = "MODSEQ" [search-modseq-ext] SP mod-sequence-valzer
/// ```
#[allow(clippy::type_complexity)]
pub(crate) fn search_modsequence(
    input: &[u8],
) -> IMAPResult<&[u8], (Option<(AttributeFlag, EntryTypeReq)>, u64)> {
    preceded(
        tag_no_case("MODSEQ"),
        tuple((opt(search_modseq_ext), preceded(sp, mod_sequence_valzer))),
    )(input)
}

/// ```abnf
/// search-modseq-ext = SP entry-name SP entry-type-req
/// ```
pub(crate) fn search_modseq_ext(input: &[u8]) -> IMAPResult<&[u8], (AttributeFlag, EntryTypeReq)> {
    tuple((preceded(sp, entry_name), preceded(sp, entry_type_req)))(input)
}

/// ```abnf
/// entry-name = entry-flag-name
/// ```
#[inline]
pub(crate) fn entry_name(input: &[u8]) -> IMAPResult<&[u8], AttributeFlag> {
    entry_flag_name(input)
}

/// Each system or user-defined flag \<flag\> is mapped to "/flags/\<flag\>".
///
/// \<entry-flag-name\> follows the escape rules used by "quoted" string as described in
/// Section 4.3 of \[RFC3501\]; e.g., for the flag \Seen, the corresponding \<entry-name\>
/// is "/flags/\\seen", and for the flag $MDNSent, the corresponding \<entry-name\>
/// is "/flags/$mdnsent".
///
/// ```abnf
/// entry-flag-name = DQUOTE "/flags/" attr-flag DQUOTE
/// ```
pub(crate) fn entry_flag_name(input: &[u8]) -> IMAPResult<&[u8], AttributeFlag> {
    delimited(tag_no_case("\"/flags/"), attr_flag, char('"'))(input)
}

/// ```abnf
/// attr-flag = "\\Answered" /
///             "\\Flagged" /
///             "\\Deleted" /
///             "\\Seen" /
///             "\\Draft" /
///             attr-flag-keyword /
///             attr-flag-extension
///             ;; Does not include "\\Recent".
/// ```
pub(crate) fn attr_flag(input: &[u8]) -> IMAPResult<&[u8], AttributeFlag> {
    alt((
        map(preceded(tag("\\\\"), atom), AttributeFlag::system),
        map(atom, AttributeFlag::Keyword),
    ))(input)
}

// /// ```abnf
// /// attr-flag-keyword = atom
// /// ```
// #[inline]
// pub(crate) fn attr_flag_keyword(input: &[u8]) -> IMAPResult<&[u8], Atom> {
//     atom(input)
// }

// /// Future expansion.
// /// Client implementations MUST accept flag-extension flags.
// /// Server implementations MUST NOT generate flag-extension flags, except as defined by future
// /// standards or Standards Track revisions of [RFC3501].
// ///
// /// ```abnf
// /// attr-flag-extension = "\\" atom
// /// ```
// pub(crate) fn attr_flag_extension(input: &[u8]) -> IMAPResult<&[u8], Atom> {
//     preceded(tag("\\\\"), atom)(input)
// }

/// ```abnf
/// ;; Perform SEARCH operation on a private metadata item,
/// ;; shared metadata item, or both.
/// entry-type-req = entry-type-resp / "all"
///
/// ;; Metadata item type.
/// entry-type-resp = "priv" / "shared"
/// ```
pub(crate) fn entry_type_req(input: &[u8]) -> IMAPResult<&[u8], EntryTypeReq> {
    alt((
        value(EntryTypeReq::Private, tag_no_case("priv")),
        value(EntryTypeReq::Shared, tag_no_case("shared")),
        value(EntryTypeReq::All, tag_no_case("all")),
    ))(input)
}

#[cfg(test)]
mod tests {
    use crate::response::resp_text;

    #[test]
    fn modseq_uses_rfc7162_positive_63_bit_range() {
        use crate::{CommandCodec, ResponseCodec, decode::Decoder, encode::Encoder};
        for value in [
            "0",
            "1",
            "9223372036854775807",
            "9223372036854775808",
            "18446744073709551615",
            "18446744073709551616",
        ] {
            let in_range = value.parse::<u64>().is_ok_and(|v| v <= i64::MAX as u64);
            for (template, zero_allowed) in [
                ("A SEARCH MODSEQ {}\r\n", true),
                ("A STORE 1 (UNCHANGEDSINCE {}) +FLAGS (\\Seen)\r\n", true),
                ("A FETCH 1 FLAGS (CHANGEDSINCE {})\r\n", false),
                ("A SELECT inbox (QRESYNC (42 {}))\r\n", false),
            ] {
                let wire = template.replace("{}", value);
                assert_eq!(
                    CommandCodec::default().decode(wire.as_bytes()).is_ok(),
                    in_range && (zero_allowed || value != "0"),
                    "{wire}"
                );
            }
            let code = format!("HIGHESTMODSEQ {value}]");
            assert_eq!(
                crate::response::resp_text_code(code.as_bytes()).is_ok(),
                in_range && value != "0",
                "{code}"
            );
            for (template, zero_allowed) in [
                ("* ESEARCH MODSEQ {}\r\n", false),
                ("* SEARCH 1 (MODSEQ {})\r\n", false),
                ("* 1 FETCH (MODSEQ ({}))\r\n", false),
                ("* STATUS INBOX (HIGHESTMODSEQ {})\r\n", true),
            ] {
                let wire = template.replace("{}", value);
                let decoded = ResponseCodec::default().decode(wire.as_bytes());
                assert_eq!(
                    decoded.is_ok(),
                    in_range && (zero_allowed || value != "0"),
                    "{wire}"
                );
                if let Ok((_, response)) = decoded {
                    assert_eq!(
                        ResponseCodec::default().encode(&response).dump(),
                        wire.as_bytes()
                    );
                }
            }
        }
    }
    #[test]
    fn test_condstore_qresync_codes() {
        assert!(resp_text(b"[MODIFIED 7,9] Conditional STORE failed\r\n").is_ok());
        assert!(
            resp_text(b"[NOMODSEQ] Sorry, this mailbox format doesn't support modsequences\r\n")
                .is_ok()
        );
        assert!(resp_text(b"[HIGHESTMODSEQ 715194045007] Highest\r\n").is_ok());
    }
}
