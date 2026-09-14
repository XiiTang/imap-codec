//! RFC 9051 / RFC 4731 / RFC 5182 / RFC 5258 syntax, owned by the codec.
use crate::{
    core::{astring, atom, charset},
    decode::{IMAPErrorKind, IMAPParseError, IMAPResult},
    encode::{EncodeContext, EncodeIntoContext, utils::join_serializable},
    mailbox::{list_mailbox, mailbox, mailbox_list},
    search::search_key,
    sequence::sequence_set,
    status::status_att,
};
use abnf_core::streaming::sp;
use imap_types::{
    command::CommandBody,
    core::{AString, Atom, Charset, QuotedChar, Vec1},
    flag::FlagNameAttribute,
    mailbox::{ListMailbox, Mailbox},
    response::Data,
    rev2::*,
    search::SearchKey,
};
use nom::{
    branch::alt,
    bytes::streaming::{tag, tag_no_case},
    combinator::{map, map_res, opt, value, verify},
    multi::{separated_list0, separated_list1},
    sequence::{delimited, preceded, separated_pair, tuple},
};
use std::io::Write;

pub(crate) fn number63(input: &[u8]) -> IMAPResult<&[u8], u64> {
    verify(crate::core::number64, |n| *n <= i64::MAX as u64)(input)
}
pub(crate) fn nz_number63(input: &[u8]) -> IMAPResult<&[u8], std::num::NonZeroU64> {
    map_res(number63, std::num::NonZeroU64::try_from)(input)
}
pub(crate) fn message_set(input: &[u8]) -> IMAPResult<&[u8], MessageSet> {
    alt((
        value(MessageSet::SearchResult, tag(b"$")),
        map(sequence_set, MessageSet::SequenceSet),
    ))(input)
}
impl EncodeIntoContext for MessageSet {
    fn encode_ctx(&self, ctx: &mut EncodeContext) -> std::io::Result<()> {
        match self {
            Self::SearchResult => ctx.write_all(b"$"),
            Self::SequenceSet(s) => s.encode_ctx(ctx),
        }
    }
}
fn label(input: &[u8]) -> IMAPResult<&[u8], Atom> {
    verify(atom, |s: &Atom| {
        let b = s.as_ref().as_bytes();
        let first = |c: u8| c.is_ascii_alphabetic() || b"-_.".contains(&c);
        first(b[0])
            && b[1..]
                .iter()
                .all(|&c| first(c) || c.is_ascii_digit() || c == b':')
    })(input)
}
fn component(input: &[u8], depth: usize) -> IMAPResult<&[u8], ExtensionComponent> {
    if depth == 0 {
        return Err(nom::Err::Failure(IMAPParseError {
            input,
            kind: IMAPErrorKind::RecursionLimitExceeded,
        }));
    }
    alt((
        map(
            delimited(
                tag(b"("),
                separated_list0(sp, |i| component(i, depth - 1)),
                tag(b")"),
            ),
            ExtensionComponent::List,
        ),
        map(astring, ExtensionComponent::String),
    ))(input)
}
fn extension_value(input: &[u8]) -> IMAPResult<&[u8], ExtensionValue> {
    alt((
        map(
            delimited(
                tag(b"("),
                separated_list0(sp, |i| component(i, 16)),
                tag(b")"),
            ),
            ExtensionValue::List,
        ),
        map(
            verify(atom, |a: &Atom| {
                let bytes = a.as_ref().as_bytes();
                if bytes.iter().all(u8::is_ascii_digit) {
                    a.as_ref()
                        .parse::<u64>()
                        .is_ok_and(|v| v <= i64::MAX as u64)
                } else {
                    imap_types::sequence::SequenceSet::try_from(a.as_ref()).is_ok()
                }
            }),
            ExtensionValue::Simple,
        ),
    ))(input)
}
impl EncodeIntoContext for ExtensionComponent<'_> {
    fn encode_ctx(&self, ctx: &mut EncodeContext) -> std::io::Result<()> {
        match self {
            Self::String(s) => s.encode_ctx(ctx),
            Self::List(v) => {
                ctx.write_all(b"(")?;
                join_serializable(v, b" ", ctx)?;
                ctx.write_all(b")")
            }
        }
    }
}
impl EncodeIntoContext for ExtensionValue<'_> {
    fn encode_ctx(&self, ctx: &mut EncodeContext) -> std::io::Result<()> {
        match self {
            Self::Simple(s) => s.encode_ctx(ctx),
            Self::List(v) => {
                ctx.write_all(b"(")?;
                join_serializable(v, b" ", ctx)?;
                ctx.write_all(b")")
            }
        }
    }
}
fn search_return(input: &[u8]) -> IMAPResult<&[u8], SearchReturn> {
    map(
        separated_pair(
            label,
            nom::combinator::success(()),
            opt(preceded(sp, extension_value)),
        ),
        |(name, parameters)| match name.as_ref().to_ascii_uppercase().as_str() {
            "MIN" if parameters.is_none() => SearchReturn::Min,
            "MAX" if parameters.is_none() => SearchReturn::Max,
            "ALL" if parameters.is_none() => SearchReturn::All,
            "COUNT" if parameters.is_none() => SearchReturn::Count,
            "SAVE" if parameters.is_none() => SearchReturn::Save,
            _ => SearchReturn::Extension { name, parameters },
        },
    )(input)
}
pub(crate) fn extended_search(input: &[u8]) -> IMAPResult<&[u8], CommandBody> {
    let (rest, (_, returns, charset, _, criteria)) = tuple((
        tag_no_case(b"SEARCH RETURN "),
        delimited(tag(b"("), separated_list0(sp, search_return), tag(b")")),
        opt(preceded(tag_no_case(b" CHARSET "), charset)),
        sp,
        map(separated_list1(sp, search_key(9)), Vec1::unvalidated),
    ))(input)?;
    Ok((
        rest,
        CommandBody::SearchExtended {
            returns,
            charset,
            criteria,
            uid: false,
        },
    ))
}
impl EncodeIntoContext for SearchReturn<'_> {
    fn encode_ctx(&self, ctx: &mut EncodeContext) -> std::io::Result<()> {
        match self {
            Self::Min => ctx.write_all(b"MIN"),
            Self::Max => ctx.write_all(b"MAX"),
            Self::All => ctx.write_all(b"ALL"),
            Self::Count => ctx.write_all(b"COUNT"),
            Self::Save => ctx.write_all(b"SAVE"),
            Self::Extension { name, parameters } => {
                name.encode_ctx(ctx)?;
                if let Some(p) = parameters {
                    ctx.write_all(b" ")?;
                    p.encode_ctx(ctx)?;
                }
                Ok(())
            }
        }
    }
}
pub(crate) fn encode_search(
    returns: &[SearchReturn],
    charset: &Option<Charset>,
    criteria: &Vec1<SearchKey>,
    uid: bool,
    ctx: &mut EncodeContext,
) -> std::io::Result<()> {
    if uid {
        ctx.write_all(b"UID ")?;
    }
    ctx.write_all(b"SEARCH RETURN (")?;
    join_serializable(returns, b" ", ctx)?;
    ctx.write_all(b")")?;
    if let Some(c) = charset {
        ctx.write_all(b" CHARSET ")?;
        c.encode_ctx(ctx)?;
    }
    ctx.write_all(b" ")?;
    join_serializable(criteria.as_ref(), b" ", ctx)
}
fn search_data(input: &[u8]) -> IMAPResult<&[u8], SearchReturnData> {
    verify(
        map(
            separated_pair(label, sp, extension_value),
            |(name, value)| SearchReturnData { name, value },
        ),
        |d: &SearchReturnData| match d.name.as_ref().to_ascii_uppercase().as_str() {
            "MIN" | "MAX" => {
                matches!(&d.value,ExtensionValue::Simple(v) if v.as_ref().parse::<u32>().is_ok_and(|n|n>0))
            }
            "COUNT" => {
                matches!(&d.value,ExtensionValue::Simple(v) if v.as_ref().parse::<u32>().is_ok())
            }
            "ALL" => {
                matches!(&d.value,ExtensionValue::Simple(v) if !v.as_ref().contains(['*','$']) && imap_types::sequence::SequenceSet::try_from(v.as_ref()).is_ok())
            }
            "MODSEQ" => {
                matches!(&d.value,ExtensionValue::Simple(v) if v.as_ref().parse::<u64>().is_ok_and(|n|n>0))
            }
            _ => true,
        },
    )(input)
}
pub(crate) fn esearch(input: &[u8]) -> IMAPResult<&[u8], Data> {
    let (rest, (_, tag, uid, items)) = tuple((
        tag_no_case(b"ESEARCH"),
        opt(delimited(tag_no_case(b" (TAG "), astring, tag(b")"))),
        map(opt(tag_no_case(b" UID")), |v| v.is_some()),
        nom::multi::many0(preceded(sp, search_data)),
    ))(input)?;
    Ok((rest, Data::ESearch { tag, uid, items }))
}
pub(crate) fn encode_esearch(
    tag: &Option<AString>,
    uid: bool,
    items: &[SearchReturnData],
    ctx: &mut EncodeContext,
) -> std::io::Result<()> {
    ctx.write_all(b"* ESEARCH")?;
    if let Some(t) = tag {
        ctx.write_all(b" (TAG ")?;
        t.encode_ctx(ctx)?;
        ctx.write_all(b")")?;
    }
    if uid {
        ctx.write_all(b" UID")?;
    }
    for item in items {
        ctx.write_all(b" ")?;
        item.name.encode_ctx(ctx)?;
        ctx.write_all(b" ")?;
        item.value.encode_ctx(ctx)?;
    }
    Ok(())
}
fn list_return(input: &[u8]) -> IMAPResult<&[u8], ListReturn> {
    alt((
        map(
            preceded(
                tag_no_case(b"STATUS "),
                delimited(
                    tag(b"("),
                    map(separated_list1(sp, status_att), Vec1::unvalidated),
                    tag(b")"),
                ),
            ),
            ListReturn::Status,
        ),
        map(
            tuple((label, opt(preceded(sp, extension_value)))),
            |(name, parameters)| match name.as_ref().to_ascii_uppercase().as_str() {
                "SUBSCRIBED" if parameters.is_none() => ListReturn::Subscribed,
                "CHILDREN" if parameters.is_none() => ListReturn::Children,
                "SPECIAL-USE" if parameters.is_none() => ListReturn::SpecialUse,
                _ => ListReturn::Extension { name, parameters },
            },
        ),
    ))(input)
}
pub(crate) fn list(input: &[u8]) -> IMAPResult<&[u8], CommandBody> {
    let (rest, (_, selection, reference, _, patterns, returns)) = tuple((
        tag_no_case(b"LIST "),
        opt(terminated_selection),
        mailbox,
        sp,
        alt((
            map(
                delimited(tag(b"("), separated_list1(sp, list_mailbox), tag(b")")),
                |p| (p, true),
            ),
            map(list_mailbox, |p| (vec![p], false)),
        )),
        opt(preceded(
            tag_no_case(b" RETURN "),
            delimited(tag(b"("), separated_list0(sp, list_return), tag(b")")),
        )),
    ))(input)?;
    let (mut patterns, multiple) = patterns;
    if selection.is_none() && !multiple && returns.is_none() {
        return Ok((
            rest,
            CommandBody::List {
                reference,
                mailbox_wildcard: patterns.remove(0),
            },
        ));
    }
    let selection = selection.unwrap_or_default();
    if selection
        .iter()
        .any(|a| a.as_ref().eq_ignore_ascii_case("RECURSIVEMATCH"))
        && !selection.iter().any(|a| {
            !a.as_ref().eq_ignore_ascii_case("RECURSIVEMATCH")
                && !a.as_ref().eq_ignore_ascii_case("REMOTE")
        })
    {
        return Err(nom::Err::Failure(IMAPParseError {
            input,
            kind: IMAPErrorKind::Nom(nom::error::ErrorKind::Verify),
        }));
    }
    Ok((
        rest,
        CommandBody::ListExtended {
            selection,
            reference,
            patterns: Vec1::unvalidated(patterns),
            returns,
        },
    ))
}
fn terminated_selection(input: &[u8]) -> IMAPResult<&[u8], Vec<Atom>> {
    nom::sequence::terminated(
        delimited(tag(b"("), separated_list0(sp, label), tag(b")")),
        sp,
    )(input)
}
impl EncodeIntoContext for ListReturn<'_> {
    fn encode_ctx(&self, ctx: &mut EncodeContext) -> std::io::Result<()> {
        match self {
            Self::Subscribed => ctx.write_all(b"SUBSCRIBED"),
            Self::Children => ctx.write_all(b"CHILDREN"),
            Self::SpecialUse => ctx.write_all(b"SPECIAL-USE"),
            Self::Status(names) => {
                ctx.write_all(b"STATUS (")?;
                join_serializable(names.as_ref(), b" ", ctx)?;
                ctx.write_all(b")")
            }
            Self::Extension { name, parameters } => {
                name.encode_ctx(ctx)?;
                if let Some(p) = parameters {
                    ctx.write_all(b" ")?;
                    p.encode_ctx(ctx)?;
                }
                Ok(())
            }
        }
    }
}
pub(crate) fn encode_list(
    selection: &[Atom],
    reference: &Mailbox,
    patterns: &Vec1<ListMailbox>,
    returns: &Option<Vec<ListReturn>>,
    ctx: &mut EncodeContext,
) -> std::io::Result<()> {
    ctx.write_all(b"LIST (")?;
    join_serializable(selection, b" ", ctx)?;
    ctx.write_all(b") ")?;
    reference.encode_ctx(ctx)?;
    ctx.write_all(b" (")?;
    join_serializable(patterns.as_ref(), b" ", ctx)?;
    ctx.write_all(b")")?;
    if let Some(returns) = returns {
        ctx.write_all(b" RETURN (")?;
        join_serializable(returns, b" ", ctx)?;
        ctx.write_all(b")")?;
    }
    Ok(())
}
pub(crate) fn list_data(input: &[u8]) -> IMAPResult<&[u8], Data> {
    let (rest, (items, delimiter, mailbox)) = preceded(tag_no_case(b"LIST "), mailbox_list)(input)?;
    let (rest, extensions) = preceded(
        sp,
        delimited(
            tag(b"("),
            separated_list0(
                sp,
                map(
                    separated_pair(astring, sp, extension_value),
                    |(tag, value)| ListExtension { tag, value },
                ),
            ),
            tag(b")"),
        ),
    )(rest)?;
    Ok((
        rest,
        Data::ListExtended {
            items: items.unwrap_or_default(),
            delimiter,
            mailbox,
            extensions,
        },
    ))
}
pub(crate) fn encode_list_data(
    items: &[FlagNameAttribute],
    delimiter: &Option<QuotedChar>,
    mailbox: &Mailbox,
    extensions: &[ListExtension],
    ctx: &mut EncodeContext,
) -> std::io::Result<()> {
    ctx.write_all(b"* LIST (")?;
    join_serializable(items, b" ", ctx)?;
    ctx.write_all(b") ")?;
    if let Some(d) = delimiter {
        ctx.write_all(b"\"")?;
        d.encode_ctx(ctx)?;
        ctx.write_all(b"\"")?;
    } else {
        ctx.write_all(b"NIL")?;
    }
    ctx.write_all(b" ")?;
    mailbox.encode_ctx(ctx)?;
    ctx.write_all(b" (")?;
    for (index, e) in extensions.iter().enumerate() {
        if index > 0 {
            ctx.write_all(b" ")?;
        }
        e.tag.encode_ctx(ctx)?;
        ctx.write_all(b" ")?;
        e.value.encode_ctx(ctx)?;
    }
    ctx.write_all(b")")
}

#[cfg(test)]
mod tests {
    use crate::{CommandCodec, ResponseCodec, decode::Decoder, encode::Encoder};
    #[test]
    fn rev2_commands_survive_every_fragment_boundary_and_roundtrip() {
        for bytes in [
            b"A UID SEARCH RETURN (MIN MAX ALL COUNT SAVE) UID $ LARGER 4294967297\r\n".as_slice(),
            b"A SEARCH RETURN () ALL\r\n",
            b"A SEARCH RETURN (SAVE) CHARSET UTF-8 (OR $ 1:4) TEXT {2}\r\nhi\r\n",
            b"A FETCH $ (UID BODY.PEEK[]<4294967296.4294967297>)\r\n",
            b"A UID STORE $ +FLAGS.SILENT (\\Seen)\r\n",
            b"A COPY $ archive\r\n",b"A UID MOVE $ archive\r\n",b"A UID EXPUNGE $\r\n",
            b"A LIST (SUBSCRIBED RECURSIVEMATCH) \"\" (\"*\" \"Archive/%\") RETURN (SUBSCRIBED CHILDREN STATUS (MESSAGES SIZE DELETED))\r\n",
            b"A ENABLE IMAP4rev2 QRESYNC\r\n",
            b"A UID SEARCH RETURN (COUNT VENDOR-OPTION (\"hi\" (two))) ALL\r\n",
        ] {
            let (_, decoded)=CommandCodec::default().decode(bytes).unwrap_or_else(|e|panic!("{}: {e:?}",String::from_utf8_lossy(bytes)));
            let canonical=CommandCodec::default().encode(&decoded).dump();
            assert_eq!(CommandCodec::default().decode(&canonical).unwrap().1,decoded);
            for split in 0..bytes.len(){assert!(CommandCodec::default().decode(&bytes[..split]).is_err(),"premature decode at {split}");}
        }
    }
    #[test]
    fn rev2_responses_preserve_extensions_and_wide_sizes() {
        for bytes in [
            b"* ESEARCH (TAG \"A\") UID MIN 2 MAX 42 ALL 2,10:20,42 COUNT 13 MODSEQ 5150\r\n".as_slice(),
            b"* ESEARCH\r\n",b"* ESEARCH COUNT 0\r\n",
            b"* ESEARCH VENDOR (\"hello\" (one two))\r\n",
            b"* LIST (\\Subscribed \\HasChildren) \"/\" archive (\"CHILDINFO\" (\"SUBSCRIBED\") \"OLDNAME\" (\"old archive\"))\r\n",
            b"* LIST () NIL inbox ()\r\n",
            b"* STATUS inbox (MESSAGES 3 SIZE 4294967297 DELETED 1)\r\n",
            b"* 1 FETCH (RFC822.SIZE 4294967297 BINARY.SIZE[1] 4294967298 BODY[]<4294967296> {2}\r\nhi)\r\n",
            b"* CAPABILITY IMAP4rev2\r\n",b"A OK \r\n",b"A OK [CLOSED]\r\n",
            "A OK 完成\r\n".as_bytes(),
        ] {
            let (_, decoded)=ResponseCodec::default().decode(bytes).unwrap_or_else(|e|panic!("{}: {e:?}",String::from_utf8_lossy(bytes)));
            let canonical=ResponseCodec::default().encode(&decoded).dump();
            assert_eq!(ResponseCodec::default().decode(&canonical).unwrap().1,decoded);
            for split in 0..bytes.len(){assert!(ResponseCodec::default().decode(&bytes[..split]).is_err(),"premature decode at {split}");}
        }
    }
    #[test]
    fn rejects_invalid_sets_bounds_options_and_utf8() {
        for bytes in [
            b"A FETCH $,1 UID\r\n".as_slice(),
            b"A FETCH 1:$ UID\r\n",
            b"A LIST (RECURSIVEMATCH) \"\" *\r\n",
            b"A SEARCH RETURN (ALL) LARGER 9223372036854775808\r\n",
            b"A FETCH $ BODY[]<1.0>\r\n",
        ] {
            assert!(
                CommandCodec::default().decode(bytes).is_err(),
                "{}",
                String::from_utf8_lossy(bytes)
            );
        }
        for bytes in [
            b"* ESEARCH ALL $\r\n".as_slice(),
            b"* ESEARCH ALL 1:*\r\n",
            b"* ESEARCH MIN 0\r\n",
            b"* ESEARCH COUNT 4294967296\r\n",
            b"* STATUS inbox (SIZE 9223372036854775808)\r\n",
            b"A OK \xff\r\n",
        ] {
            assert!(
                ResponseCodec::default().decode(bytes).is_err(),
                "{}",
                String::from_utf8_lossy(bytes)
            );
        }
    }
}
