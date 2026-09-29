//! URLAUTH and extended URLFETCH grammar (RFC 4467 / RFC 5524).
use crate::{
    body::body,
    core::{astring, atom, nstring},
    decode::IMAPResult,
    encode::{EncodeContext, EncodeIntoContext},
    extensions::binary::literal8,
    mailbox::mailbox,
};
use abnf_core::streaming::sp;
use imap_types::{
    command::CommandBody,
    core::{AString, NString8, Vec1},
    extensions::urlauth::*,
    response::{Code, Data},
};
use nom::{
    branch::alt,
    bytes::streaming::{tag, tag_no_case},
    combinator::{map, map_opt, opt},
    multi::{many0, separated_list1},
    sequence::{delimited, preceded, separated_pair, tuple},
};
use std::io::Write;

fn url(input: &[u8]) -> IMAPResult<&[u8], ImapMessageUrl> {
    map_opt(astring, |s| {
        std::str::from_utf8(s.as_ref())
            .map_err(|_| InvalidUrl)
            .and_then(ImapMessageUrl::try_from)
            .ok()
    })(input)
}
fn rump(input: &[u8]) -> IMAPResult<&[u8], UrlAuthRump> {
    map_opt(astring, |s| {
        std::str::from_utf8(s.as_ref())
            .map_err(|_| InvalidUrl)
            .and_then(UrlAuthRump::try_from)
            .ok()
    })(input)
}
fn response_url(input: &[u8]) -> IMAPResult<&[u8], UrlResponse> {
    map(astring, UrlResponse)(input)
}
fn mechanism(input: &[u8]) -> IMAPResult<&[u8], UrlAuthMechanism> {
    map_opt(atom, |s| UrlAuthMechanism::try_from(s.as_ref()).ok())(input)
}
fn fetch_parameter(input: &[u8]) -> IMAPResult<&[u8], UrlFetchParameter> {
    map_opt(atom, |name| {
        match name.as_ref().to_ascii_uppercase().as_str() {
            "BODY" => Some(UrlFetchParameter::Body),
            "BINARY" => Some(UrlFetchParameter::Binary),
            "BODYPARTSTRUCTURE" => Some(UrlFetchParameter::BodyPartStructure),
            _ => None,
        }
    })(input)
}
fn fetch_argument(input: &[u8]) -> IMAPResult<&[u8], UrlFetchArgument> {
    alt((
        map_opt(
            delimited(
                tag("("),
                tuple((url, many0(preceded(sp, fetch_parameter)))),
                tag(")"),
            ),
            |(url, parameters)| {
                UrlFetchParameters::try_from(parameters)
                    .ok()
                    .map(|parameters| {
                        UrlFetchArgument::Extended(UrlFetchRequest { url, parameters })
                    })
            },
        ),
        map(url, UrlFetchArgument::Simple),
    ))(input)
}
fn fetch_metadata(input: &[u8]) -> IMAPResult<&[u8], UrlFetchMetadata> {
    delimited(
        tag("("),
        alt((
            map(
                preceded(tag_no_case("BODY "), nstring),
                UrlFetchMetadata::Body,
            ),
            map(
                preceded(
                    tag_no_case("BINARY "),
                    alt((
                        map(nstring, NString8::NString),
                        map(literal8, NString8::Literal8),
                    )),
                ),
                UrlFetchMetadata::Binary,
            ),
            map(
                preceded(tag_no_case("BODYPARTSTRUCTURE "), body(8)),
                |body| UrlFetchMetadata::BodyPartStructure(Box::new(body)),
            ),
        )),
        tag(")"),
    )(input)
}
fn fetch_data(input: &[u8]) -> IMAPResult<&[u8], UrlFetchData> {
    alt((
        map_opt(separated_list1(sp, fetch_metadata), |metadata| {
            UrlFetchMetadataList::try_from(Vec1::unvalidated(metadata))
                .ok()
                .map(UrlFetchData::Extended)
        }),
        map(nstring, UrlFetchData::Simple),
    ))(input)
}
pub(crate) fn command(input: &[u8]) -> IMAPResult<&[u8], CommandBody> {
    alt((
        map(
            preceded(
                tag_no_case("GENURLAUTH "),
                separated_list1(sp, separated_pair(rump, sp, mechanism)),
            ),
            |items| CommandBody::GenUrlAuth {
                requests: Vec1::unvalidated(
                    items
                        .into_iter()
                        .map(|(url, mechanism)| UrlAuthRequest { url, mechanism })
                        .collect(),
                ),
            },
        ),
        map(
            preceded(
                tag_no_case("URLFETCH "),
                separated_list1(sp, fetch_argument),
            ),
            |urls| CommandBody::UrlFetch {
                urls: Vec1::unvalidated(urls),
            },
        ),
        map(
            preceded(
                tag_no_case("RESETKEY"),
                opt(preceded(
                    sp,
                    tuple((mailbox, many0(preceded(sp, mechanism)))),
                )),
            ),
            |target| CommandBody::ResetKey {
                target: target.map(|(mailbox, mechanisms)| ResetKeyTarget {
                    mailbox,
                    mechanisms,
                }),
            },
        ),
    ))(input)
}
pub(crate) fn response(input: &[u8]) -> IMAPResult<&[u8], Data> {
    alt((
        map(
            preceded(
                tag_no_case("GENURLAUTH "),
                separated_list1(sp, response_url),
            ),
            |urls| Data::GenUrlAuth {
                urls: Vec1::unvalidated(urls),
            },
        ),
        map(
            preceded(
                tag_no_case("URLFETCH "),
                separated_list1(sp, separated_pair(response_url, sp, fetch_data)),
            ),
            |items| Data::UrlFetch {
                results: Vec1::unvalidated(
                    items
                        .into_iter()
                        .map(|(url, data)| UrlFetchResult { url, data })
                        .collect(),
                ),
            },
        ),
    ))(input)
}
pub(crate) fn code(input: &[u8]) -> IMAPResult<&[u8], Code> {
    map(
        preceded(
            tag_no_case("URLMECH "),
            separated_list1(sp, map_opt(atom, |s| UrlMech::try_from(s.as_ref()).ok())),
        ),
        |items| Code::UrlMech(Vec1::unvalidated(items)),
    )(input)
}
macro_rules! encode_url {
    ($type:ty) => {
        impl EncodeIntoContext for $type {
            fn encode_ctx(&self, ctx: &mut EncodeContext) -> std::io::Result<()> {
                // Validated URI ASCII is always a valid IMAP astring.
                AString::try_from(self.as_str())
                    .expect("validated URL")
                    .encode_ctx(ctx)
            }
        }
    };
}
encode_url!(ImapMessageUrl);
encode_url!(UrlAuthUrl);
encode_url!(UrlAuthRump);
impl EncodeIntoContext for UrlAuthMechanism {
    fn encode_ctx(&self, ctx: &mut EncodeContext) -> std::io::Result<()> {
        ctx.write_all(self.as_str().as_bytes())
    }
}
impl EncodeIntoContext for UrlMech {
    fn encode_ctx(&self, ctx: &mut EncodeContext) -> std::io::Result<()> {
        ctx.write_all(self.as_str().as_bytes())
    }
}
impl EncodeIntoContext for UrlAuthRequest {
    fn encode_ctx(&self, ctx: &mut EncodeContext) -> std::io::Result<()> {
        self.url.encode_ctx(ctx)?;
        ctx.write_all(b" ")?;
        self.mechanism.encode_ctx(ctx)
    }
}
impl EncodeIntoContext for UrlResponse<'_> {
    fn encode_ctx(&self, ctx: &mut EncodeContext) -> std::io::Result<()> {
        self.0.encode_ctx(ctx)
    }
}
impl EncodeIntoContext for UrlFetchResult<'_> {
    fn encode_ctx(&self, ctx: &mut EncodeContext) -> std::io::Result<()> {
        self.url.encode_ctx(ctx)?;
        ctx.write_all(b" ")?;
        self.data.encode_ctx(ctx)
    }
}
impl EncodeIntoContext for UrlFetchArgument {
    fn encode_ctx(&self, ctx: &mut EncodeContext) -> std::io::Result<()> {
        match self {
            Self::Simple(url) => url.encode_ctx(ctx),
            Self::Extended(request) => {
                ctx.write_all(b"(")?;
                request.url.encode_ctx(ctx)?;
                for parameter in request.parameters.as_ref() {
                    ctx.write_all(b" ")?;
                    ctx.write_all(parameter.as_str().as_bytes())?;
                }
                ctx.write_all(b")")
            }
        }
    }
}
impl EncodeIntoContext for UrlFetchData<'_> {
    fn encode_ctx(&self, ctx: &mut EncodeContext) -> std::io::Result<()> {
        match self {
            Self::Simple(data) => data.encode_ctx(ctx),
            Self::Extended(metadata) => {
                for (index, item) in metadata.as_ref().iter().enumerate() {
                    if index != 0 {
                        ctx.write_all(b" ")?;
                    }
                    ctx.write_all(b"(")?;
                    ctx.write_all(item.parameter().as_str().as_bytes())?;
                    ctx.write_all(b" ")?;
                    match item {
                        UrlFetchMetadata::Body(data) => data.encode_ctx(ctx)?,
                        UrlFetchMetadata::Binary(data) => data.encode_ctx(ctx)?,
                        UrlFetchMetadata::BodyPartStructure(body) => body.encode_ctx(ctx)?,
                    }
                    ctx.write_all(b")")?;
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{CommandCodec, ResponseCodec, decode::Decoder, encode::Encoder};
    use imap_types::{
        command::CommandBody,
        response::{Data, Response},
    };
    #[test]
    fn extended_arguments_round_trip_and_require_their_capability() {
        use crate::client_capabilities::{ClientCapabilities, Version};
        let url = "imap://joe@h/INBOX/;UID=1/;SECTION=1";
        for arguments in [
            format!("({url} BINARY BODYPARTSTRUCTURE)"),
            format!("({url} BODY) {url} ({url} BODYPARTSTRUCTURE)"),
            format!("({url})"),
        ] {
            let wire = format!("A URLFETCH {arguments}\r\n");
            let (remaining, command) = CommandCodec::default().decode(wire.as_bytes()).unwrap();
            assert!(remaining.is_empty());
            assert_eq!(
                CommandCodec::default().encode(&command).dump(),
                wire.as_bytes()
            );
            for (caps, permitted) in [
                (vec!["URLAUTH"], false),
                (vec!["URLAUTH", "BINARY"], false),
                (vec!["URLAUTH", "URLAUTH=BINARY"], true),
            ] {
                let state = ClientCapabilities::new(
                    caps.into_iter().map(str::to_owned).collect(),
                    Version::Rev1,
                );
                assert_eq!(state.validate(&command.body).is_ok(), permitted);
            }
        }
        for parameters in [
            "BODY BINARY",
            "BODY BODY",
            "BINARY BINARY",
            "BODYPARTSTRUCTURE BODYPARTSTRUCTURE",
            "UNKNOWN",
        ] {
            let wire = format!("A URLFETCH ({url} {parameters})\r\n");
            assert!(
                CommandCodec::default().decode(wire.as_bytes()).is_err(),
                "{wire}"
            );
        }
    }

    #[test]
    fn extended_metadata_preserves_binary_nil_empty_and_body_structure() {
        let url = "imap://joe@h/INBOX/;UID=1/;SECTION=1";
        for metadata in [
            "(BINARY ~{3}\r\na\0b)",
            "(BINARY {0}\r\n)",
            "(BINARY NIL)",
            "(BODY \"YQBi\")",
            "(BODYPARTSTRUCTURE (\"APPLICATION\" \"OCTET-STREAM\" NIL NIL NIL \"BINARY\" 3)) (BINARY ~{3}\r\na\0b)",
            "(BODYPARTSTRUCTURE (\"IMAGE\" \"PNG\" NIL NIL NIL \"BASE64\" 4))",
        ] {
            let wire = format!("* URLFETCH {url} {metadata} {url} NIL\r\n");
            let (remaining, response) = ResponseCodec::default().decode(wire.as_bytes()).unwrap();
            assert!(remaining.is_empty());
            assert_eq!(
                ResponseCodec::default().encode(&response).dump(),
                wire.as_bytes()
            );
            for end in 0..wire.len() {
                assert!(
                    ResponseCodec::default()
                        .decode(&wire.as_bytes()[..end])
                        .is_err(),
                    "truncated at {end}"
                );
            }
        }
        for metadata in [
            "(BODY NIL) (BODY NIL)",
            "(BINARY NIL) (BODY NIL)",
            "(BINARY {3}\r\na\0b)",
            "(BODY ~{3}\r\na\0b)",
        ] {
            let wire = format!("* URLFETCH {url} {metadata}\r\n");
            assert!(
                ResponseCodec::default().decode(wire.as_bytes()).is_err(),
                "{wire:?}"
            );
        }
    }

    #[test]
    fn commands_and_literals_round_trip() {
        for input in [
            "A GENURLAUTH imap://joe@h/INBOX/;UID=1;URLAUTH=submit+joe INTERNAL\r\n",
            "A GENURLAUTH imap://joe@h/INBOX/;UID=1;URLAUTH=anonymous INTERNAL imap://joe@h/INBOX/;UID=2;URLAUTH=anonymous INTERNAL\r\n",
            "A URLFETCH imap://joe@h/INBOX/;UID=1 imap://joe@h/INBOX/;UID=2\r\n",
            "A RESETKEY\r\n",
            "A RESETKEY INBOX INTERNAL\r\n",
        ] {
            let (rest, command) = CommandCodec::default().decode(input.as_bytes()).unwrap();
            assert!(rest.is_empty());
            let encoded = CommandCodec::default().encode(&command).dump();
            let (rest, decoded) = CommandCodec::default().decode(&encoded).unwrap();
            assert!(rest.is_empty());
            assert_eq!(decoded, command);
        }
        let raw =
            b"A GENURLAUTH {52+}\r\nimap://joe@h/INBOX/;UID=1;URLAUTH=submit+joe INTERNAL\r\n";
        assert!(CommandCodec::default().decode(raw).is_err()); // incorrect literal length
        for input in [
            "A GENURLAUTH imap://h INTERNAL\r\n",
            "A URLFETCH imap://h/INBOX/;UID=1 LAST\r\n",
            "A RESETKEY INBOX INTERNAL:bad\r\n",
        ] {
            assert!(CommandCodec::default().decode(input.as_bytes()).is_err());
        }
        let (_, reset) = CommandCodec::default()
            .decode(b"A RESETKEY INBOX\r\n")
            .unwrap();
        assert!(matches!(
            reset.body,
            CommandBody::ResetKey { target: Some(_) }
        ));
    }
    #[test]
    fn url_astring_literals_preserve_provenance() {
        let url = "imap://joe@h/INBOX/;UID=1;URLAUTH=submit+joe:INTERNAL:0123456789abcdef0123456789abcdef01234567";
        for wire in [
            format!("* GENURLAUTH {{{}}}\r\n{url}\r\n", url.len()),
            format!("* URLFETCH {{{}}}\r\n{url} {{3}}\r\nabc\r\n", url.len()),
        ] {
            let (rest, response) = ResponseCodec::default().decode(wire.as_bytes()).unwrap();
            assert!(rest.is_empty());
            assert_eq!(
                ResponseCodec::default().encode(&response).dump(),
                wire.as_bytes()
            );
        }
    }
    #[test]
    fn response_nil_empty_and_literal_are_distinct() {
        let wire = b"* URLFETCH imap://joe@h/INBOX/;UID=1 NIL imap://joe@h/INBOX/;UID=2 \"\" imap://joe@h/INBOX/;UID=3 {3}\r\na\r\n\r\n";
        let (rest, response) = ResponseCodec::default().decode(wire).unwrap();
        assert!(rest.is_empty());
        assert!(
            matches!(&response, Response::Data(Data::UrlFetch { results }) if results.as_ref().len() == 3)
        );
        assert_eq!(ResponseCodec::default().encode(&response).dump(), wire);
        for wire in [
            "* GENURLAUTH imap://joe@h/INBOX/;UID=1;URLAUTH=submit+joe:INTERNAL:0123456789abcdef0123456789abcdef01234567\r\n",
            "A OK [URLMECH INTERNAL EXAMPLE=YQ==] done\r\n",
        ] {
            let (rest, response) = ResponseCodec::default().decode(wire.as_bytes()).unwrap();
            assert!(rest.is_empty());
            assert_eq!(
                ResponseCodec::default().encode(&response).dump(),
                wire.as_bytes()
            );
        }
    }
}
