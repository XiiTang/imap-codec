//! IMAP message URLs (RFC 5092) and URLAUTH (RFC 4467).
//!
//! URL text is validated without decoding or normalizing it: URLAUTH tokens cover
//! the original octets, including the spelling of percent escapes.
use crate::mailbox::Mailbox;
mod fetch;
use bounded_static_derive::ToStatic;
pub use fetch::*;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid IMAP message URL")]
pub struct InvalidUrl;

#[derive(Clone, Debug, Eq, PartialEq, Hash, ToStatic)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(try_from = "String", into = "String")
)]
pub struct ImapMessageUrl(String);

#[derive(Clone, Debug, Eq, PartialEq, Hash, ToStatic)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(try_from = "String", into = "String")
)]
pub struct UrlAuthRump(String);

#[derive(Clone, Debug, Eq, PartialEq, Hash, ToStatic)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(try_from = "String", into = "String")
)]
pub struct UrlAuthUrl(String);

#[derive(Clone, Debug, Eq, PartialEq, Hash, ToStatic)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(try_from = "String", into = "String")
)]
pub struct UrlAuthMechanism(String);

macro_rules! validated_string {
    ($type:ident, $validate:expr) => {
        impl TryFrom<String> for $type {
            type Error = InvalidUrl;
            fn try_from(s: String) -> Result<Self, Self::Error> {
                ($validate)(&s)?;
                Ok(Self(s))
            }
        }
        impl TryFrom<&str> for $type {
            type Error = InvalidUrl;
            fn try_from(s: &str) -> Result<Self, Self::Error> {
                Self::try_from(s.to_owned())
            }
        }
        impl From<$type> for String {
            fn from(s: $type) -> String {
                s.0
            }
        }
        impl $type {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
        #[cfg(feature = "arbitrary")]
        impl<'a> arbitrary::Arbitrary<'a> for $type {
            fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
                Self::try_from(<String as arbitrary::Arbitrary>::arbitrary(u)?)
                    .map_err(|_| arbitrary::Error::IncorrectFormat)
            }
        }
    };
}
validated_string!(ImapMessageUrl, |s: &str| parse(s, false).map(|_| ()));
validated_string!(UrlAuthRump, |s: &str| parse(s, true)
    .and_then(|auth| if auth { Ok(()) } else { Err(InvalidUrl) }));
validated_string!(UrlAuthUrl, |s: &str| parse(s, false)
    .and_then(|auth| if auth { Ok(()) } else { Err(InvalidUrl) }));
validated_string!(UrlAuthMechanism, |s: &str| ensure(
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-.".contains(&b))
));

impl ImapMessageUrl {
    pub fn has_urlauth(&self) -> bool {
        split_ci(&self.0, ";URLAUTH=").is_some()
    }
    /// Whether a BURL trusted-server advertisement names this authority.
    /// Userinfo, paths, queries, and fragments are not authority advertisements.
    pub fn matches_trusted_server(&self, advertised: &str) -> bool {
        let Some(rest) = advertised
            .get(..7)
            .filter(|s| s.eq_ignore_ascii_case("imap://"))
            .map(|_| &advertised[7..])
        else {
            return false;
        };
        if rest.bytes().any(|b| b"/@?#".contains(&b)) {
            return false;
        }
        let Ok(server) = server(rest) else {
            return false;
        };
        let authority = self.0[7..].split('/').next().unwrap();
        let target = authority
            .rsplit_once('@')
            .map_or(authority, |(_, host)| host);
        server
            == match self::server(target) {
                Ok(s) => s,
                Err(_) => return false,
            }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, ToStatic)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(deny_unknown_fields)
)]
pub struct UrlAuthRequest {
    pub url: UrlAuthRump,
    pub mechanism: UrlAuthMechanism,
}

/// A URL as a server sent it in a GENURLAUTH or URLFETCH response, kept as its
/// astring. A client relays these URLs rather than interpreting them, so a URL
/// the validator refuses does not make the whole response undecodable; it is
/// validated as an `ImapMessageUrl` when supplied in a command.
#[derive(Clone, Debug, Eq, PartialEq, Hash, ToStatic)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct UrlResponse<'a>(pub crate::core::AString<'a>);

/// No mailbox means all keys. Mechanisms may only be specified with a mailbox.
#[derive(Clone, Debug, Eq, PartialEq, Hash, ToStatic)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(deny_unknown_fields)
)]
pub struct ResetKeyTarget<'a> {
    pub mailbox: Mailbox<'a>,
    pub mechanisms: Vec<UrlAuthMechanism>,
}

/// An advertised URLAUTH mechanism and its optional base64 parameter.
#[derive(Clone, Debug, Eq, PartialEq, Hash, ToStatic)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(try_from = "String", into = "String")
)]
pub struct UrlMech(String);
validated_string!(UrlMech, |s: &str| {
    let (name, parameter) = s.split_once('=').map_or((s, None), |(n, p)| (n, Some(p)));
    UrlAuthMechanism::try_from(name)?;
    if let Some(parameter) = parameter {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(parameter)
            .map_err(|_| InvalidUrl)?;
    }
    Ok(())
});

fn ensure(valid: bool) -> Result<(), InvalidUrl> {
    if valid { Ok(()) } else { Err(InvalidUrl) }
}
fn split_ci<'a>(s: &'a str, needle: &str) -> Option<(&'a str, &'a str)> {
    s.as_bytes()
        .windows(needle.len())
        .position(|w| w.eq_ignore_ascii_case(needle.as_bytes()))
        .map(|i| (&s[..i], &s[i + needle.len()..]))
}
fn encoded(s: &str, extra: &[u8]) -> Result<(), InvalidUrl> {
    ensure(!s.is_empty())?;
    let mut bytes = s.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            ensure(
                bytes.next().is_some_and(|x| x.is_ascii_hexdigit())
                    && bytes.next().is_some_and(|x| x.is_ascii_hexdigit()),
            )?;
        } else {
            ensure(
                b.is_ascii_alphanumeric() || b"-._~!$'()*+,".contains(&b) || extra.contains(&b),
            )?;
        }
    }
    Ok(())
}
fn number(s: &str, nonzero: bool) -> Result<(), InvalidUrl> {
    ensure(!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))?;
    ensure(!nonzero || !s.starts_with('0'))?;
    s.parse::<u32>().map_err(|_| InvalidUrl)?;
    Ok(())
}
fn server(s: &str) -> Result<(url::Host<String>, u16), InvalidUrl> {
    let (host, port) = if s.starts_with('[') {
        let end = s.find(']').ok_or(InvalidUrl)?;
        (&s[..=end], &s[end + 1..])
    } else if let Some((host, port)) = s.split_once(':') {
        (host, &s[host.len()..host.len() + port.len() + 1])
    } else {
        (s, "")
    };
    ensure(!host.is_empty())?;
    encoded(host.trim_start_matches('[').trim_end_matches(']'), b":&=")?;
    let host = url::Host::parse(host).map_err(|_| InvalidUrl)?;
    let port = if port.is_empty() {
        143
    } else {
        let port = port.strip_prefix(':').ok_or(InvalidUrl)?;
        ensure(!port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()))?;
        port.parse::<u16>().map_err(|_| InvalidUrl)?
    };
    Ok((host, port))
}
fn parse(s: &str, rump: bool) -> Result<bool, InvalidUrl> {
    ensure(
        s.is_ascii()
            && s.get(..7)
                .is_some_and(|p| p.eq_ignore_ascii_case("imap://")),
    )?;
    let (authority, mut path) = s[7..].split_once('/').ok_or(InvalidUrl)?;
    let (userinfo, host) = authority
        .rsplit_once('@')
        .map_or((None, authority), |(u, h)| (Some(u), h));
    let mut has_user = false;
    if let Some(userinfo) = userinfo {
        let (user, auth) =
            split_ci(userinfo, ";AUTH=").map_or((userinfo, None), |(u, a)| (u, Some(a)));
        if !user.is_empty() {
            encoded(user, b"&=")?;
            has_user = true;
        } else {
            ensure(auth.is_some())?;
        }
        if let Some(auth) = auth {
            if auth != "*" {
                encoded(auth, b"&=")?;
            }
        }
    }
    server(host)?;
    let mut has_auth = false;
    if let Some((before, auth)) = split_ci(path, ";URLAUTH=") {
        has_auth = true;
        ensure(has_user)?;
        path = before;
        let access = if rump {
            auth
        } else {
            let mut parts = auth.split(':');
            let access = parts.next().ok_or(InvalidUrl)?;
            UrlAuthMechanism::try_from(parts.next().ok_or(InvalidUrl)?)?;
            let token = parts.next().ok_or(InvalidUrl)?;
            ensure(
                parts.next().is_none()
                    && token.len() >= 32
                    && token.bytes().all(|b| b.is_ascii_hexdigit()),
            )?;
            access
        };
        if !access.eq_ignore_ascii_case("authuser") && !access.eq_ignore_ascii_case("anonymous") {
            let (kind, user) = access.split_once('+').ok_or(InvalidUrl)?;
            ensure(kind.eq_ignore_ascii_case("submit") || kind.eq_ignore_ascii_case("user"))?;
            encoded(user, b"&=")?;
        }
        if let Some((before, expire)) = split_ci(path, ";EXPIRE=") {
            chrono::DateTime::parse_from_rfc3339(expire).map_err(|_| InvalidUrl)?;
            path = before;
        }
    }
    let (mailbox, mut message) = split_ci(path, "/;UID=").ok_or(InvalidUrl)?;
    ensure(!mailbox.starts_with('/'))?;
    let mailbox = if let Some((mailbox, validity)) = split_ci(mailbox, ";UIDVALIDITY=") {
        number(validity, true)?;
        mailbox
    } else {
        mailbox
    };
    encoded(mailbox, b"&=:@/")?;
    if let Some((before, partial)) = split_ci(message, "/;PARTIAL=") {
        let (offset, length) = partial
            .split_once('.')
            .map_or((partial, None), |(o, l)| (o, Some(l)));
        number(offset, false)?;
        if let Some(length) = length {
            number(length, true)?;
        }
        message = before;
    }
    if let Some((before, section)) = split_ci(message, "/;SECTION=") {
        encoded(section, b"&=:@/")?;
        message = before;
    }
    number(message, true)?;
    Ok(has_auth)
}

#[cfg(test)]
mod tests {
    use super::*;
    const RUMP: &str = "imap://joe%3Awork;AUTH=*@example.org/INBOX;UIDVALIDITY=2/;UID=1/;SECTION=1.2/;PARTIAL=0.12;EXPIRE=2030-01-01T00:00:00Z;URLAUTH=submit+joe%40example.org";
    #[test]
    fn exact_urls_and_authorities() {
        let full = format!("{RUMP}:INTERNAL:{}", "aB".repeat(20));
        assert_eq!(UrlAuthUrl::try_from(full.as_str()).unwrap().as_str(), full);
        assert_eq!(UrlAuthRump::try_from(RUMP).unwrap().as_str(), RUMP);
        let url = ImapMessageUrl::try_from(full).unwrap();
        assert!(url.has_urlauth());
        assert!(url.matches_trusted_server("imap://EXAMPLE.org:143"));
        assert!(!url.matches_trusted_server("imap://example.org:144"));
        assert!(!url.matches_trusted_server("imap://example.org.evil"));
        assert!(!url.matches_trusted_server("imap://example.org/"));
        for s in [
            "imap://[::1]:993/INBOX/;UID=12",
            "IMAP://joe%40example.org@example.org/INBOX/;UID=1",
            "imap://;AUTH=*@example.org/INBOX/;UID=1",
            "imap://example.org/a/b/;UID=1",
        ] {
            ImapMessageUrl::try_from(s).unwrap();
        }
    }
    #[test]
    fn reject_non_message_or_ambiguous_urls() {
        for s in [
            "imap://h",
            "imap://h/INBOX",
            "imap://h/INBOX/;UID=1 LAST",
            "imap://u:p@h/INBOX/;UID=1",
            "imap://u@h/INBOX/;UID=1#x",
            "imap://u@h/INBOX/;UID=1?x",
            "imap://u%xx@h/INBOX/;UID=1",
            "imap://h/INBOX/;UID=0",
            "imap://h/INBOX/;UID=01",
            "imap://h/INBOX/;UID=4294967296",
            "imap://h/INBOX/;UID=1/;PARTIAL=0.0",
            "imap://h/INBOX/;UID=1;URLAUTH=anonymous:INTERNAL:abcd",
            "imap://u@h/INBOX/;UID=1\r\nNOOP",
            "imap://u@/INBOX/;UID=1",
        ] {
            assert!(ImapMessageUrl::try_from(s).is_err(), "{s}");
        }
        assert!(UrlAuthRump::try_from("imap://u@h/INBOX/;UID=1").is_err());
        assert!(UrlAuthRump::try_from(format!("{RUMP}:INTERNAL:{}", "a".repeat(40))).is_err());
        assert!(UrlAuthUrl::try_from(RUMP).is_err());
    }
    #[cfg(feature = "serde")]
    #[test]
    fn serde_validates() {
        assert!(serde_json::from_str::<ImapMessageUrl>(r#""imap://h/INBOX/;UID=1 LAST""#).is_err());
    }
}
