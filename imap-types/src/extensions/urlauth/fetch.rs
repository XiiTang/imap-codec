//! RFC 5524 URLFETCH arguments and response metadata.
use super::{ImapMessageUrl, UrlResponse};
use crate::{
    body::BodyStructure,
    core::{NString, NString8, Vec1},
};
use bounded_static_derive::ToStatic;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A bare URL retains RFC 4467 behavior. An object selects extended syntax,
/// including when its parameter list is empty. Both forms can share a command.
#[derive(Clone, Debug, Eq, PartialEq, Hash, ToStatic)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(untagged))]
pub enum UrlFetchArgument {
    Simple(ImapMessageUrl),
    Extended(UrlFetchRequest),
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, ToStatic)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(deny_unknown_fields)
)]
pub struct UrlFetchRequest {
    pub url: ImapMessageUrl,
    pub parameters: UrlFetchParameters,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, ToStatic)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum UrlFetchParameter {
    Body,
    Binary,
    BodyPartStructure,
}
impl UrlFetchParameter {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Body => "BODY",
            Self::Binary => "BINARY",
            Self::BodyPartStructure => "BODYPARTSTRUCTURE",
        }
    }
    fn bit(self) -> u8 {
        match self {
            Self::Body => 1,
            Self::Binary => 2,
            Self::BodyPartStructure => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("URLFETCH parameters or metadata contain duplicates or both BODY and BINARY")]
pub struct InvalidUrlFetch;

fn unique(parameters: impl IntoIterator<Item = UrlFetchParameter>) -> Result<(), InvalidUrlFetch> {
    let mut seen = 0;
    for parameter in parameters {
        let bit = parameter.bit();
        if seen & bit != 0 {
            return Err(InvalidUrlFetch);
        }
        seen |= bit;
    }
    if seen & 3 == 3 {
        return Err(InvalidUrlFetch);
    }
    Ok(())
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Hash, ToStatic)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(try_from = "Vec<UrlFetchParameter>", into = "Vec<UrlFetchParameter>")
)]
pub struct UrlFetchParameters(Vec<UrlFetchParameter>);
impl TryFrom<Vec<UrlFetchParameter>> for UrlFetchParameters {
    type Error = InvalidUrlFetch;
    fn try_from(parameters: Vec<UrlFetchParameter>) -> Result<Self, Self::Error> {
        unique(parameters.iter().copied())?;
        Ok(Self(parameters))
    }
}
impl From<UrlFetchParameters> for Vec<UrlFetchParameter> {
    fn from(parameters: UrlFetchParameters) -> Self {
        parameters.0
    }
}
impl AsRef<[UrlFetchParameter]> for UrlFetchParameters {
    fn as_ref(&self) -> &[UrlFetchParameter] {
        &self.0
    }
}
#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for UrlFetchParameters {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Self::try_from(<Vec<UrlFetchParameter> as arbitrary::Arbitrary>::arbitrary(
            u,
        )?)
        .map_err(|_| arbitrary::Error::IncorrectFormat)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, ToStatic)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(deny_unknown_fields)
)]
pub struct UrlFetchResult<'a> {
    pub url: UrlResponse<'a>,
    pub data: UrlFetchData<'a>,
}

/// Keep the original nstring representation for a simple response (including
/// NIL for an invalid URL). Extended responses carry a nonempty metadata array.
#[derive(Clone, Debug, Eq, PartialEq, Hash, ToStatic)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(untagged))]
pub enum UrlFetchData<'a> {
    Simple(NString<'a>),
    Extended(UrlFetchMetadataList<'a>),
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, ToStatic)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(tag = "type", content = "content")
)]
pub enum UrlFetchMetadata<'a> {
    Body(NString<'a>),
    Binary(NString8<'a>),
    BodyPartStructure(Box<BodyStructure<'a>>),
}
impl UrlFetchMetadata<'_> {
    pub fn parameter(&self) -> UrlFetchParameter {
        match self {
            Self::Body(_) => UrlFetchParameter::Body,
            Self::Binary(_) => UrlFetchParameter::Binary,
            Self::BodyPartStructure(_) => UrlFetchParameter::BodyPartStructure,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, ToStatic)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(
        try_from = "Vec1<UrlFetchMetadata<'a>>",
        into = "Vec1<UrlFetchMetadata<'a>>"
    )
)]
pub struct UrlFetchMetadataList<'a>(Vec1<UrlFetchMetadata<'a>>);
impl<'a> TryFrom<Vec1<UrlFetchMetadata<'a>>> for UrlFetchMetadataList<'a> {
    type Error = InvalidUrlFetch;
    fn try_from(metadata: Vec1<UrlFetchMetadata<'a>>) -> Result<Self, Self::Error> {
        unique(metadata.as_ref().iter().map(UrlFetchMetadata::parameter))?;
        Ok(Self(metadata))
    }
}
impl<'a> From<UrlFetchMetadataList<'a>> for Vec1<UrlFetchMetadata<'a>> {
    fn from(metadata: UrlFetchMetadataList<'a>) -> Self {
        metadata.0
    }
}
impl<'a> AsRef<[UrlFetchMetadata<'a>]> for UrlFetchMetadataList<'a> {
    fn as_ref(&self) -> &[UrlFetchMetadata<'a>] {
        self.0.as_ref()
    }
}
#[cfg(feature = "arbitrary")]
impl<'a: 'b, 'b> arbitrary::Arbitrary<'a> for UrlFetchMetadataList<'b> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Self::try_from(<Vec1<UrlFetchMetadata<'b>> as arbitrary::Arbitrary>::arbitrary(u)?)
            .map_err(|_| arbitrary::Error::IncorrectFormat)
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;
    #[test]
    fn extended_serde_cannot_bypass_parameter_validation() {
        for parameters in [
            serde_json::json!(["Body", "Binary"]),
            serde_json::json!(["Body", "Body"]),
        ] {
            let request =
                serde_json::json!({"url":"imap://joe@h/INBOX/;UID=1", "parameters": parameters});
            assert!(serde_json::from_value::<UrlFetchArgument>(request).is_err());
        }
        for metadata in [
            serde_json::json!([]),
            serde_json::json!([{"type":"Body","content":null},{"type":"Body","content":null}]),
        ] {
            assert!(serde_json::from_value::<UrlFetchMetadataList>(metadata).is_err());
        }
    }
}
