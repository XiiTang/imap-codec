//! IMAP4rev2 and the ESEARCH, SEARCHRES and LIST-EXTENDED extensions.
use crate::{
    core::{AString, Atom, Vec1},
    sequence::SequenceSet,
    status::StatusDataItemName,
};
use bounded_static_derive::ToStatic;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A command message set. The saved result is a server-owned variable; it is
/// never expanded locally and cannot be mixed into an ordinary sequence set.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", content = "content"))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub enum MessageSet {
    SequenceSet(SequenceSet),
    SearchResult,
}
impl From<SequenceSet> for MessageSet {
    fn from(value: SequenceSet) -> Self {
        Self::SequenceSet(value)
    }
}
impl TryFrom<&str> for MessageSet {
    type Error = crate::error::ValidationError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value == "$" {
            Ok(Self::SearchResult)
        } else {
            Ok(Self::SequenceSet(value.try_into()?))
        }
    }
}
impl TryFrom<u32> for MessageSet {
    type Error = crate::error::ValidationError;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Ok(Self::SequenceSet(value.try_into()?))
    }
}
impl TryFrom<i32> for MessageSet {
    type Error = crate::error::ValidationError;
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        Ok(Self::SequenceSet(value.try_into()?))
    }
}

/// A nested extension component (RFC 9051 tagged-ext-comp).
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", content = "content"))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub enum ExtensionComponent<'a> {
    String(AString<'a>),
    List(Vec<ExtensionComponent<'a>>),
}

/// The generic extension value grammar preserves unknown response extensions.
/// Simple values are validated numeric/sequence atoms by the codec.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", content = "content"))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub enum ExtensionValue<'a> {
    Simple(Atom<'a>),
    List(Vec<ExtensionComponent<'a>>),
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", content = "content"))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub enum SearchReturn<'a> {
    Min,
    Max,
    All,
    Count,
    Save,
    Extension {
        name: Atom<'a>,
        parameters: Option<ExtensionValue<'a>>,
    },
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct SearchReturnData<'a> {
    pub name: Atom<'a>,
    pub value: ExtensionValue<'a>,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", content = "content"))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub enum ListReturn<'a> {
    Subscribed,
    Children,
    SpecialUse,
    Status(Vec1<StatusDataItemName>),
    Extension {
        name: Atom<'a>,
        parameters: Option<ExtensionValue<'a>>,
    },
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct ListExtension<'a> {
    pub tag: AString<'a>,
    pub value: ExtensionValue<'a>,
}
