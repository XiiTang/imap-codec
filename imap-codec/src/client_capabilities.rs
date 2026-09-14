//! Client-side capability and ENABLE state. Advertising an extension never
//! silently enables it. A new transport starts with a new instance.
use crate::{
    CommandCodec,
    encode::{Encoder, Fragment},
};
use imap_types::{
    command::CommandBody,
    extensions::binary::LiteralOrLiteral8,
    fetch::{MacroOrMessageDataItemNames, MessageDataItemName},
    response::{Code, Data, Response, Status},
    rev2::{ListReturn, MessageSet, SearchReturn},
    search::SearchKey,
};
use std::collections::BTreeSet;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    Rev1,
    Rev2,
}
#[derive(Debug, Clone)]
pub struct ClientCapabilities {
    advertised: BTreeSet<String>,
    enabled: BTreeSet<String>,
    version: Version,
}
impl ClientCapabilities {
    pub fn new(advertised: BTreeSet<String>, version: Version) -> Self {
        Self {
            advertised,
            enabled: BTreeSet::new(),
            version,
        }
    }
    pub fn advertised(&self) -> &BTreeSet<String> {
        &self.advertised
    }
    pub fn enabled(&self) -> &BTreeSet<String> {
        &self.enabled
    }
    pub fn version(&self) -> Version {
        self.version
    }
    pub fn rev2_active(&self) -> bool {
        self.version == Version::Rev2
            && self.advertised.contains("IMAP4REV2")
            && (!self.advertised.contains("IMAP4REV1") || self.enabled.contains("IMAP4REV2"))
    }
    pub fn utf8_active(&self) -> bool {
        self.rev2_active()
            || self.enabled.contains("UTF8=ACCEPT")
            || self.enabled.contains("UTF8=ONLY")
    }
    pub fn supports(&self, name: &str) -> bool {
        self.advertised.contains(name)
            || self.rev2_active()
                && matches!(
                    name,
                    "NAMESPACE"
                        | "UNSELECT"
                        | "UIDPLUS"
                        | "ESEARCH"
                        | "SEARCHRES"
                        | "ENABLE"
                        | "IDLE"
                        | "SASL-IR"
                        | "LIST-EXTENDED"
                        | "LIST-STATUS"
                        | "MOVE"
                        | "LITERAL-"
                        | "BINARY-FETCH"
                        | "STATUS=SIZE"
                )
            || name == "BINARY-FETCH" && self.advertised.contains("BINARY")
    }
    pub fn require(&self, name: &str) -> Result<(), String> {
        if self.supports(name) {
            Ok(())
        } else {
            Err(format!("IMAP capability {name} is required"))
        }
    }
    #[cfg(feature = "ext_condstore_qresync")]
    fn require_enabled(&self, name: &str) -> Result<(), String> {
        if self.enabled.contains(name) {
            Ok(())
        } else {
            Err(format!("IMAP capability {name} has not been enabled"))
        }
    }
    pub fn observe(&mut self, response: &Response<'_>) {
        let caps = match response {
            Response::Data(Data::Capability(c)) => Some(c),
            Response::Status(Status::Tagged(t)) => match &t.body.code {
                Some(Code::Capability(c)) => Some(c),
                _ => None,
            },
            Response::Status(Status::Untagged(t)) => match &t.code {
                Some(Code::Capability(c)) => Some(c),
                _ => None,
            },
            _ => None,
        };
        if let Some(c) = caps {
            self.advertised = c
                .as_ref()
                .iter()
                .map(|c| c.to_string().to_ascii_uppercase())
                .collect();
        }
        if let Response::Data(Data::Enabled { capabilities }) = response {
            self.enabled.extend(
                capabilities
                    .iter()
                    .map(|c| c.to_string().to_ascii_uppercase()),
            );
            if self.enabled.contains("QRESYNC") {
                self.enabled.insert("CONDSTORE".into());
            }
        }
    }
    fn message_set(&self, set: &MessageSet) -> Result<(), String> {
        if matches!(set, MessageSet::SearchResult) {
            self.require("SEARCHRES")?;
        }
        Ok(())
    }
    fn search_key(&self, key: &SearchKey<'_>) -> Result<(), String> {
        match key {
            SearchKey::SearchResult | SearchKey::UidSearchResult => self.require("SEARCHRES")?,
            SearchKey::And(keys) => {
                for key in keys.as_ref() {
                    self.search_key(key)?;
                }
            }
            SearchKey::Not(key) => self.search_key(key)?,
            SearchKey::Or(a, b) => {
                self.search_key(a)?;
                self.search_key(b)?;
            }
            #[cfg(feature = "ext_condstore_qresync")]
            SearchKey::ModSequence { .. } => self.require("CONDSTORE")?,
            SearchKey::New | SearchKey::Old | SearchKey::Recent if self.rev2_active() => {
                return Err("IMAP4rev2 does not define RECENT, NEW or OLD search keys".into());
            }
            _ => {}
        }
        Ok(())
    }
    fn search(
        &self,
        charset: &Option<imap_types::core::Charset>,
        criteria: &imap_types::core::Vec1<SearchKey>,
    ) -> Result<(), String> {
        if !self.rev2_active() && self.utf8_active() && charset.is_some() {
            return Err("IMAP UTF-8 mode prohibits an explicit SEARCH CHARSET".into());
        }
        for key in criteria.as_ref() {
            self.search_key(key)?;
        }
        Ok(())
    }
    pub fn validate_response(&self, response: &Response<'_>) -> Result<(), String> {
        if !self.utf8_active() {
            for fragment in crate::ResponseCodec::default().encode(response) {
                if let Fragment::Line { data } = fragment {
                    if !data.is_ascii() {
                        return Err("UTF-8 response syntax was not enabled".into());
                    }
                }
            }
        }
        Ok(())
    }
    pub fn validate(&self, body: &CommandBody<'_>) -> Result<(), String> {
        match body {
            CommandBody::Idle => self.require("IDLE")?,
            CommandBody::Unselect => self.require("UNSELECT")?,
            CommandBody::ExpungeUid { sequence_set } => {
                self.require("UIDPLUS")?;
                self.message_set(sequence_set)?;
            }
            CommandBody::Move { sequence_set, .. } => {
                self.require("MOVE")?;
                self.message_set(sequence_set)?;
            }
            CommandBody::Copy { sequence_set, .. } => self.message_set(sequence_set)?,
            CommandBody::Enable { capabilities } => {
                self.require("ENABLE")?;
                for c in capabilities.as_ref() {
                    let name = c.to_string().to_ascii_uppercase();
                    if name == "IMAP4REV2" && self.version != Version::Rev2 {
                        return Err("IMAP version was declared as 4rev1".into());
                    }
                    self.require(&name)?;
                }
            }
            CommandBody::Compress { algorithm } => {
                self.require(&format!("COMPRESS={algorithm}"))?
            }
            CommandBody::GetQuota { .. }
            | CommandBody::GetQuotaRoot { .. }
            | CommandBody::SetQuota { .. } => self.require("QUOTA")?,
            #[cfg(feature = "ext_id")]
            CommandBody::Id { .. } => self.require("ID")?,
            #[cfg(feature = "ext_metadata")]
            CommandBody::GetMetadata { .. } | CommandBody::SetMetadata { .. } => {
                self.require("METADATA")?
            }
            #[cfg(feature = "ext_namespace")]
            CommandBody::Namespace => self.require("NAMESPACE")?,
            CommandBody::Sort {
                search_criteria, ..
            } => {
                self.require("SORT")?;
                for k in search_criteria.as_ref() {
                    self.search_key(k)?;
                }
            }
            CommandBody::Thread {
                algorithm,
                search_criteria,
                ..
            } => {
                self.require(&format!("THREAD={algorithm}").to_ascii_uppercase())?;
                for k in search_criteria.as_ref() {
                    self.search_key(k)?;
                }
            }
            CommandBody::Search {
                charset, criteria, ..
            } => self.search(charset, criteria)?,
            CommandBody::SearchExtended {
                returns,
                charset,
                criteria,
                ..
            } => {
                self.require("ESEARCH")?;
                self.search(charset, criteria)?;
                for r in returns {
                    if matches!(r, SearchReturn::Save) {
                        self.require("SEARCHRES")?;
                    }
                }
            }
            CommandBody::ListExtended {
                selection, returns, ..
            } => {
                self.require("LIST-EXTENDED")?;
                if selection
                    .iter()
                    .any(|s| s.as_ref().eq_ignore_ascii_case("SPECIAL-USE"))
                {
                    self.require("SPECIAL-USE")?;
                }
                if let Some(returns) = returns {
                    for r in returns {
                        match r {
                            ListReturn::Status(names) => {
                                self.require("LIST-STATUS")?;
                                self.status_names(names.as_ref())?;
                            }
                            ListReturn::SpecialUse => self.require("SPECIAL-USE")?,
                            _ => {}
                        }
                    }
                }
            }
            CommandBody::Status { item_names, .. } => self.status_names(item_names)?,
            CommandBody::Append { message, .. }
                if matches!(message, LiteralOrLiteral8::Literal8(_)) =>
            {
                self.require("BINARY")?
            }
            CommandBody::Fetch {
                sequence_set,
                macro_or_item_names,
                ..
            } => {
                self.message_set(sequence_set)?;
                if let MacroOrMessageDataItemNames::MessageDataItemNames(names) =
                    macro_or_item_names
                {
                    for name in names {
                        match name {
                            MessageDataItemName::Binary { .. }
                            | MessageDataItemName::BinarySize { .. } => {
                                self.require("BINARY-FETCH")?
                            }
                            #[cfg(feature = "ext_condstore_qresync")]
                            MessageDataItemName::ModSeq => self.require("CONDSTORE")?,
                            MessageDataItemName::Rfc822
                            | MessageDataItemName::Rfc822Header
                            | MessageDataItemName::Rfc822Text
                                if self.rev2_active() =>
                            {
                                return Err("Use BODY sections for IMAP4rev2 FETCH".into());
                            }
                            _ => {}
                        }
                    }
                }
                #[cfg(feature = "ext_condstore_qresync")]
                if let CommandBody::Fetch { uid, modifiers, .. } = body {
                    for modifier in modifiers {
                        match modifier {
                            imap_types::command::FetchModifier::ChangedSince(_) => {
                                self.require("CONDSTORE")?
                            }
                            imap_types::command::FetchModifier::Vanished => {
                                self.require_enabled("QRESYNC")?;
                                if !uid
                                    || !modifiers.iter().any(|m| {
                                        matches!(
                                            m,
                                            imap_types::command::FetchModifier::ChangedSince(_)
                                        )
                                    })
                                {
                                    return Err(
                                        "VANISHED requires UID FETCH with CHANGEDSINCE".into()
                                    );
                                }
                            }
                        }
                    }
                }
            }
            CommandBody::Store { sequence_set, .. } => {
                self.message_set(sequence_set)?;
                #[cfg(feature = "ext_condstore_qresync")]
                if let CommandBody::Store { modifiers, .. } = body {
                    if !modifiers.is_empty() {
                        self.require("CONDSTORE")?;
                    }
                }
            }
            #[cfg(feature = "ext_condstore_qresync")]
            CommandBody::Select { parameters, .. } | CommandBody::Examine { parameters, .. } => {
                for p in parameters {
                    match p {
                        imap_types::command::SelectParameter::CondStore => {
                            self.require("CONDSTORE")?
                        }
                        imap_types::command::SelectParameter::QResync {
                            known_uids,
                            seq_match_data,
                            ..
                        } => {
                            self.require_enabled("QRESYNC")?;
                            if let Some(s) = known_uids {
                                explicit_set(s)?;
                            }
                            if let Some((seq, uids)) = seq_match_data {
                                if explicit_set(seq)? != explicit_set(uids)? {
                                    return Err("QRESYNC sequence and UID match sets must have equal cardinality".into());
                                }
                            }
                        }
                    }
                }
            }
            CommandBody::Check | CommandBody::Lsub { .. } if self.rev2_active() => {
                return Err("Command was removed from IMAP4rev2".into());
            }
            _ => {}
        }
        let command = body.clone().tag("V").map_err(|_| "Invalid tag")?;
        for fragment in CommandCodec::default().encode(&command) {
            match fragment {
                Fragment::Literal {
                    data,
                    mode: imap_types::core::LiteralMode::NonSync,
                } => {
                    if !self.supports("LITERAL+")
                        && !(data.len() <= 4096 && self.supports("LITERAL-"))
                    {
                        return Err("Non-synchronizing literal was not negotiated".into());
                    }
                }
                Fragment::Line { data } if !self.utf8_active() && !data.is_ascii() => {
                    return Err("UTF-8 quoted strings require UTF8=ACCEPT or IMAP4rev2".into());
                }
                _ => {}
            }
        }
        Ok(())
    }
    /// Validate streamed APPEND using its announced length, not a placeholder payload size.
    pub fn validate_streamed_append(
        &self,
        append: &crate::encode::StreamedAppend,
    ) -> Result<(), String> {
        let fragments = append.encode_prefix().map_err(str::to_owned)?;
        if append.binary {
            self.require("BINARY")?;
        }
        if append.mode == imap_types::core::LiteralMode::NonSync
            && !self.supports("LITERAL+")
            && !(append.length <= 4096 && self.supports("LITERAL-"))
        {
            return Err("Non-synchronizing APPEND length was not negotiated".into());
        }
        for fragment in fragments {
            match fragment {
                Fragment::Line { data } if !self.utf8_active() && !data.is_ascii() => {
                    return Err("UTF-8 quoted strings require UTF8=ACCEPT or IMAP4rev2".into());
                }
                Fragment::Literal {
                    data,
                    mode: imap_types::core::LiteralMode::NonSync,
                } if !self.supports("LITERAL+")
                    && !(data.len() <= 4096 && self.supports("LITERAL-")) =>
                {
                    return Err("Non-synchronizing mailbox literal was not negotiated".into());
                }
                _ => {}
            }
        }
        Ok(())
    }
    fn status_names(&self, names: &[imap_types::status::StatusDataItemName]) -> Result<(), String> {
        use imap_types::status::StatusDataItemName::*;
        for n in names {
            match n {
                Size => self.require("STATUS=SIZE")?,
                Deleted if !self.rev2_active() => self.require("QUOTA=RES-MESSAGE")?,
                DeletedStorage => self.require("QUOTA=RES-STORAGE")?,
                Recent if self.rev2_active() => {
                    return Err("RECENT status was removed from IMAP4rev2".into());
                }
                #[cfg(feature = "ext_condstore_qresync")]
                HighestModSeq => self.require("CONDSTORE")?,
                _ => {}
            }
        }
        Ok(())
    }
}
#[cfg(feature = "ext_condstore_qresync")]
fn explicit_set(set: &imap_types::sequence::SequenceSet) -> Result<u64, String> {
    use imap_types::sequence::{SeqOrUid, Sequence};
    let mut total = 0u64;
    for seq in set.0.as_ref() {
        let (a, b) = match seq {
            Sequence::Single(a) => (a, a),
            Sequence::Range(a, b) => (a, b),
        };
        let (SeqOrUid::Value(a), SeqOrUid::Value(b)) = (a, b) else {
            return Err("QRESYNC match sets cannot contain '*'".into());
        };
        total = total
            .checked_add(u64::from(a.get().abs_diff(b.get())) + 1)
            .ok_or("QRESYNC set cardinality overflow")?;
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CommandCodec, ResponseCodec, decode::Decoder};
    fn validate(c: &ClientCapabilities, wire: &[u8]) -> Result<(), String> {
        c.validate(&CommandCodec::default().decode(wire).unwrap().1.body)
    }
    #[test]
    fn rev2_intrinsic_capabilities_require_explicit_enable_on_dual_server() {
        let mut c = ClientCapabilities::new(
            ["IMAP4REV1", "IMAP4REV2", "ENABLE"]
                .map(str::to_owned)
                .into(),
            Version::Rev2,
        );
        assert!(!c.supports("MOVE"));
        assert!(!c.rev2_active());
        c.observe(
            &ResponseCodec::default()
                .decode(b"* ENABLED IMAP4rev2\r\n")
                .unwrap()
                .1,
        );
        assert!(c.rev2_active());
        assert!(c.supports("MOVE"));
        assert!(c.supports("BINARY-FETCH"));
        assert!(!c.supports("BINARY"));
        assert!(validate(&c, b"A SEARCH RETURN (ALL SAVE) CHARSET UTF-8 UID $\r\n").is_ok());
        assert!(validate(&c, b"A FETCH $ BINARY.PEEK[]\r\n").is_ok());
        assert!(validate(&c, b"A CHECK\r\n").is_err());
        assert!(validate(&c, b"A FETCH 1 RFC822\r\n").is_err());
        assert!(validate(&c, b"A SEARCH NEW\r\n").is_err());
        assert!(!c.advertised().contains("MOVE"));
    }
    #[cfg(feature = "ext_condstore_qresync")]
    #[test]
    fn qresync_is_enabled_explicitly_and_match_data_is_checked_without_expanding_ranges() {
        let mut c = ClientCapabilities::new(
            ["IMAP4REV1", "ENABLE", "QRESYNC", "CONDSTORE"]
                .map(str::to_owned)
                .into(),
            Version::Rev1,
        );
        let select = b"A SELECT inbox (QRESYNC (42 1000 1:4294967295 (1:3 4:6)))\r\n";
        assert!(validate(&c, select).is_err());
        c.observe(
            &ResponseCodec::default()
                .decode(b"* ENABLED QRESYNC\r\n")
                .unwrap()
                .1,
        );
        assert!(validate(&c, select).is_ok());
        assert!(validate(&c, b"A SELECT inbox (QRESYNC (42 1000 1:*))\r\n").is_err());
        assert!(validate(&c, b"A SELECT inbox (QRESYNC (42 1000 (1:3 4:5)))\r\n").is_err());
        assert!(validate(&c, b"A UID FETCH 1:* FLAGS (VANISHED)\r\n").is_err());
        assert!(validate(&c, b"A FETCH 1:* FLAGS (CHANGEDSINCE 1000 VANISHED)\r\n").is_err());
        assert!(
            validate(
                &c,
                b"A UID FETCH 1:* FLAGS (CHANGEDSINCE 1000 VANISHED)\r\n"
            )
            .is_ok()
        );
    }
    #[cfg(feature = "ext_utf8")]
    #[test]
    fn utf8_enable_is_distinct_from_advertisement_and_rev2() {
        let mut c = ClientCapabilities::new(
            ["IMAP4REV1", "ENABLE", "UTF8=ACCEPT"]
                .map(str::to_owned)
                .into(),
            Version::Rev1,
        );
        assert!(validate(&c, "A SELECT \"邮件\"\r\n".as_bytes()).is_err());
        c.observe(
            &ResponseCodec::default()
                .decode(b"* ENABLED UTF8=ACCEPT\r\n")
                .unwrap()
                .1,
        );
        assert!(validate(&c, "A SELECT \"邮件\"\r\n".as_bytes()).is_ok());
        assert!(validate(&c, b"A SEARCH CHARSET UTF-8 ALL\r\n").is_err());
        assert!(validate(&c, b"A SEARCH ALL\r\n").is_ok());
    }
}
