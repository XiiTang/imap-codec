//! Bounded response literal streaming using the same line parser as Fragmentizer.
//! Literal bytes never enter the message syntax buffer. The final typed response
//! contains private reference markers, resolved with `literal_reference` when
//! producing a public DTO. It must not be used as a materialized response.
use super::{FragmentInfo, LineEnding, LineParser};
use crate::{ResponseCodec, decode::Decoder};
use imap_types::{IntoStatic, core::LiteralMode, response::Response};
use std::collections::VecDeque;

const INPUT_BUFFER: usize = 64 * 1024;
const MARKER: &[u8] = b"~imap-stream-literal~";
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiteralDescriptor {
    pub index: u32,
    pub length: u64,
    pub binary: bool,
}
#[derive(Debug)]
pub enum StreamingResponseEvent {
    LiteralStart {
        literal: LiteralDescriptor,
        prefix: Vec<u8>,
    },
    LiteralChunk {
        index: u32,
        data: Vec<u8>,
    },
    LiteralEnd {
        index: u32,
    },
    Complete {
        structure: Response<'static>,
    },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StreamingResponseError {
    BufferLimit,
    Syntax,
    NonSyncResponse,
    NullLiteral,
    Failed,
}
impl std::fmt::Display for StreamingResponseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IMAP response streaming: {self:?}")
    }
}
impl std::error::Error for StreamingResponseError {}
/// Returns the descriptor represented by a literal in a streamed response
/// structure. Every literal in that structure must resolve to one descriptor.
pub fn literal_reference<'a>(
    data: &[u8],
    literals: &'a [LiteralDescriptor],
) -> Option<&'a LiteralDescriptor> {
    let digits = data.strip_prefix(MARKER)?;
    if digits.len() != 8 {
        return None;
    }
    let index = u32::from_str_radix(std::str::from_utf8(digits).ok()?, 16).ok()?;
    literals.get(index as usize).filter(|d| d.index == index)
}

pub struct StreamingResponseDecoder {
    input: VecDeque<u8>,
    line_parser: LineParser,
    line: Vec<u8>,
    syntax: Vec<u8>,
    normalized: Vec<u8>,
    literals: Vec<LiteralDescriptor>,
    remaining: Option<u64>,
    maximum: usize,
    consumed: usize,
    complete: bool,
    failed: bool,
}
impl std::fmt::Debug for StreamingResponseDecoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamingResponseDecoder")
            .field("buffered", &self.input.len())
            .field("literal_count", &self.literals.len())
            .field("complete", &self.complete)
            .finish_non_exhaustive()
    }
}
impl StreamingResponseDecoder {
    pub fn new(maximum_syntax_bytes: usize) -> Self {
        Self {
            input: VecDeque::new(),
            line_parser: LineParser::new(0),
            line: Vec::new(),
            syntax: Vec::new(),
            normalized: Vec::new(),
            literals: Vec::new(),
            remaining: None,
            maximum: maximum_syntax_bytes,
            consumed: 0,
            complete: false,
            failed: false,
        }
    }
    pub fn enqueue_input(&mut self, bytes: &[u8]) -> Result<(), StreamingResponseError> {
        if self.failed {
            return Err(StreamingResponseError::Failed);
        }
        if self
            .input
            .len()
            .checked_add(bytes.len())
            .is_none_or(|n| n > INPUT_BUFFER)
        {
            self.failed = true;
            return Err(StreamingResponseError::BufferLimit);
        }
        self.input.extend(bytes);
        Ok(())
    }
    pub fn take_consumed_input(&mut self) -> usize {
        std::mem::take(&mut self.consumed)
    }
    pub fn syntax_bytes(&self) -> &[u8] {
        &self.syntax
    }
    pub fn literals(&self) -> &[LiteralDescriptor] {
        &self.literals
    }
    pub fn is_message_complete(&self) -> bool {
        self.complete
    }
    pub fn take_unparsed_after_message(&mut self) -> Option<Vec<u8>> {
        if self.complete {
            Some(std::mem::take(&mut self.input).into())
        } else {
            None
        }
    }
    pub fn next(&mut self) -> Result<Option<StreamingResponseEvent>, StreamingResponseError> {
        if self.failed {
            return Err(StreamingResponseError::Failed);
        }
        let result = self.progress();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn account_syntax(&self, additional: usize) -> Result<(), StreamingResponseError> {
        self.syntax
            .len()
            .checked_add(self.normalized.len())
            .and_then(|n| n.checked_add(self.line.len()))
            .and_then(|n| {
                n.checked_add(
                    self.literals
                        .len()
                        .checked_mul(std::mem::size_of::<LiteralDescriptor>())?,
                )
            })
            .and_then(|n| n.checked_add(additional))
            .filter(|n| *n <= self.maximum)
            .map(|_| ())
            .ok_or(StreamingResponseError::BufferLimit)
    }
    fn progress(&mut self) -> Result<Option<StreamingResponseEvent>, StreamingResponseError> {
        if self.complete {
            self.complete = false;
            self.syntax.clear();
            self.normalized.clear();
            self.literals.clear();
        }
        if let Some(remaining) = self.remaining {
            let literal = self.literals.last().ok_or(StreamingResponseError::Syntax)?;
            if remaining == 0 {
                self.remaining = None;
                return Ok(Some(StreamingResponseEvent::LiteralEnd {
                    index: literal.index,
                }));
            }
            if self.input.is_empty() {
                return Ok(None);
            }
            let count = remaining.min(self.input.len() as u64) as usize;
            let data = self.input.drain(..count).collect::<Vec<_>>();
            self.consumed += count;
            if !literal.binary && data.contains(&0) {
                return Err(StreamingResponseError::NullLiteral);
            }
            self.remaining = Some(remaining - count as u64);
            return Ok(Some(StreamingResponseEvent::LiteralChunk {
                index: literal.index,
                data,
            }));
        }
        let (count, fragment) = self.line_parser.parse(&self.input);
        self.account_syntax(count)?;
        self.line.extend(self.input.drain(..count));
        self.consumed += count;
        let Some(FragmentInfo::Line {
            announcement,
            ending,
            ..
        }) = fragment
        else {
            return Ok(None);
        };
        if ending != LineEnding::CrLf {
            return Err(StreamingResponseError::Syntax);
        }
        self.line_parser = LineParser::new(0);
        match announcement {
            Some(announcement) => {
                // A response text can end in "{123}" without announcing a
                // literal. Ask the real response parser before consuming bytes.
                let previous = self.normalized.len();
                self.account_syntax(self.line.len())?;
                self.normalized.extend_from_slice(&self.line);
                match ResponseCodec::default().decode(&self.normalized) {
                    Ok((rest, response)) if rest.is_empty() => {
                        let structure = response.into_static();
                        self.syntax.extend_from_slice(&self.line);
                        self.line.clear();
                        self.complete = true;
                        return Ok(Some(StreamingResponseEvent::Complete { structure }));
                    }
                    Err(crate::decode::ResponseDecodeError::LiteralFound { length })
                        if length == announcement.length => {}
                    _ => return Err(StreamingResponseError::Syntax),
                }
                self.normalized.truncate(previous);
                if announcement.mode != LiteralMode::Sync {
                    return Err(StreamingResponseError::NonSyncResponse);
                }
                let start = self
                    .line
                    .iter()
                    .rposition(|&b| b == b'{')
                    .ok_or(StreamingResponseError::Syntax)?;
                let literal = LiteralDescriptor {
                    index: self
                        .literals
                        .len()
                        .try_into()
                        .map_err(|_| StreamingResponseError::BufferLimit)?,
                    length: announcement.length,
                    binary: start > 0 && self.line[start - 1] == b'~',
                };
                let marker = format!("~imap-stream-literal~{:08X}", literal.index);
                let replacement = format!("{{{}}}\r\n{marker}", marker.len());
                self.account_syntax(
                    self.line.len()
                        + start
                        + replacement.len()
                        + std::mem::size_of::<LiteralDescriptor>(),
                )?;
                self.syntax.extend_from_slice(&self.line);
                self.normalized.extend_from_slice(&self.line[..start]);
                self.normalized.extend_from_slice(replacement.as_bytes());
                self.literals.push(literal.clone());
                self.remaining = Some(literal.length);
                Ok(Some(StreamingResponseEvent::LiteralStart {
                    literal,
                    prefix: std::mem::take(&mut self.line),
                }))
            }
            None => {
                self.account_syntax(self.line.len() * 2)?;
                self.syntax.extend_from_slice(&self.line);
                self.normalized.extend_from_slice(&self.line);
                self.line.clear();
                let (rest, response) = ResponseCodec::default()
                    .decode(&self.normalized)
                    .map_err(|_| StreamingResponseError::Syntax)?;
                if !rest.is_empty() {
                    return Err(StreamingResponseError::Syntax);
                }
                let structure = response.into_static();
                self.complete = true;
                Ok(Some(StreamingResponseEvent::Complete { structure }))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use imap_types::{core::NString, fetch::MessageDataItem, response::Data};
    #[test]
    fn bytewise_multiple_literals_keep_exact_boundaries_and_binary_nuls() {
        let wire = b"* 1 FETCH (BODY[] {3}\r\nabc BINARY[1] ~{3}\r\nx\0y)\r\nA OK done\r\n";
        let mut decoder = StreamingResponseDecoder::new(4096);
        let mut literals = Vec::<Vec<u8>>::new();
        let mut completed = 0;
        for &byte in wire {
            decoder.enqueue_input(&[byte]).unwrap();
            while let Some(event) = decoder.next().unwrap() {
                match event {
                    StreamingResponseEvent::LiteralStart { literal, prefix } => {
                        assert_eq!(literal.index as usize, literals.len());
                        assert!(prefix.ends_with(b"{3}\r\n"));
                        literals.push(Vec::new());
                    }
                    StreamingResponseEvent::LiteralChunk { index, data } => {
                        literals[index as usize].extend(data)
                    }
                    StreamingResponseEvent::LiteralEnd { index } => {
                        assert_eq!(literals[index as usize].len(), 3)
                    }
                    StreamingResponseEvent::Complete { structure } => {
                        if completed == 0 {
                            assert_eq!(decoder.literals().len(), 2);
                            let Response::Data(Data::Fetch { items, .. }) = structure else {
                                panic!()
                            };
                            let MessageDataItem::BodyExt {
                                data: NString(Some(data)),
                                ..
                            } = &items.as_ref()[0]
                            else {
                                panic!()
                            };
                            assert_eq!(
                                literal_reference(data.as_ref(), decoder.literals())
                                    .unwrap()
                                    .index,
                                0
                            );
                            assert_eq!(
                                decoder.syntax_bytes(),
                                b"* 1 FETCH (BODY[] {3}\r\n BINARY[1] ~{3}\r\n)\r\n"
                            );
                        } else {
                            assert!(decoder.literals().is_empty());
                        }
                        completed += 1;
                    }
                }
            }
        }
        assert_eq!(completed, 2);
        assert_eq!(literals, vec![b"abc".to_vec(), b"x\0y".to_vec()]);
        assert_eq!(decoder.take_consumed_input(), wire.len());
    }
    #[test]
    fn response_text_literal_lookalike_does_not_consume_next_message() {
        let mut decoder = StreamingResponseDecoder::new(2048);
        decoder
            .enqueue_input(b"A OK note {123}\r\nB OK next\r\n")
            .unwrap();
        assert!(matches!(
            decoder.next().unwrap(),
            Some(StreamingResponseEvent::Complete { .. })
        ));
        assert!(decoder.literals().is_empty());
        assert!(matches!(
            decoder.next().unwrap(),
            Some(StreamingResponseEvent::Complete { .. })
        ));
    }
    #[test]
    fn large_literal_stays_bounded_and_huge_declaration_is_not_allocated() {
        let mut decoder = StreamingResponseDecoder::new(2048);
        let length = 32 * 1024 * 1024;
        decoder
            .enqueue_input(format!("* 1 FETCH (BODY[] {{{length}}}\r\n").as_bytes())
            .unwrap();
        assert!(matches!(
            decoder.next().unwrap(),
            Some(StreamingResponseEvent::LiteralStart { .. })
        ));
        let chunk = vec![b'a'; INPUT_BUFFER];
        let mut received = 0;
        for _ in 0..length / INPUT_BUFFER {
            decoder.enqueue_input(&chunk).unwrap();
            while let Some(event) = decoder.next().unwrap() {
                if let StreamingResponseEvent::LiteralChunk { data, .. } = event {
                    received += data.len();
                }
            }
            assert!(decoder.syntax.capacity() < 2048);
            assert!(decoder.normalized.capacity() < 2048);
            assert!(decoder.line.capacity() < 2048);
        }
        assert_eq!(received, length);
        decoder.enqueue_input(b")\r\n").unwrap();
        assert!(matches!(
            decoder.next().unwrap(),
            Some(StreamingResponseEvent::Complete { .. })
        ));
        let mut decoder = StreamingResponseDecoder::new(2048);
        decoder
            .enqueue_input(b"* 1 FETCH (BODY[] {9223372036854775807}\r\n")
            .unwrap();
        let Some(StreamingResponseEvent::LiteralStart { literal, .. }) = decoder.next().unwrap()
        else {
            panic!()
        };
        assert_eq!(literal.length, i64::MAX as u64);
        assert!(decoder.next().unwrap().is_none());
    }
    #[test]
    fn malformed_data_fails_closed_and_handoff_requires_completion() {
        for bytes in [
            b"* 1 FETCH (BODY[] {1+}\r\n".as_slice(),
            b"* 1 FETCH (BODY[] {1}\r\n\0",
            b"* 1 FETCH (BODY[] {0}\n",
        ] {
            let mut decoder = StreamingResponseDecoder::new(2048);
            decoder.enqueue_input(bytes).unwrap();
            let mut failure = false;
            loop {
                match decoder.next() {
                    Err(_) => {
                        failure = true;
                        break;
                    }
                    Ok(None) => break,
                    Ok(Some(_)) => {}
                }
            }
            assert!(failure);
            assert!(decoder.next().is_err());
        }
        let mut decoder = StreamingResponseDecoder::new(2048);
        decoder.enqueue_input(b"A OK done\r\nopaque").unwrap();
        assert!(decoder.take_unparsed_after_message().is_none());
        assert!(matches!(
            decoder.next().unwrap(),
            Some(StreamingResponseEvent::Complete { .. })
        ));
        assert_eq!(decoder.take_unparsed_after_message().unwrap(), b"opaque");
    }
}
