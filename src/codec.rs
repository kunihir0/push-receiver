use crate::error::{Error, Result};
use crate::proto::{
    Close, DataMessageStanza, HeartbeatAck, HeartbeatPing, IqStanza, LoginRequest, LoginResponse,
    StreamErrorStanza,
};
use bytes::{Buf, BufMut, BytesMut};
use prost::Message;
use tokio_util::codec::{Decoder, Encoder};

#[derive(Debug, Clone)]
pub enum McsMessage {
    HeartbeatPing(HeartbeatPing),
    HeartbeatAck(HeartbeatAck),
    LoginRequest(LoginRequest),
    LoginResponse(LoginResponse),
    Close(Close),
    IqStanza(IqStanza),
    DataMessageStanza(DataMessageStanza),
    StreamErrorStanza(StreamErrorStanza),
}

impl McsMessage {
    pub fn tag(&self) -> u8 {
        match self {
            Self::HeartbeatPing(_) => 0,
            Self::HeartbeatAck(_) => 1,
            Self::LoginRequest(_) => 2,
            Self::LoginResponse(_) => 3,
            Self::Close(_) => 4,
            Self::IqStanza(_) => 7,
            Self::DataMessageStanza(_) => 8,
            Self::StreamErrorStanza(_) => 10,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum CodecState {
    VersionTagAndSize,
    TagAndSize,
    Size,
    ProtoBytes,
}

pub struct McsCodec {
    state: CodecState,
    tag: u8,
    size: usize,
}

impl McsCodec {
    pub fn new() -> Self {
        Self {
            state: CodecState::VersionTagAndSize,
            tag: 0,
            size: 0,
        }
    }

    fn decode_varint(src: &mut BytesMut) -> Option<usize> {
        let mut result = 0;
        let mut shift = 0;
        let mut bytes_read = 0;
        for &byte in src.iter() {
            bytes_read += 1;
            result |= ((byte & 0x7F) as usize) << shift;
            if byte & 0x80 == 0 {
                src.advance(bytes_read);
                return Some(result);
            }
            shift += 7;
            if shift >= 32 {
                break; // Invalid varint
            }
        }
        None
    }
}

impl Default for McsCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder for McsCodec {
    type Item = McsMessage;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        loop {
            match self.state {
                CodecState::VersionTagAndSize => {
                    if src.is_empty() {
                        return Ok(None);
                    }
                    let version = src[0];
                    if version < 41 && version != 38 {
                        return Err(Error::Protocol(format!("Invalid version: {version}")));
                    }
                    src.advance(1);
                    self.state = CodecState::TagAndSize;
                }
                CodecState::TagAndSize => {
                    if src.is_empty() {
                        return Ok(None);
                    }
                    self.tag = src[0];
                    src.advance(1);
                    self.state = CodecState::Size;
                }
                CodecState::Size => {
                    if let Some(size) = Self::decode_varint(src) {
                        self.size = size;
                        self.state = CodecState::ProtoBytes;
                    } else {
                        return Ok(None);
                    }
                }
                CodecState::ProtoBytes => {
                    if src.len() < self.size {
                        return Ok(None);
                    }
                    let payload = src.split_to(self.size);
                    self.state = CodecState::TagAndSize;

                    let msg = match self.tag {
                        0 => McsMessage::HeartbeatPing(HeartbeatPing::decode(payload)?),
                        1 => McsMessage::HeartbeatAck(HeartbeatAck::decode(payload)?),
                        2 => McsMessage::LoginRequest(LoginRequest::decode(payload)?),
                        3 => McsMessage::LoginResponse(LoginResponse::decode(payload)?),
                        4 => McsMessage::Close(Close::decode(payload)?),
                        7 => McsMessage::IqStanza(IqStanza::decode(payload)?),
                        8 => McsMessage::DataMessageStanza(DataMessageStanza::decode(payload)?),
                        10 => McsMessage::StreamErrorStanza(StreamErrorStanza::decode(payload)?),
                        tag => {
                            tracing::debug!("Unknown tag: {}", tag);
                            continue; // Skip unknown
                        }
                    };
                    return Ok(Some(msg));
                }
            }
        }
    }
}

impl Encoder<McsMessage> for McsCodec {
    type Error = Error;

    fn encode(&mut self, item: McsMessage, dst: &mut BytesMut) -> Result<()> {
        let tag = item.tag();
        let is_login = tag == 2;

        let mut payload = BytesMut::new();
        match item {
            McsMessage::HeartbeatPing(m) => m.encode(&mut payload)?,
            McsMessage::HeartbeatAck(m) => m.encode(&mut payload)?,
            McsMessage::LoginRequest(m) => m.encode(&mut payload)?,
            McsMessage::LoginResponse(m) => m.encode(&mut payload)?,
            McsMessage::Close(m) => m.encode(&mut payload)?,
            McsMessage::IqStanza(m) => m.encode(&mut payload)?,
            McsMessage::DataMessageStanza(m) => m.encode(&mut payload)?,
            McsMessage::StreamErrorStanza(m) => m.encode(&mut payload)?,
        }

        if is_login {
            dst.put_u8(41); // Version
        }
        dst.put_u8(tag);

        // Encode varint size
        let mut size = payload.len();
        #[allow(clippy::cast_possible_truncation)]
        loop {
            let mut byte = (size & 0x7F) as u8;
            size >>= 7;
            if size > 0 {
                byte |= 0x80;
                dst.put_u8(byte);
            } else {
                dst.put_u8(byte);
                break;
            }
        }
        dst.put_slice(&payload);
        Ok(())
    }
}
