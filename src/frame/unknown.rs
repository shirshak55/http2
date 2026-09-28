use crate::frame::Frame;

use bytes::{BufMut, Bytes};

/// A frame of a type HTTP/2 doesn't define, such as a GREASE type, encoded as given.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Unknown {
    kind: u8,
    flags: u8,
    stream_id: u32,
    payload: Bytes,
}

impl Unknown {
    /// The payload must fit a frame's 24-bit length.
    pub fn new(kind: u8, flags: u8, stream_id: u32, payload: Bytes) -> Self {
        Unknown {
            kind,
            flags,
            stream_id,
            payload,
        }
    }

    pub fn kind(&self) -> u8 {
        self.kind
    }

    pub fn flags(&self) -> u8 {
        self.flags
    }

    pub fn stream_id(&self) -> u32 {
        self.stream_id
    }

    pub fn payload(&self) -> &Bytes {
        &self.payload
    }

    pub fn encode<B: BufMut>(&self, dst: &mut B) {
        dst.put_uint(self.payload.len() as u64, 3);
        dst.put_u8(self.kind);
        dst.put_u8(self.flags);
        dst.put_u32(self.stream_id);
        dst.put_slice(&self.payload);
    }
}

impl<B> From<Unknown> for Frame<B> {
    fn from(src: Unknown) -> Self {
        Frame::Unknown(src)
    }
}
