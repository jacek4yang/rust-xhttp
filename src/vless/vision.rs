//! XTLS Vision padding codec for non-RAW transports such as XHTTP.

use bytes::Bytes;
use rand::Rng;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, ReadBuf};

pub const COMMAND_CONTINUE: u8 = 0;
pub const COMMAND_END: u8 = 1;
pub const COMMAND_DIRECT: u8 = 2;
const MAX_FRAME_CONTENT: usize = 8192 - 21;

pub fn encode_frame(
    content: &[u8],
    command: u8,
    user_uuid: Option<[u8; 16]>,
    long_padding: bool,
) -> Result<Bytes, VisionError> {
    if !matches!(command, COMMAND_CONTINUE | COMMAND_END | COMMAND_DIRECT) {
        return Err(VisionError::Command(command));
    }
    if content.len() > MAX_FRAME_CONTENT || content.len() > u16::MAX as usize {
        return Err(VisionError::ContentLength(content.len()));
    }
    let max_padding = MAX_FRAME_CONTENT - content.len();
    let wanted = if content.len() < 900 && long_padding {
        rand::thread_rng().gen_range(0..500) + 900 - content.len()
    } else {
        rand::thread_rng().gen_range(0..256)
    };
    let padding_len = wanted.min(max_padding);
    let mut out = Vec::with_capacity(user_uuid.map_or(0, |_| 16) + 5 + content.len() + padding_len);
    if let Some(uuid) = user_uuid {
        out.extend_from_slice(&uuid);
    }
    out.push(command);
    out.extend_from_slice(&(content.len() as u16).to_be_bytes());
    out.extend_from_slice(&(padding_len as u16).to_be_bytes());
    out.extend_from_slice(content);
    out.resize(out.len() + padding_len, 0);
    Ok(Bytes::from(out))
}

pub struct VisionReader<R> {
    inner: R,
    uuid: [u8; 16],
    prefix: [u8; 16],
    prefix_read: usize,
    raw: bool,
    state: ReadState,
    output: Bytes,
}

enum ReadState {
    Header {
        bytes: [u8; 5],
        read: usize,
    },
    Content {
        remaining: usize,
        padding: usize,
        command: u8,
    },
    Padding {
        remaining: usize,
        command: u8,
    },
}

impl<R> VisionReader<R> {
    pub fn new(inner: R, uuid: [u8; 16]) -> Self {
        Self {
            inner,
            uuid,
            prefix: [0; 16],
            prefix_read: 0,
            raw: false,
            state: ReadState::Header {
                bytes: [0; 5],
                read: 0,
            },
            output: Bytes::new(),
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for VisionReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.output.is_empty() {
                let n = this.output.len().min(dst.remaining());
                dst.put_slice(&this.output.split_to(n));
                return Poll::Ready(Ok(()));
            }
            if this.raw {
                return Pin::new(&mut this.inner).poll_read(cx, dst);
            }
            if this.prefix_read < 16 {
                let mut buf = ReadBuf::new(&mut this.prefix[this.prefix_read..]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut buf) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) if buf.filled().is_empty() => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "Vision UUID prefix truncated",
                        )));
                    }
                    Poll::Ready(Ok(())) => {
                        this.prefix_read += buf.filled().len();
                        if this.prefix_read < 16 {
                            continue;
                        }
                        if this.prefix != this.uuid {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "Vision UUID prefix mismatch",
                            )));
                        }
                    }
                }
            }

            match &mut this.state {
                ReadState::Header { bytes, read } => {
                    let mut buf = ReadBuf::new(&mut bytes[*read..]);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut buf) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) if buf.filled().is_empty() => {
                            return Poll::Ready(Ok(()));
                        }
                        Poll::Ready(Ok(())) => {
                            *read += buf.filled().len();
                            if *read < 5 {
                                continue;
                            }
                            let command = bytes[0];
                            if !matches!(command, COMMAND_CONTINUE | COMMAND_END | COMMAND_DIRECT) {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "unknown Vision command",
                                )));
                            }
                            let content = u16::from_be_bytes([bytes[1], bytes[2]]) as usize;
                            let padding = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
                            this.state = ReadState::Content {
                                remaining: content,
                                padding,
                                command,
                            };
                        }
                    }
                }
                ReadState::Content {
                    remaining,
                    padding,
                    command,
                } => {
                    if *remaining == 0 {
                        this.state = ReadState::Padding {
                            remaining: *padding,
                            command: *command,
                        };
                        continue;
                    }
                    let capacity = (*remaining).min(32 * 1024);
                    let mut data = vec![0u8; capacity];
                    let mut buf = ReadBuf::new(&mut data);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut buf) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) if buf.filled().is_empty() => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "Vision content truncated",
                            )));
                        }
                        Poll::Ready(Ok(())) => {
                            let n = buf.filled().len();
                            *remaining -= n;
                            data.truncate(n);
                            this.output = Bytes::from(data);
                        }
                    }
                }
                ReadState::Padding { remaining, command } => {
                    if *remaining == 0 {
                        if *command == COMMAND_CONTINUE {
                            this.state = ReadState::Header {
                                bytes: [0; 5],
                                read: 0,
                            };
                        } else {
                            this.raw = true;
                        }
                        continue;
                    }
                    let capacity = (*remaining).min(8192);
                    let mut discard = vec![0u8; capacity];
                    let mut buf = ReadBuf::new(&mut discard);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut buf) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) if buf.filled().is_empty() => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "Vision padding truncated",
                            )));
                        }
                        Poll::Ready(Ok(())) => *remaining -= buf.filled().len(),
                    }
                }
            }
        }
    }
}

#[derive(Default)]
pub struct TlsFilter {
    pub packets_left: u8,
    pub is_tls: bool,
}

impl TlsFilter {
    pub fn new() -> Self {
        Self {
            packets_left: 8,
            is_tls: false,
        }
    }

    pub fn observe(&mut self, data: &[u8]) {
        self.packets_left = self.packets_left.saturating_sub(1);
        if data.len() >= 6
            && ((data[0] == 0x16 && data[1] == 0x03)
                || (data[0] == 0x17 && data[1..3] == [0x03, 0x03]))
        {
            self.is_tls = true;
        }
    }
}

pub struct VisionWriter {
    uuid: Option<[u8; 16]>,
    filter: TlsFilter,
    padding: bool,
}

impl VisionWriter {
    pub fn new(uuid: [u8; 16]) -> Self {
        Self {
            uuid: Some(uuid),
            filter: TlsFilter::new(),
            padding: true,
        }
    }

    pub fn encode(&mut self, data: &[u8]) -> Result<Vec<Bytes>, VisionError> {
        if !self.padding {
            return Ok(vec![Bytes::copy_from_slice(data)]);
        }
        let mut frames = Vec::new();
        for chunk in data.chunks(MAX_FRAME_CONTENT) {
            self.filter.observe(chunk);
            let application_data = chunk.len() >= 5 && chunk[..3] == [0x17, 0x03, 0x03];
            let command =
                if (self.filter.is_tls && application_data) || self.filter.packets_left == 0 {
                    self.padding = false;
                    COMMAND_END
                } else {
                    COMMAND_CONTINUE
                };
            frames.push(encode_frame(
                chunk,
                command,
                self.uuid.take(),
                self.filter.is_tls,
            )?);
        }
        Ok(frames)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VisionError {
    #[error("unknown Vision command: {0}")]
    Command(u8),
    #[error("Vision frame content is too large: {0}")]
    ContentLength(usize),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn fragmented_unpadding_and_raw_tail() {
        let uuid = [7u8; 16];
        let mut wire = encode_frame(b"hello", COMMAND_END, Some(uuid), false)
            .unwrap()
            .to_vec();
        wire.extend_from_slice(b"raw");
        let source = tokio::io::BufReader::with_capacity(3, std::io::Cursor::new(wire));
        let mut reader = VisionReader::new(source, uuid);
        let mut output = Vec::new();
        reader.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, b"helloraw");
    }

    #[tokio::test]
    async fn multiple_continue_frames() {
        let uuid = [8u8; 16];
        let mut wire = encode_frame(b"a", COMMAND_CONTINUE, Some(uuid), true)
            .unwrap()
            .to_vec();
        wire.extend_from_slice(&encode_frame(b"b", COMMAND_END, None, false).unwrap());
        let mut reader = VisionReader::new(std::io::Cursor::new(wire), uuid);
        let mut output = Vec::new();
        reader.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, b"ab");
    }
}
