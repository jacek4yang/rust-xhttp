use super::{HeaderXor, RecordCipher, decode_header};
use bytes::{Buf, Bytes, BytesMut};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, ReadBuf};

pub struct EncryptedReader<R> {
    inner: R,
    cipher: RecordCipher,
    xor: Option<HeaderXor>,
    encrypted: BytesMut,
    plaintext: Bytes,
    expected: Option<usize>,
}

impl<R> EncryptedReader<R> {
    pub fn new(inner: R, cipher: RecordCipher, xor: Option<HeaderXor>) -> Self {
        Self {
            inner,
            cipher,
            xor,
            encrypted: BytesMut::new(),
            plaintext: Bytes::new(),
            expected: None,
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for EncryptedReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.plaintext.is_empty() {
                let n = self.plaintext.len().min(output.remaining());
                output.put_slice(&self.plaintext[..n]);
                self.plaintext.advance(n);
                return Poll::Ready(Ok(()));
            }
            if self.expected.is_none() && self.encrypted.len() >= 5 {
                let header: [u8; 5] = self.encrypted[..5].try_into().unwrap();
                self.expected = Some(
                    decode_header(&header)
                        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?,
                );
            }
            if let Some(length) = self.expected {
                if self.encrypted.len() >= 5 + length {
                    let record = self.encrypted.split_to(5 + length).freeze();
                    let header: &[u8; 5] = record[..5].try_into().unwrap();
                    self.plaintext = Bytes::from(
                        self.cipher
                            .open(header, &record[5..])
                            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?,
                    );
                    self.expected = None;
                    continue;
                }
            }

            let mut temporary = [0u8; 8192];
            let mut read_buf = ReadBuf::new(&mut temporary);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) if read_buf.filled().is_empty() => {
                    if self.encrypted.is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "encrypted record truncated",
                    )));
                }
                Poll::Ready(Ok(())) => {
                    let bytes = read_buf.filled_mut();
                    if let Some(xor) = self.xor.as_mut() {
                        xor.apply(bytes)
                            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                    }
                    self.encrypted.extend_from_slice(bytes);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vless::encryption::CipherKind;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn fragmented_records() {
        let mut sender = RecordCipher::new(b"ctx", b"key", CipherKind::Aes256Gcm);
        let mut wire = sender.seal(b"hello").unwrap();
        wire.extend_from_slice(&sender.seal(b"world").unwrap());
        let source = tokio::io::BufReader::with_capacity(3, std::io::Cursor::new(wire));
        let cipher = RecordCipher::new(b"ctx", b"key", CipherKind::Aes256Gcm);
        let mut reader = EncryptedReader::new(source, cipher, None);
        let mut output = Vec::new();
        reader.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, b"helloworld");
    }
}
