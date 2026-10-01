//! A log writer that redacts stored secret values before anything reaches disk
//! or a terminal (INV-1, defence in depth: handlers never log values on
//! purpose; this catches mistakes).

use crate::state::redact;
use std::io::{self, Write};
use std::sync::Mutex;
use tracing_subscriber::fmt::MakeWriter;

/// Wraps any writer; every write is passed through the global redactor.
pub struct RedactingWriter<W: Write + Send> {
    inner: Mutex<W>,
}

impl<W: Write + Send> RedactingWriter<W> {
    /// Wrap `inner`.
    pub fn new(inner: W) -> Self {
        Self {
            inner: Mutex::new(inner),
        }
    }
}

/// One writer handle, as `tracing` requests per event.
pub struct RedactingHandle<'a, W: Write + Send> {
    owner: &'a RedactingWriter<W>,
}

impl<W: Write + Send> Write for RedactingHandle<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let clean = redact(buf);
        let mut w = self.owner.inner.lock().unwrap_or_else(|e| e.into_inner());
        w.write_all(&clean)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.owner
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .flush()
    }
}

impl<'a, W: Write + Send + 'a> MakeWriter<'a> for RedactingWriter<W> {
    type Writer = RedactingHandle<'a, W>;

    fn make_writer(&'a self) -> Self::Writer {
        RedactingHandle { owner: self }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::set_redactor;
    use std::sync::{Arc, Mutex as StdMutex};
    use unseenkey_core::broker::scrub::{Guarded, Scrubber};
    use unseenkey_core::crypto::SecretBytes;

    #[derive(Clone, Default)]
    struct Sink(Arc<StdMutex<Vec<u8>>>);
    impl Write for Sink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn writes_are_redacted() {
        let value = SecretBytes::from("sk_live_51Habcdefghijklmnop");
        set_redactor(Scrubber::new(&[Guarded {
            name: "stripe",
            value: &value,
        }]));
        let sink = Sink::default();
        let w = RedactingWriter::new(sink.clone());
        let mut h = w.make_writer();
        h.write_all(b"leak: sk_live_51Habcdefghijklmnop end\n")
            .unwrap();
        h.flush().unwrap();
        let out = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
        assert_eq!(out, "leak: [REDACTED:usk:stripe] end\n");
        set_redactor(Scrubber::empty());
    }
}
