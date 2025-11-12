// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use anyhow::Result;
use bon::Builder;
use tokio::sync::mpsc::UnboundedReceiver;

use crate::{ConnectionWriter, Frame};

/// The key exchange sender for the moshpit
#[derive(Builder, Debug)]
pub struct KexSender {
    /// The connection writer
    writer: ConnectionWriter,
    /// The receiver for frames to send
    rx: UnboundedReceiver<Frame>,
}

impl KexSender {
    /// Handle sending frames
    ///
    /// # Errors
    ///
    /// * `write_frame` errors
    ///
    pub async fn handle_send_frames(&mut self) -> Result<()> {
        while let Some(frame) = self.rx.recv().await {
            self.writer.write_frame(&frame).await?;
        }
        Ok(())
    }
}
