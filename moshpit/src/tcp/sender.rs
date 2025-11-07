// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use anyhow::Result;
use bon::Builder;
use libmoshpit::{ConnectionWriter, Frame};
use tokio::sync::mpsc::UnboundedReceiver;

#[derive(Builder)]
pub(crate) struct FrameSender {
    writer: ConnectionWriter,
    rx: UnboundedReceiver<Frame>,
}

impl FrameSender {
    pub(crate) async fn handle_tx(&mut self) -> Result<()> {
        while let Some(frame) = self.rx.recv().await {
            self.writer.write_frame(&frame).await?;
        }
        Ok(())
    }
}
