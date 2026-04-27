// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

/// A message for the moshpits psuedo-terminal
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TerminalMessage {
    /// A resize event
    Resize {
        /// Number of columns
        columns: u16,
        /// Number of rows
        rows: u16,
    },
    /// Input for the terminal
    Input(Vec<u8>),
}
