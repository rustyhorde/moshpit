// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use getset::{CopyGetters, Getters};
use serde::{Deserialize, Serialize};

/// Used in bartoc configuration to define the bartos instance to connect to
#[derive(Clone, CopyGetters, Debug, Default, Deserialize, Eq, Getters, PartialEq, Serialize)]
pub struct Mps {
    /// The mps IP address to listen for connections on
    #[getset(get = "pub")]
    ip: String,
    /// The mps port
    #[getset(get_copy = "pub")]
    port: u16,
}
