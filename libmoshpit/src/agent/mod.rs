// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! moshpit agent protocol types and async Unix-socket client.

#[cfg(unix)]
pub mod client;
pub mod protocol;

#[cfg(unix)]
pub use self::client::AgentClient;
pub use self::protocol::{AgentIdentityInfo, AgentRequest, AgentResponse};
