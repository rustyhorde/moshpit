// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::{collections::HashMap, sync::Arc};

use tokio::sync::Mutex;
use uuid::Uuid;

/// Minimal session registry used during key exchange.
///
/// Maps session UUID → username. This lightweight registry lives in libmoshpit so the
/// key-exchange layer can validate resume requests without depending on higher-level
/// session state (channels, scrollback, etc.) that lives in the server binary.
pub type SessionRegistry = Arc<Mutex<HashMap<Uuid, String>>>;

/// Create a new, empty [`SessionRegistry`].
#[must_use]
pub fn new_session_registry() -> SessionRegistry {
    Arc::new(Mutex::new(HashMap::new()))
}
