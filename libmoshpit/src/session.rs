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

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::new_session_registry;

    #[test]
    fn new_session_registry_starts_empty() {
        let reg = new_session_registry();
        assert!(reg.blocking_lock().is_empty());
    }

    #[test]
    fn new_session_registry_insert_and_lookup() {
        let reg = new_session_registry();
        let uuid = Uuid::new_v4();
        drop(reg.blocking_lock().insert(uuid, "alice".to_owned()));
        assert!(reg.blocking_lock().contains_key(&uuid));
    }
}
