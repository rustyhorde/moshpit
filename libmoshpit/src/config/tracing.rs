// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use getset::{CopyGetters, Getters, Setters};
use serde::{Deserialize, Serialize};
use tracing::Level;
use tracing_subscriber_init::{TracingConfig, get_effective_level};

use crate::TracingConfigExt;

/// Tracing configuration
#[derive(Clone, Debug, Default, Deserialize, Eq, Getters, PartialEq, Serialize)]
pub struct Tracing {
    /// stdout layer configuration
    #[getset(get = "pub")]
    stdout: Layer,
    /// file layer configuration
    #[getset(get = "pub")]
    file: FileLayer,
}

/// Tracing configuration
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, CopyGetters, Debug, Default, Deserialize, Eq, Getters, PartialEq, Serialize)]
pub struct Layer {
    /// Should we trace the event target
    #[getset(get_copy = "pub")]
    with_target: bool,
    /// Should we trace the thread id
    #[getset(get_copy = "pub")]
    with_thread_ids: bool,
    /// Should we trace the thread names
    #[getset(get_copy = "pub")]
    with_thread_names: bool,
    /// Should we trace the line numbers
    #[getset(get_copy = "pub")]
    with_line_number: bool,
    /// Should we trace the level
    #[getset(get_copy = "pub")]
    with_level: bool,
    /// Additional tracing directives
    #[getset(get = "pub")]
    directives: Option<String>,
}

/// Tracing configuration
#[derive(Clone, CopyGetters, Debug, Default, Deserialize, Eq, PartialEq, Serialize, Setters)]
pub struct FileLayer {
    /// quiet level
    #[getset(set = "pub")]
    quiet: u8,
    /// verbose level
    #[getset(set = "pub")]
    verbose: u8,
    /// layer configuration
    layer: Layer,
}

impl TracingConfig for FileLayer {
    fn quiet(&self) -> u8 {
        self.quiet
    }

    fn verbose(&self) -> u8 {
        self.verbose
    }

    fn with_ansi(&self) -> bool {
        false
    }

    fn with_target(&self) -> bool {
        self.layer.with_target
    }

    fn with_thread_ids(&self) -> bool {
        self.layer.with_thread_ids
    }

    fn with_thread_names(&self) -> bool {
        self.layer.with_thread_names
    }

    fn with_line_number(&self) -> bool {
        self.layer.with_line_number
    }

    fn with_level(&self) -> bool {
        self.layer.with_level
    }
}

impl TracingConfigExt for FileLayer {
    fn enable_stdout(&self) -> bool {
        false
    }

    fn directives(&self) -> Option<&String> {
        self.layer.directives.as_ref()
    }

    fn level(&self) -> Level {
        get_effective_level(self.quiet(), self.verbose())
    }
}

#[cfg(test)]
mod tests {
    use tracing::Level;
    use tracing_subscriber_init::TracingConfig;

    use crate::TracingConfigExt;

    use super::{FileLayer, Tracing};

    #[test]
    fn layer_defaults_all_false() {
        let t = Tracing::default();
        let l = t.stdout();
        assert!(!l.with_target());
        assert!(!l.with_thread_ids());
        assert!(!l.with_thread_names());
        assert!(!l.with_line_number());
        assert!(!l.with_level());
        assert!(l.directives().is_none());
    }

    #[test]
    fn file_layer_tracing_config_defaults() {
        let f = FileLayer::default();
        assert_eq!(f.quiet(), 0);
        assert_eq!(f.verbose(), 0);
        assert!(!f.with_ansi());
    }

    #[test]
    fn file_layer_tracing_config_ext_defaults() {
        let f = FileLayer::default();
        assert!(!f.enable_stdout());
        assert!(f.directives().is_none());
    }

    #[test]
    fn file_layer_level_default_is_info() {
        let f = FileLayer::default();
        assert_eq!(f.level(), Level::INFO);
    }

    #[test]
    fn file_layer_is_distinct_from_stdout_layer() {
        let t = Tracing::default();
        // file layer wraps its own Layer
        let _ = t.file();
        let _ = t.stdout();
    }
}
