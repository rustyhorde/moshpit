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
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, CopyGetters, Debug, Default, Deserialize, Eq, PartialEq, Serialize, Setters)]
pub struct FileLayer {
    /// quiet level
    quiet: u8,
    /// verbose level
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
