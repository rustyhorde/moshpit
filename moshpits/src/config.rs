// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use getset::{CopyGetters, Getters, Setters};
use libmoshpit::{Mps, Tracing, TracingConfigExt};
use serde::{Deserialize, Serialize};
use tracing::Level;
use tracing_subscriber_init::{TracingConfig, get_effective_level};

#[derive(
    Clone, CopyGetters, Debug, Default, Deserialize, Eq, Getters, PartialEq, Serialize, Setters,
)]
pub(crate) struct Config {
    #[getset(get_copy = "pub(crate)")]
    verbose: u8,
    #[getset(get_copy = "pub(crate)")]
    quiet: u8,
    #[getset(get_copy = "pub(crate)")]
    #[getset(set = "pub(crate)")]
    enable_std_output: bool,
    #[getset(get = "pub(crate)")]
    tracing: Tracing,
    #[getset(get = "pub(crate)")]
    mps: Mps,
}

impl TracingConfig for Config {
    fn quiet(&self) -> u8 {
        self.quiet
    }

    fn verbose(&self) -> u8 {
        self.verbose
    }

    fn with_target(&self) -> bool {
        self.tracing().stdout().with_target()
    }

    fn with_thread_ids(&self) -> bool {
        self.tracing().stdout().with_thread_ids()
    }

    fn with_thread_names(&self) -> bool {
        self.tracing().stdout().with_thread_names()
    }

    fn with_line_number(&self) -> bool {
        self.tracing().stdout().with_line_number()
    }

    fn with_level(&self) -> bool {
        self.tracing().stdout().with_level()
    }
}

impl TracingConfigExt for Config {
    fn enable_stdout(&self) -> bool {
        self.enable_std_output
    }

    fn directives(&self) -> Option<&String> {
        self.tracing().stdout().directives().as_ref()
    }

    fn level(&self) -> Level {
        get_effective_level(self.quiet(), self.verbose())
    }
}
