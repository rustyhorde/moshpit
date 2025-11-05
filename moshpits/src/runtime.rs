// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::{ffi::OsString, net::SocketAddr};

use anyhow::{Context as _, Result};
use clap::Parser as _;
use libmoshpit::{Connection, MoshpitError, init_tracing, load};
use tokio::{net::TcpListener, spawn};
use tracing::{error, info, trace};

use crate::{cli::Cli, config::Config};

pub(crate) async fn run<I, T>(args: Option<I>) -> Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    // Parse the command line
    let cli = if let Some(args) = args {
        Cli::try_parse_from(args)?
    } else {
        Cli::try_parse()?
    };

    // Load the configuration
    let config = load::<Cli, Config, Cli>(&cli, &cli).with_context(|| MoshpitError::ConfigLoad)?;

    // Initialize tracing
    init_tracing(&config, config.tracing().file(), &cli, None)
        .with_context(|| MoshpitError::TracingInit)?;

    trace!("Configuration loaded");
    trace!("Tracing initialized");

    let socket_addr = SocketAddr::new(
        config
            .mps()
            .ip()
            .parse()
            .with_context(|| MoshpitError::InvalidIpAddress)?,
        config.mps().port(),
    );
    let listener = TcpListener::bind(socket_addr).await?;

    loop {
        match listener.accept().await {
            Ok((socket, addr)) => {
                info!("Accepted connection from {addr}");
                let handler = Handler {
                    connection: Connection::new(socket),
                };
                // Spawn a new task to process the connections. Tokio tasks are like
                // asynchronous green threads and are executed concurrently.
                let _handle = spawn(async move {
                    // Process the connection. If an error is encountered, log it.
                    if let Err(err) = handler.handle_connection().await {
                        error!("connection error: {err:?} from {addr}");
                    }
                });
            }
            Err(e) => error!("couldn't get client: {e:?}"),
        }
    }
}

struct Handler {
    connection: Connection,
}

impl Handler {
    async fn handle_connection(mut self) -> Result<()> {
        loop {
            trace!("Waiting for frame...");
            if let Some(frame) = self.connection.read_frame().await? {
                trace!("Received frame: {frame}");
            } else {
                info!("Connection closed");
                break;
            }
        }
        Ok(())
    }
}
