// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::{ffi::OsString, net::SocketAddr, time::Duration};

use anyhow::{Context as _, Result};
use clap::Parser as _;
use libmoshpit::{Connection, Frame, MoshpitError, init_tracing, load};
use tokio::{net::TcpStream, time::sleep};
use tracing::{info, trace};

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

    // The `addr` argument is passed directly to `TcpStream::connect`. This
    // performs any asynchronous DNS lookup and attempts to establish the TCP
    // connection. An error at either step returns an error, which is then
    // bubbled up to the caller of `mini_redis` connect.
    let socket_addr = SocketAddr::new(
        config
            .mps()
            .ip()
            .parse()
            .with_context(|| MoshpitError::InvalidIpAddress)?,
        config.mps().port(),
    );
    let socket = TcpStream::connect(socket_addr).await?;

    info!("Connected to the server!");
    // Initialize the connection state. This allocates read/write buffers to
    // perform redis protocol frame parsing.
    let mut connection = Connection::new(socket);

    sleep(Duration::from_secs(3)).await;

    info!("Sending initialize frame...");
    let frame = Frame::initialize(b"Hello, Moshpit!".to_vec())?;
    connection.write_bytes(&frame).await?;

    sleep(Duration::from_secs(3)).await;
    info!("Sending initialize frame...");
    connection.write_bytes(&frame).await?;

    sleep(Duration::from_secs(3)).await;

    info!("Closing connection.");
    Ok(())
}
