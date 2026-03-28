// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::{
    ffi::OsString,
    io::{Read as _, Write as _, stdin, stdout},
    thread,
};

use anyhow::{Context as _, Result};
use clap::Parser as _;
use crossterm::terminal::enable_raw_mode;
use dialoguer::Password;
use libmoshpit::{
    EncryptedFrame, Kex, MoshpitError, UdpReader, UdpSender, init_tracing, load,
    parse_server_destination, run_key_exchange,
};
use terminal_size::terminal_size;
use tokio::{
    net::TcpStream,
    signal::unix::{SignalKind, signal},
    spawn,
    sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
};
use tokio_util::sync::CancellationToken;
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
    let mut config =
        load::<Cli, Config, Cli>(&cli, &cli).with_context(|| MoshpitError::ConfigLoad)?;

    // Initialize tracing
    init_tracing(&config, config.tracing().file(), &cli, None)
        .with_context(|| MoshpitError::TracingInit)?;

    trace!("Configuration loaded");
    trace!("Tracing initialized");

    // Setup the TCP connection to the server for key exchange
    let (user, socket_addr) =
        parse_server_destination(config.server_destination(), config.server_port())?;
    let _ = config.set_user(user);
    trace!("Connecting to server at {socket_addr}");
    let socket = TcpStream::connect(socket_addr).await?;
    let remote_addr = socket.peer_addr()?;
    info!("Connected to server at {remote_addr}");
    let (sock_read, sock_write) = socket.into_split();

    // Run the key exchange
    let (kex, udp_arc, _skex_opt) =
        run_key_exchange(config, sock_read, sock_write, read_passpharase).await?;
    info!("Key exchange completed with moshpits");

    // Setup the cancellation token
    let token = CancellationToken::new();

    let udp_recv = udp_arc.clone();
    let udp_send = udp_arc.clone();
    let (tx, rx) = unbounded_channel::<EncryptedFrame>();
    let (retransmit_tx, retransmit_rx) = unbounded_channel::<Vec<u64>>();
    let mut udp_reader = UdpReader::builder()
        .socket(udp_recv)
        .id(kex.uuid())
        .hmac(kex.hmac_key())
        .rnk(kex.key())
        .unwrap()
        .nak_out_tx(tx.clone())
        .retransmit_tx(retransmit_tx)
        .build();
    let mut udp_sender = UdpSender::builder()
        .socket(udp_send)
        .rx(rx)
        .retransmit_rx(retransmit_rx)
        .id(kex.uuid())
        .hmac(kex.hmac_key())
        .rnk(kex.key())?
        .build();

    let sender_token = token.clone();
    let _udp_handle = spawn(async move { udp_sender.frame_loop(sender_token).await });

    let (columns, rows) = terminal_size().map_or((80, 24), |(width, height)| (width.0, height.0));
    tx.send(EncryptedFrame::Resize((kex.uuid_wrapper(), columns, rows)))?;

    let (stdout_tx, stdout_rx) = unbounded_channel::<Vec<u8>>();

    let stdout_tx_c = stdout_tx.clone();
    let reader_token = token.clone();
    let _udp_reader_handle = spawn(async move {
        udp_reader
            .client_frame_loop(reader_token, stdout_tx_c)
            .await;
    });

    let resize_tx = tx.clone();
    let resize_uuid = kex.uuid_wrapper();
    let resize_token = token.clone();
    let _resize_handle = spawn(async move {
        match signal(SignalKind::window_change()) {
            Ok(mut sigwinch) => loop {
                tokio::select! {
                    () = resize_token.cancelled() => break,
                    _ = sigwinch.recv() => {
                        let (columns, rows) = terminal_size()
                            .map_or((80, 24), |(width, height)| (width.0, height.0));
                        if let Err(e) =
                            resize_tx.send(EncryptedFrame::Resize((resize_uuid, columns, rows)))
                        {
                            error!("Failed to send resize frame: {e}");
                            break;
                        }
                    }
                }
            },
            Err(e) => error!("Failed to register SIGWINCH handler: {e}"),
        }
    });

    handle_io(stdout_rx, &tx, &kex)?;
    Ok(())
}

fn handle_io(
    mut stdout_rx: UnboundedReceiver<Vec<u8>>,
    tx: &UnboundedSender<EncryptedFrame>,
    kex: &Kex,
) -> Result<()> {
    enable_raw_mode()?;

    let _stdout_handle = thread::spawn(move || {
        let mut stdout = stdout();

        while let Some(msg) = stdout_rx.blocking_recv() {
            if let Err(e) = stdout.write_all(&msg) {
                error!("Error writing to stdout: {e}");
            }
            if let Err(e) = stdout.flush() {
                error!("Error flushing stdout: {e}");
            }
        }
    });

    let mut stdin = stdin();
    loop {
        let mut buf = [0u8; 4096];
        let len = stdin.read(&mut buf)?;
        if len > 0 {
            let msg = &buf[..len];
            if let Err(e) = tx.send(EncryptedFrame::Bytes((kex.uuid_wrapper(), msg.to_vec()))) {
                error!("{e}");
            }
        }
    }
}

fn read_passpharase() -> Result<Option<String>> {
    Password::new()
        .with_prompt("Please enter your private key passphrase")
        .with_confirmation(
            "Confirm the passphrase",
            "The entered passphrases do not match",
        )
        .report(false)
        .interact()
        .map(Some)
        .map_err(Into::into)
}
