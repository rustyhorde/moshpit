// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::{
    ffi::OsString,
    io::{Read as _, Write as _},
    net::SocketAddr,
    path::PathBuf,
    process::Command,
    thread,
};

use anyhow::{Context as _, Result};
use bytes::{Buf as _, BytesMut};
use clap::Parser as _;
use libmoshpit::{
    EncryptedFrame, KexMode, KeyPair, MoshpitError, TerminalMessage, UdpReader, UdpSender,
    init_tracing, load, run_key_exchange,
};
use pseudoterminal::{CommandExt as _, TerminalSize};
use tokio::{
    net::{TcpListener, TcpStream},
    spawn,
    sync::mpsc::unbounded_channel,
};
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

    // Load the X25519 key pair from the configured paths or defaults
    let (default_private_key_path, default_pub_key_ext) =
        KeyPair::default_key_path_ext(KexMode::Server(socket_addr))?;
    let private_key_path = config
        .private_key_path()
        .as_ref()
        .map_or(default_private_key_path, PathBuf::from);
    let public_key_path = config.public_key_path().as_ref().map_or(
        private_key_path.with_extension(default_pub_key_ext),
        PathBuf::from,
    );
    trace!("Loading private key from {}", private_key_path.display());
    trace!("Loading public key from {}", public_key_path.display());

    loop {
        match listener.accept().await {
            Ok((socket, _addr)) => {
                if let Err(e) = handle_connection(
                    socket,
                    socket_addr,
                    private_key_path.clone(),
                    public_key_path.clone(),
                )
                .await
                {
                    error!("error handling connection: {e}");
                }
            }
            Err(e) => error!("couldn't get client: {e:?}"),
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn handle_connection(
    socket: TcpStream,
    socket_addr: SocketAddr,
    private_key_path: PathBuf,
    public_key_path: PathBuf,
) -> Result<()> {
    let (sock_read, sock_write) = socket.into_split();
    let (kex, udp_arc) = run_key_exchange(
        KexMode::Server(socket_addr),
        sock_read,
        sock_write,
        private_key_path,
        public_key_path,
        || Ok(None),
    )
    .await?;
    info!("Key exchange completed with moshpit");
    let (tx, rx) = unbounded_channel::<EncryptedFrame>();
    let udp_recv = udp_arc.clone();
    let udp_send = udp_arc.clone();
    let (term_tx, mut term_rx) = unbounded_channel::<TerminalMessage>();
    let mut udp_reader = UdpReader::builder()
        .socket(udp_recv)
        .id(kex.uuid())
        .hmac(kex.hmac_key())
        .rnk(kex.key())
        .unwrap()
        .build();
    let mut udp_sender = UdpSender::builder()
        .socket(udp_send)
        .rx(rx)
        .id(kex.uuid())
        .hmac(kex.hmac_key())
        .rnk(kex.key())
        .unwrap()
        .build();

    let _udp_reader_handle = spawn(async move {
        while let Ok(frame_opt) = udp_reader.read_encrypted_frame().await {
            if let Some(frame) = frame_opt {
                match frame {
                    EncryptedFrame::Bytes((_id, message)) => {
                        term_tx.send(TerminalMessage::Input(message)).unwrap();
                    }
                    EncryptedFrame::Resize((_id, columns, rows)) => {
                        term_tx
                            .send(TerminalMessage::Resize { rows, columns })
                            .unwrap();
                    }
                }
            }
        }
    });

    let _udp_handle = spawn(async move {
        if let Err(e) = udp_sender.handle_frame().await {
            error!("udp sender error {e}");
        }
    });

    let _term_handle = thread::spawn(move || {
        let mut cmd = Command::new("/usr/bin/fish");
        let _ = cmd.arg("-li");
        let mut terminal = cmd.spawn_terminal().unwrap();
        if let Some((mut term_in, mut term_out)) = terminal.split() {
            let _in_handle = thread::spawn(move || {
                while let Some(terminal_message) = term_rx.blocking_recv() {
                    match terminal_message {
                        TerminalMessage::Resize { columns, rows } => {
                            if let Err(e) = terminal.set_term_size(TerminalSize { rows, columns }) {
                                error!("error resizing terminal: {e}");
                            }
                        }
                        TerminalMessage::Input(data) => {
                            if let Err(e) = term_in.write_all(&data) {
                                error!("error writing to terminal: {e}");
                                break;
                            }
                        }
                    }
                }
                info!("Terminal input handler exiting");
            });

            loop {
                let mut buffer = BytesMut::zeroed(4096);
                match term_out.read(&mut buffer) {
                    Ok(0) => {
                        trace!("read 0 bytes from terminal, exiting");
                        break;
                    }
                    Ok(n) => {
                        let frame =
                            EncryptedFrame::Bytes((kex.uuid_wrapper(), buffer[..n].to_vec()));
                        if let Err(e) = tx.send(frame) {
                            error!("error sending udp packet: {e}");
                            break;
                        }
                        buffer.advance(n);
                    }
                    Err(e) => {
                        error!("error reading from terminal: {e}");
                        break;
                    }
                }
            }
            info!("Terminal output handler exiting");
        }
    });
    Ok(())
}
