// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::{
    collections::BTreeSet,
    ffi::OsString,
    io::{Read as _, Write as _},
    net::SocketAddr,
    path::PathBuf,
    process::Command,
    sync::Arc,
    thread,
};

use anyhow::{Context as _, Result};
use bytes::{Buf as _, BytesMut};
use clap::Parser as _;
use libmoshpit::{
    EncryptedFrame, KexMode, KeyPair, MoshpitError, TerminalMessage, UdpReader, UdpSender,
    init_tracing, is_exit_title, load, run_key_exchange,
};
use pseudoterminal::{CommandExt as _, TerminalSize};
use tokio::{
    net::{TcpListener, TcpStream},
    spawn,
    sync::{Mutex, mpsc::unbounded_channel},
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

    let mut port_pool = BTreeSet::new();
    for i in 50000..60000 {
        let _ = port_pool.insert(i);
    }
    let port_pool_arc = Arc::new(Mutex::new(port_pool));

    loop {
        let port_pool_c = port_pool_arc.clone();
        match listener.accept().await {
            Ok((socket, _addr)) => {
                if let Err(e) = handle_connection(
                    socket,
                    socket_addr,
                    port_pool_c,
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
    port_pool: Arc<Mutex<BTreeSet<u16>>>,
    private_key_path: PathBuf,
    public_key_path: PathBuf,
) -> Result<()> {
    let (sock_read, sock_write) = socket.into_split();
    let port_pool_c = port_pool.clone();
    let (kex, udp_arc) = run_key_exchange(
        KexMode::Server(socket_addr),
        sock_read,
        sock_write,
        Some(port_pool_c),
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
        .rnk(kex.key())?
        .build();
    let mut udp_sender = UdpSender::builder()
        .socket(udp_send)
        .rx(rx)
        .id(kex.uuid())
        .hmac(kex.hmac_key())
        .rnk(kex.key())?
        .build();

    let token = CancellationToken::new();
    let reader_token = token.clone();
    let term_tx_c = term_tx.clone();
    let _udp_reader_handle = spawn(async move {
        if let Err(e) = udp_reader.server_frame_loop(reader_token, term_tx_c).await {
            error!("{e}");
        }
    });

    let sender_token = token.clone();
    let _udp_handle = spawn(async move { udp_sender.frame_loop(sender_token).await });

    let (tx_pool, mut rx_pool) = unbounded_channel();
    let _port_handler = spawn(async move {
        if let Some(port) = rx_pool.recv().await {
            let mut pool = port_pool.lock().await;
            let _ = pool.insert(port);
            trace!("Port {port} returned to pool");
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
                        let buf = buffer[..n].to_vec();
                        let utf8_buf = String::from_utf8_lossy(&buf);
                        let frame = EncryptedFrame::Bytes((kex.uuid_wrapper(), buf.clone()));
                        if let Err(e) = tx.send(frame) {
                            error!("error sending udp packet: {e}");
                            break;
                        }
                        if is_exit_title(&utf8_buf, true) {
                            trace!("exit title detected, exiting");
                            token.cancel();
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
            if let Ok(local_addr) = udp_arc.local_addr() {
                let _ = tx_pool.send(local_addr.port());
            }
            info!("Terminal output handler exiting");
        }
    });
    Ok(())
}
