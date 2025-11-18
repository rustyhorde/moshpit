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
    net::SocketAddr,
    path::PathBuf,
    process,
    sync::LazyLock,
    thread,
};

use ansi_control_codes::{
    c0, c1,
    parser::{Token, TokenStream},
};
use anyhow::{Context as _, Result};
use bytes::{Buf as _, BytesMut};
use clap::Parser as _;
use crossterm::terminal::{enable_raw_mode, window_size};
use libmoshpit::{
    EncryptedFrame, KexMode, KeyPair, MoshpitError, UdpReader, UdpSender, init_tracing, load,
    run_key_exchange,
};
use regex::Regex;
use tokio::{net::TcpStream, select, spawn, sync::mpsc::unbounded_channel};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, trace};

use crate::{cli::Cli, config::Config};

static CMD_LINE_EXIT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^133;C;cmdline_url=exit$").unwrap());
static EXIT_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^133;D;\d$").unwrap());

#[allow(clippy::too_many_lines)]
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

    // Setup the TCP connection to the server for key exchange
    let socket_addr = config
        .server_ip()
        .parse::<SocketAddr>()
        .with_context(|| MoshpitError::InvalidServerAddress)?;
    let socket = TcpStream::connect(socket_addr).await?;
    let (sock_read, sock_write) = socket.into_split();

    // Load the X25519 key pair from the configured paths or defaults
    let (default_private_key_path, default_pub_key_ext) =
        KeyPair::default_key_path_ext(KexMode::Client)?;
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

    // Run the key exchange
    let (kex, udp_arc) = run_key_exchange(
        KexMode::Client,
        sock_read,
        sock_write,
        private_key_path,
        public_key_path,
        || Ok(Some("test".to_string())),
    )
    .await?;
    info!("Key exchange completed with moshpits");

    // Setup the cancellation token
    let token = CancellationToken::new();

    let udp_recv = udp_arc.clone();
    let udp_send = udp_arc.clone();
    let (tx, rx) = unbounded_channel::<EncryptedFrame>();
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
        .rnk(kex.key())?
        .build();

    let sender_token = token.clone();
    let _udp_handle = spawn(async move {
        select! {
            () = sender_token.cancelled() => {
                trace!("UDP sender received cancellation");
                drop(udp_sender);
            }
            result = udp_sender.handle_frame() => {
                if let Err(e) = result {
                    error!("udp sender error {e}");
                }
            }
        }
    });

    let (columns, rows) = window_size().map_or((80, 24), |ws| (ws.columns, ws.rows));
    tx.send(EncryptedFrame::Resize((kex.uuid_wrapper(), columns, rows)))?;

    let (stdout_tx, mut stdout_rx) = unbounded_channel::<Vec<u8>>();

    let stdout_tx_c = stdout_tx.clone();
    let reader_token = token.clone();
    let _udp_reader_handle = spawn(async move {
        let mut prev_bytes = BytesMut::with_capacity(1024);
        let mut osc_started = false;
        let mut cmd_line_exit_detected = false;

        loop {
            select! {
                () = reader_token.cancelled() => {
                    trace!("UDP reader received cancellation");
                    process::exit(0);
                }
                frame_res = udp_reader.read_encrypted_frame() =>{
                    if let Ok(Some(frame)) = frame_res {
                        match frame {
                            EncryptedFrame::Resize(_) => {
                                error!("Received Resize frame on client, which is unexpected");
                            }
                            EncryptedFrame::Bytes((_id, message)) => {
                                let message = if prev_bytes.is_empty() {
                                    message
                                } else {
                                    let mut combined =
                                        BytesMut::with_capacity(prev_bytes.len() + message.len());
                                    combined.extend_from_slice(&prev_bytes);
                                    combined.extend_from_slice(&message);
                                    prev_bytes.clear();
                                    combined.freeze().to_vec()
                                };
                                prev_bytes.clear();
                                let mut valid_utf8 = String::new();
                                for chunk in message.utf8_chunks() {
                                    valid_utf8.push_str(chunk.valid());

                                    if !chunk.invalid().is_empty() {
                                        info!("Received invalid UTF-8 chunk");
                                        prev_bytes.extend_from_slice(chunk.invalid());
                                    }
                                }
                                let result = TokenStream::from(&valid_utf8).collect::<Vec<Token<'_>>>();

                                for part in &result {
                                    match part {
                                        Token::String(osc_cmd_string) => {
                                            if osc_started
                                                && cmd_line_exit_detected
                                                && EXIT_RE.is_match(osc_cmd_string)
                                            {
                                                reader_token.cancel();
                                                trace!(
                                                    "exit command detected in OSC sequence: {osc_cmd_string}"
                                                );
                                            } else if osc_started
                                                && CMD_LINE_EXIT_RE.is_match(osc_cmd_string)
                                            {
                                                cmd_line_exit_detected = true;
                                            }
                                        }
                                        Token::ControlFunction(control_function) => {
                                            if osc_started
                                                && (*control_function == c1::ST
                                                    || *control_function == c0::BEL)
                                            {
                                                osc_started = false;
                                            } else if *control_function == c1::OSC && !osc_started {
                                                osc_started = true;
                                            }
                                        }
                                    }
                                }
                                let _unused = stdout_tx_c.send(valid_utf8.into_bytes());
                            }
                        }
                    } else {
                        trace!("UDP reader received None frame, exiting");
                    }
                }
            }
        }
    });

    let _stdin_handle = thread::spawn(move || {
        let mut stdout = stdout();
        enable_raw_mode().unwrap();

        while let Some(msg) = stdout_rx.blocking_recv() {
            if msg.len() == 1 && msg[0] == b'q' {
                info!("Exiting stdout thread on 'q' input");
                break;
            }
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
        let mut buf = BytesMut::zeroed(8192);
        let len = stdin.read(&mut buf).unwrap();
        if len > 0 {
            if len == 1 && buf[0] == b'q' {
                info!("Exiting on 'q' input");
                stdout_tx.send(b"q".to_vec()).unwrap();
                break;
            }
            let msg = &buf[..len];
            tx.send(EncryptedFrame::Bytes((kex.uuid_wrapper(), msg.to_vec())))
                .unwrap();
            buf.advance(len);
        }
    }

    Ok(())
}
