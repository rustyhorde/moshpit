use std::net::SocketAddr;

use anyhow::Result;
use bytes::BytesMut;
use tokio::{
    io::BufWriter,
    net::{TcpListener, TcpStream},
    spawn,
};

#[derive(Debug)]
pub struct Connection {
    // The `TcpStream`. It is decorated with a `BufWriter`, which provides write
    // level buffering. The `BufWriter` implementation provided by Tokio is
    // sufficient for our needs.
    stream: BufWriter<TcpStream>,

    // The buffer for reading frames. Here we do manually buffer handling.
    // A more high level approach would be to use `tokio_util::codec`, and
    // implement your own codec for decoding and encoding frames.
    buffer: BytesMut,
}

impl Connection {
    pub fn new(socket: TcpStream) -> Self {
        Self {
            stream: BufWriter::new(socket),
            buffer: BytesMut::with_capacity(4096),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:8080").await?;

    match listener.accept().await {
        Ok((socket, addr)) => {
            let _unused = spawn(async move {
                let _connection = Connection::new(socket);
                println!("Accepted connection from {:?}", addr);
                // Handle the connection here
            });
        }
        Err(e) => println!("couldn't get client: {:?}", e),
    }

    Ok(())
}
