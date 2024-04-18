const VERSION: &str = env!("CARGO_PKG_VERSION");
const ADDR: SocketAddr = V4(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 443));
const FROM_ADDR: SocketAddr = V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0));

use std::error::Error;
use std::fmt::Display;
use std::future;
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;
use std::io;
use std::net::{SocketAddr, SocketAddr::V4};
use quinn::VarInt;
use tokio::sync::mpsc;
use tokio::net::UdpSocket;
use h3_quinn::quinn::Endpoint;
use bytes::{Buf, BytesMut};
use std::fmt::Debug;

trait SizedError: Error + Sized {}

struct DNSQuery {
    buf: BytesMut,
    respond_to: SocketAddr
}

struct MismatchLength {}

impl Error for MismatchLength {}

impl Display for MismatchLength {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "content-length does not match actual bytes read")
    }
}

impl Debug for MismatchLength {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MismatchLength").finish()
    }
}

struct NoValue {}

impl Error for NoValue {}

impl Display for NoValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "called unwrap_or_err on None")
    }
}

impl Debug for NoValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoValue").finish()
    }
}

trait UnwrapOrErr<T, E> {
    fn unwrap_or_err(self) -> Result<T, E>;
}

impl<T> UnwrapOrErr<T, NoValue> for Option<T> {
    #[inline]
    fn unwrap_or_err(self) -> Result<T, NoValue> {
        if let Some(val) = self {
            Ok(val)
        } else {
            Err(NoValue {})
        }
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let mut roots = rustls::RootCertStore::empty();
    match rustls_native_certs::load_native_certs() {
        Ok(certs) => {
            for cert in certs {
                if let Err(e) = roots.add(&rustls::Certificate(cert.0)) {
                    panic!("failed to parse trust anchor: {}", e);
                }
            }
        }
        Err(e) => {
            panic!("couldn't load any default trust roots: {}", e);
        }
    };

    let mut tls_config = rustls::ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();

    tls_config.enable_early_data = true;
    tls_config.alpn_protocols = vec!["h3".into()];

    tls_config.key_log = Arc::new(rustls::KeyLogFile::new());

    let mut transport_config = quinn::TransportConfig::default();

    transport_config.max_idle_timeout(Some(VarInt::from_u32(10_000).into()));
    transport_config.keep_alive_interval(Some(Duration::from_secs(1)));

    let mut client_config = quinn::ClientConfig::new(Arc::new(tls_config));
    client_config.transport_config(Arc::new(transport_config));

    let dns_sock = Arc::new(UdpSocket::bind("127.0.0.1:53").await?);



    let mut client_endpoint = Endpoint::client(FROM_ADDR).unwrap();
    client_endpoint.set_default_client_config(client_config);

    let quic = h3_quinn::Connection::new(client_endpoint.connect(ADDR, "1.1.1.1").unwrap().await?);
    let (mut driver, mut send_request) = h3::client::new(quic).await.unwrap();
    
    tokio::spawn(async move {
        let r = future::poll_fn(|cx| driver.poll_close(cx)).await;
        if let Err(e) = r {
            println!("death from driver: {}", e);
        }
        Ok::<(), Box<dyn std::error::Error + Send>>(())
    });
    println!("ready");

    let (tx, mut rx) = mpsc::channel::<DNSQuery>(32);

    let response_socket = dns_sock.clone();


    tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            let result: Result<(), Box<dyn Error>> = async {
                
                let req = http::Request::builder()
                    .method("POST")
                    .uri("https://1.1.1.1/dns-query")
                    .header("accept", "application/dns-message")
                    .header("content-type", "application/dns-message")
                    .header("content-length", format!("{}", message.buf.len()))
                    .header("user-agent", format!("quic-dns/{} (+https://github.com/pandaninjas/quic-dns)", VERSION))
                    .body(())?;
    
                let mut stream = send_request.send_request(req).await?;

                stream.send_data(message.buf.freeze()).await?;

                stream.finish().await?;
                
                let resp = stream.recv_response().await?;

                let length: usize = resp.headers().get("content-length").unwrap_or_err()?.to_str()?.parse()?;
                let mut resp_buffer: [u8; 512] = [0; 512];
                let mut read_total = 0;
                while let Some(chunk) = stream.recv_data().await? {
                    let read = chunk.reader().read(&mut resp_buffer)?;
                    read_total += read;
                }
                if read_total != length {
                    return Err::<(), Box<dyn Error>>(Box::new(MismatchLength {}))
                }
                response_socket.send_to(&resp_buffer[0..length], message.respond_to).await?;
                println!("done");
                Ok(())
            }.await;
            if let Err(e) = result {
                println!("oops: {}", e);
            }
        }
    });

    loop {
        let mut buf = BytesMut::with_capacity(512);
        if let Ok((len, addr)) = dns_sock.clone().recv_buf_from(&mut buf).await {
            let channel = tx.clone();

            tokio::spawn(async move {
                println!("started processing");
                buf.truncate(len);
                let query = DNSQuery {
                    buf: buf,
                    respond_to: addr
                };
                println!("sent");
                let _ = channel.send(query).await;
                Ok::<_, Box<dyn std::error::Error + Send>>(())
            });
        }
    }
}