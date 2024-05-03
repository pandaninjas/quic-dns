const VERSION: &str = env!("CARGO_PKG_VERSION");
const UA: &str = formatcp!(
    "quic-dns/{} (+https://github.com/pandaninjas/quic-dns)",
    VERSION
);
const ADDR: SocketAddr = V4(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 443));
const FROM_ADDR: SocketAddr = V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0));
use bytes::{Buf, Bytes, BytesMut};
use const_format::formatcp;
use h3::client::SendRequest;
use h3_quinn::quinn::Endpoint;
use h3_quinn::{Connection, OpenStreams};
use quinn::VarInt;
use std::error::Error;
use std::fmt::Debug;
use std::fmt::Display;
use std::future::{self};
use std::io::Read;
use std::io::{self, ErrorKind};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::net::{SocketAddr, SocketAddr::V4};
use std::ops::Mul;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::sleep;

struct DNSQuery {
    h3_request: http::Request<()>,
    buf: Bytes,
    respond_to: SocketAddr,
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

impl<T, E> UnwrapOrErr<T, NoValue> for Result<T, E> {
    #[inline]
    fn unwrap_or_err(self) -> Result<T, NoValue> {
        if let Ok(val) = self {
            Ok(val)
        } else {
            Err(NoValue {})
        }
    }
}

trait UnwrapOrIOErr<T> {
    fn unwrap_or_io_err(self) -> Result<T, std::io::Error>;
}

impl<T> UnwrapOrIOErr<T> for Option<T> {
    #[inline]
    fn unwrap_or_io_err(self) -> Result<T, std::io::Error> {
        if let Some(val) = self {
            Ok(val)
        } else {
            Err(std::io::Error::from(ErrorKind::NotFound))
        }
    }
}

impl<T, E> UnwrapOrIOErr<T> for Result<T, E> {
    #[inline]
    fn unwrap_or_io_err(self) -> Result<T, std::io::Error> {
        if let Ok(val) = self {
            Ok(val)
        } else {
            Err(std::io::Error::from(ErrorKind::NotFound))
        }
    }
}

fn start_quic_handler(
    mut is_dead_rx: oneshot::Receiver<bool>,
    mut rx: mpsc::Receiver<DNSQuery>,
    mut send_request: SendRequest<OpenStreams, Bytes>,
    response_socket: Arc<UdpSocket>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            let result: Result<(), Box<dyn Error>> = async {
                let mut stream = send_request.send_request(message.h3_request).await?;

                stream.send_data(message.buf).await?;

                stream.finish().await?;

                let resp = stream.recv_response().await?;

                let length: usize = resp
                    .headers()
                    .get("content-length")
                    .unwrap_or_err()?
                    .to_str()?
                    .parse()?;

                let mut resp_buffer: [u8; 512] = [0; 512];
                let mut read_total = 0;
                while let Some(chunk) = stream.recv_data().await? {
                    let read = chunk.reader().read(&mut resp_buffer[read_total..512])?;
                    read_total += read;
                }
                if read_total != length || length > 512 {
                    return Err::<(), Box<dyn Error>>(Box::new(MismatchLength {}));
                }

                response_socket
                    .send_to(&resp_buffer[0..length], message.respond_to)
                    .await?;
                // println!("finished processing for dns request");
                Ok(())
            }
            .await;
            if let Err(_e) = result {
                // println!("operation did not succeed: {}", e);
            }
            if is_dead_rx.try_recv().is_ok() {
                return;
            }
        }
    })
}

fn start_quic_driver(
    mut driver: h3::client::Connection<Connection, Bytes>,
    is_dead_tx: oneshot::Sender<bool>,
) {
    tokio::spawn(async move {
        let r = future::poll_fn(|cx| driver.poll_close(cx)).await;
        if let Err(_e) = r {
            // println!("driver died with error: {}", e);
        }
        let _ = is_dead_tx.send(true);
    });
}

fn create_cert_store() -> rustls::RootCertStore {
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
    roots
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let roots = create_cert_store();

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

    let tls_config = Arc::new(tls_config);

    let mut transport_config = quinn::TransportConfig::default();

    transport_config.max_idle_timeout(Some(VarInt::from_u32(10_000).into()));
    transport_config.keep_alive_interval(Some(Duration::from_secs(1)));

    let mut client_config = quinn::ClientConfig::new(tls_config.clone());
    let transport_config = Arc::new(transport_config);

    client_config.transport_config(transport_config.clone());

    let dns_sock = Arc::new(UdpSocket::bind("127.0.0.1:53").await?);

    let mut client_endpoint = Endpoint::client(FROM_ADDR).unwrap();
    client_endpoint.set_default_client_config(client_config);

    let connecting = client_endpoint.connect(ADDR, "1.1.1.1").unwrap();

    let quic = Connection::new(connecting.await?);
    let (driver, send_request) = h3::client::new(quic).await.unwrap();

    let (is_dead_tx, is_dead_rx) = oneshot::channel();

    start_quic_driver(driver, is_dead_tx);
    // println!("h3 connection to 1.1.1.1 established");

    let (mut tx, mut rx) = mpsc::channel::<DNSQuery>(128);

    let response_socket = dns_sock.clone();

    let mut quic_handler =
        start_quic_handler(is_dead_rx, rx, send_request, response_socket.clone());

    let mut backoff = Duration::from_millis(500);
    loop {
        let base_http_req = http::Request::builder()
            .method("POST")
            .uri("https://1.1.1.1/dns-query")
            .header("accept", "application/dns-message")
            .header("content-type", "application/dns-message")
            .header("user-agent", UA)
            .body(())
            .unwrap();

        if quic_handler.is_finished() {
            loop {
                let result: Result<(), io::Error> = {
                    let mut client_config = quinn::ClientConfig::new(tls_config.clone());
                    client_config.transport_config(transport_config.clone());

                    // connection must've died, revive it
                    let mut client_endpoint = Endpoint::client(FROM_ADDR).unwrap_or_io_err()?;
                    client_endpoint.set_default_client_config(client_config);

                    let connecting = client_endpoint
                        .connect(ADDR, "1.1.1.1")
                        .unwrap_or_io_err()?;

                    let quic: Connection = Connection::new(connecting.await?);

                    let (driver, send_request) = h3::client::new(quic).await.unwrap_or_io_err()?;

                    let (is_dead_tx, is_dead_rx) = oneshot::channel();

                    start_quic_driver(driver, is_dead_tx);
                    // println!("h3 connection to 1.1.1.1 established");

                    let channel = mpsc::channel::<DNSQuery>(128);
                    tx = channel.0;
                    rx = channel.1;

                    quic_handler =
                        start_quic_handler(is_dead_rx, rx, send_request, response_socket.clone());
                    Ok(())
                };

                if let Err(_) = result {
                    // println!("failed to reconnect, backing off for {}ms", backoff.as_millis());
                    // back off & retry
                    sleep(backoff).await;
                    backoff = backoff.mul(2);
                } else {
                    break;
                }
            }
        }
        let mut buf = BytesMut::with_capacity(512);
        if let Ok((len, addr)) = dns_sock.clone().recv_buf_from(&mut buf).await {
            let channel = tx.clone();

            tokio::spawn(async move {
                let mut request = base_http_req.clone();
                request
                    .headers_mut()
                    .insert("content-length", buf.len().into());

                buf.truncate(len);
                let buf = buf.freeze();
                let query = DNSQuery {
                    h3_request: request,
                    buf: buf,
                    respond_to: addr,
                };

                let _ = channel.send(query).await;
                // println!("sent query to h3 processor");
            });
        }
    }
}
