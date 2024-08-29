const VERSION: &str = env!("CARGO_PKG_VERSION");
const UA: &str = formatcp!(
    "quic-dns/{} (+https://github.com/pandaninjas/quic-dns)",
    VERSION
);
const ADDR: SocketAddr = V4(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 443));
const FROM_ADDR: SocketAddr = V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0));

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use bytes::{Buf, Bytes, BytesMut};
use const_format::formatcp;
use fast_log::{Config, Receiver};
use h3::client::SendRequest;
use h3_quinn::quinn::Endpoint;
use h3_quinn::{Connection, OpenStreams};

use quinn::rustls;

use log::{error, info};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{TransportConfig, VarInt};
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
use tokio::sync::{mpsc, oneshot, Mutex};
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

async fn handle_message(
    message: DNSQuery,
    send_request: Arc<Mutex<&mut SendRequest<OpenStreams, Bytes>>>,
    response_socket: &Arc<UdpSocket>,
) -> Result<(), Box<dyn Error>> {
    let mut send_request = send_request.lock().await;
    let mut stream = send_request.send_request(message.h3_request).await?;
    std::mem::drop(send_request);

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
    info!("finished processing for dns request");
    Ok(())
}

fn start_quic_driver(
    mut driver: h3::client::Connection<Connection, Bytes>,
    is_dead_tx: oneshot::Sender<()>,
) {
    tokio::spawn(async move {
        let r = future::poll_fn(|cx| driver.poll_close(cx)).await;
        if let Err(e) = r {
            error!("driver died with error: {e}");
        }
        let _ = is_dead_tx.send(());
    });
}

fn create_cert_store() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    match rustls_native_certs::load_native_certs() {
        Ok(certs) => {
            for cert in certs {
                if let Err(e) = roots.add(cert) {
                    error!("failed to parse trust anchor: {}", e);
                }
            }
        }
        Err(e) => {
            error!("couldn't load any default trust roots: {}", e);
        }
    };
    roots
}

async fn try_connect_quad1(
    tls_config: &Arc<QuicClientConfig>,
    transport_config: &Arc<TransportConfig>,
) -> Result<
    (
        oneshot::Receiver<()>,
        Arc<Mutex<&'static mut SendRequest<OpenStreams, Bytes>>>,
    ),
    io::Error,
> {
    let mut client_config = quinn::ClientConfig::new(tls_config.clone());
    client_config.transport_config(transport_config.clone());

    // connection must've died, revive it
    let mut client_endpoint = Endpoint::client(FROM_ADDR).unwrap_or_io_err()?;
    client_endpoint.set_default_client_config(client_config);

    let connection = client_endpoint
        .connect(ADDR, "1.1.1.1")
        .unwrap_or_io_err()?
        .into_0rtt();

    let quic = match connection {
        Ok(parts) => Connection::new(parts.0),
        Err(result) => Connection::new(result.await?),
    };

    let (driver, send_request) = h3::client::new(quic).await.unwrap_or_io_err()?;

    let send_request = Arc::new(Mutex::new(Box::leak(Box::new(send_request))));

    let (is_dead_tx, is_dead_rx) = oneshot::channel();

    start_quic_driver(driver, is_dead_tx);

    Ok((is_dead_rx, send_request))
}

async fn connect_quad1(
    tls_config: &Arc<QuicClientConfig>,
    transport_config: &Arc<TransportConfig>,
) -> (
    oneshot::Receiver<()>,
    Arc<Mutex<&'static mut SendRequest<OpenStreams, Bytes>>>,
) {
    let mut backoff = Duration::from_millis(500);
    loop {
        let result: Result<
            (
                oneshot::Receiver<()>,
                Arc<Mutex<&'static mut SendRequest<h3_quinn::OpenStreams, bytes::Bytes>>>,
            ),
            io::Error,
        > = try_connect_quad1(&tls_config, &transport_config).await;

        match result {
            Ok((is_dead_rx, send_request)) => {
                return (is_dead_rx, send_request);
            }
            Err(err) => {
                error!(
                    "failed to reconnect due to {}, backing off for {}ms",
                    err,
                    backoff.as_millis()
                );
                // back off & retry
                sleep(backoff).await;
                if backoff < Duration::from_millis(30_000) {
                    backoff = backoff.mul(2);
                }
            }
        }
    }
}

#[tokio::main]
async fn main() {
    fast_log::init(
        Config::new()
            .console()
            .chan_len(Some(100000 /* 100K */))
            .level(log::LevelFilter::Info),
    )
    .unwrap();

    let roots = create_cert_store();

    let mut tls_config = quinn::rustls::ClientConfig::builder()
        .with_root_certificates(Arc::new(roots))
        .with_no_client_auth();

    tls_config.enable_early_data = true;
    tls_config.alpn_protocols = vec!["h3".into()];

    let tls_config = QuicClientConfig::try_from(tls_config).unwrap();

    let tls_config = Arc::new(tls_config);

    let mut transport_config = quinn::TransportConfig::default();

    transport_config.max_idle_timeout(Some(VarInt::from_u32(10_000).into()));
    transport_config.keep_alive_interval(Some(Duration::from_secs(1)));

    let mut client_config = quinn::ClientConfig::new(tls_config.clone());
    let transport_config = Arc::new(transport_config);

    client_config.transport_config(transport_config.clone());

    let dns_sock = Arc::new(
        UdpSocket::bind("127.0.0.1:53")
            .await
            .expect("couldn't bind to 127.0.0.1:53"),
    );

    let connection = connect_quad1(&tls_config, &transport_config).await;

    let mut is_dead_rx: oneshot::Receiver<()> = connection.0;
    let mut send_request: Arc<
        Mutex<&'static mut SendRequest<h3_quinn::OpenStreams, bytes::Bytes>>,
    > = connection.1;

    info!("h3 connection to 1.1.1.1 established");

    let base_http_req = http::Request::builder()
        .method("POST")
        .uri("https://1.1.1.1/dns-query")
        .header("accept", "application/dns-message")
        .header("content-type", "application/dns-message")
        .header("user-agent", UA)
        .body(())
        .unwrap();

    loop {
        if is_dead_rx.try_recv().is_ok() {
            let connection = connect_quad1(&tls_config, &transport_config).await;
            is_dead_rx = connection.0;
            send_request = connection.1;
        }
        let mut buf = BytesMut::with_capacity(512);

        if let Ok((len, addr)) = dns_sock.clone().recv_buf_from(&mut buf).await {
            let req = base_http_req.clone();
            let sock = dns_sock.clone();
            let send_request_copy = send_request.clone();
            tokio::spawn(async move {
                let mut request = req;
                request
                    .headers_mut()
                    .insert("content-length", buf.len().into());

                buf.truncate(len);
                let buf = buf.freeze();
                if let Err(e) = handle_message(
                    DNSQuery {
                        h3_request: request,
                        buf,
                        respond_to: addr,
                    },
                    send_request_copy,
                    &sock,
                )
                .await
                {
                    error!("operation did not succeed: {e}");
                }
            });
        }
    }
}
