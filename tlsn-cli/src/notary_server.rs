//! TLSNotary Remote Notary Server
//!
//! A WebSocket server that provides notarization services.
//! Clients connect via WebSocket and run the MPC-TLS protocol.

use std::{env, net::SocketAddr, path::PathBuf, sync::Arc};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};
use clap::Parser;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::accept_async;
use tracing::{error, info, warn};

use tlsn::{
    attestation::{
        signing::Secp256k1Signer,
        AttestationConfig, CryptoProvider,
    },
    config::verifier::VerifierConfig,
    transcript::ContentType,
    verifier::VerifierOutput,
    webpki::RootCertStore,
    Session,
};

/// Global traffic metrics
static TOTAL_BYTES_IN: AtomicU64 = AtomicU64::new(0);
static TOTAL_BYTES_OUT: AtomicU64 = AtomicU64::new(0);
static TOTAL_SESSIONS: AtomicU64 = AtomicU64::new(0);
static SUCCESSFUL_SESSIONS: AtomicU64 = AtomicU64::new(0);

#[derive(Parser)]
#[command(name = "notary-server")]
#[command(about = "TLSNotary Remote Notary Server")]
#[command(version)]
struct Args {
    /// Host to bind to
    #[arg(short = 'H', long, default_value = "0.0.0.0")]
    host: String,

    /// Port to listen on
    #[arg(short, long, default_value = "7047")]
    port: u16,

    /// Path to signing key file (32 bytes hex or raw)
    /// If not specified, uses NOTARY_SIGNING_KEY env var or generates ephemeral key
    #[arg(short, long)]
    signing_key: Option<PathBuf>,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Print metrics every N seconds (0 to disable)
    #[arg(long, default_value = "60")]
    metrics_interval: u64,
}

/// WebSocket to futures::AsyncRead/AsyncWrite adapter with traffic counting
mod ws_adapter {
    use std::io::{Error, ErrorKind};
    use std::pin::Pin;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::task::{Context, Poll};

    use bytes::BytesMut;
    use futures::{AsyncRead, AsyncWrite, Sink, SinkExt, Stream, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    /// Session traffic metrics
    #[derive(Default)]
    pub struct SessionMetrics {
        pub bytes_in: AtomicU64,
        pub bytes_out: AtomicU64,
    }

    pub struct WsAdapter<S> {
        inner: S,
        read_buf: BytesMut,
        metrics: Arc<SessionMetrics>,
        global_bytes_in: &'static AtomicU64,
        global_bytes_out: &'static AtomicU64,
    }

    impl<S: Unpin> Unpin for WsAdapter<S> {}

    impl<S> WsAdapter<S> {
        pub fn new(
            stream: S,
            global_bytes_in: &'static AtomicU64,
            global_bytes_out: &'static AtomicU64,
        ) -> (Self, Arc<SessionMetrics>) {
            let metrics = Arc::new(SessionMetrics::default());
            (
                Self {
                    inner: stream,
                    read_buf: BytesMut::new(),
                    metrics: Arc::clone(&metrics),
                    global_bytes_in,
                    global_bytes_out,
                },
                metrics,
            )
        }
    }

    impl<S> AsyncRead for WsAdapter<S>
    where
        S: Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
    {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<std::io::Result<usize>> {
            // If we have buffered data, return it first
            if !self.read_buf.is_empty() {
                let len = std::cmp::min(buf.len(), self.read_buf.len());
                buf[..len].copy_from_slice(&self.read_buf.split_to(len));
                return Poll::Ready(Ok(len));
            }

            // Try to read from WebSocket
            match self.inner.poll_next_unpin(cx) {
                Poll::Ready(Some(Ok(msg))) => {
                    match msg {
                        Message::Binary(data) => {
                            let data_len = data.len() as u64;
                            self.metrics.bytes_in.fetch_add(data_len, Ordering::Relaxed);
                            self.global_bytes_in.fetch_add(data_len, Ordering::Relaxed);

                            let len = std::cmp::min(buf.len(), data.len());
                            buf[..len].copy_from_slice(&data[..len]);
                            if len < data.len() {
                                self.read_buf.extend_from_slice(&data[len..]);
                            }
                            Poll::Ready(Ok(len))
                        }
                        Message::Close(_) => Poll::Ready(Ok(0)),
                        Message::Ping(_) | Message::Pong(_) | Message::Text(_) | Message::Frame(_) => {
                            cx.waker().wake_by_ref();
                            Poll::Pending
                        }
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    Poll::Ready(Err(Error::new(ErrorKind::Other, e)))
                }
                Poll::Ready(None) => Poll::Ready(Ok(0)),
                Poll::Pending => Poll::Pending,
            }
        }
    }

    impl<S> AsyncWrite for WsAdapter<S>
    where
        S: Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
    {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            // Track bytes
            let buf_len = buf.len() as u64;
            self.metrics.bytes_out.fetch_add(buf_len, Ordering::Relaxed);
            self.global_bytes_out.fetch_add(buf_len, Ordering::Relaxed);

            // Send immediately as binary message
            match self.inner.poll_ready_unpin(cx) {
                Poll::Ready(Ok(())) => {
                    match self.inner.start_send_unpin(Message::Binary(buf.to_vec().into())) {
                        Ok(()) => Poll::Ready(Ok(buf.len())),
                        Err(e) => Poll::Ready(Err(Error::new(ErrorKind::Other, e))),
                    }
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(Error::new(ErrorKind::Other, e))),
                Poll::Pending => Poll::Pending,
            }
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            match self.inner.poll_flush_unpin(cx) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
                Poll::Ready(Err(e)) => Poll::Ready(Err(Error::new(ErrorKind::Other, e))),
                Poll::Pending => Poll::Pending,
            }
        }

        fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            match self.inner.poll_close_unpin(cx) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
                Poll::Ready(Err(e)) => Poll::Ready(Err(Error::new(ErrorKind::Other, e))),
                Poll::Pending => Poll::Pending,
            }
        }
    }
}

use ws_adapter::{SessionMetrics, WsAdapter};

/// Format bytes as human readable
fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

/// Load signing key from file, environment, or generate ephemeral
fn load_signing_key(path: Option<&PathBuf>) -> Result<[u8; 32]> {
    // Try file first
    if let Some(path) = path {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read signing key from {:?}", path))?;
        let content = content.trim();

        // Try hex decoding
        if content.len() == 64 {
            let mut key = [0u8; 32];
            hex::decode_to_slice(content, &mut key)
                .context("Invalid hex in signing key file")?;
            return Ok(key);
        }

        // Try raw bytes
        let bytes = std::fs::read(path)?;
        if bytes.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            return Ok(key);
        }

        anyhow::bail!("Signing key must be 32 bytes (or 64 hex chars)");
    }

    // Try environment variable
    if let Ok(key_hex) = env::var("NOTARY_SIGNING_KEY") {
        let key_hex = key_hex.trim();
        if key_hex.len() == 64 {
            let mut key = [0u8; 32];
            hex::decode_to_slice(key_hex, &mut key)
                .context("Invalid hex in NOTARY_SIGNING_KEY")?;
            return Ok(key);
        }
        anyhow::bail!("NOTARY_SIGNING_KEY must be 64 hex characters");
    }

    // Generate ephemeral key (for testing only)
    warn!("No signing key provided - generating ephemeral key (NOT FOR PRODUCTION)");
    let mut key = [0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut key);
    Ok(key)
}

/// Handle a single notary session over WebSocket
async fn handle_session(
    stream: TcpStream,
    signing_key: Arc<[u8; 32]>,
    peer_addr: SocketAddr,
) -> Result<Arc<SessionMetrics>> {
    TOTAL_SESSIONS.fetch_add(1, Ordering::Relaxed);

    // Upgrade to WebSocket
    let ws_stream = accept_async(stream).await
        .context("WebSocket handshake failed")?;

    info!("[{}] Session started", peer_addr);

    // Wrap WebSocket in AsyncRead/AsyncWrite adapter with metrics
    let (adapter, metrics) = WsAdapter::new(ws_stream, &TOTAL_BYTES_IN, &TOTAL_BYTES_OUT);

    // Create session with prover
    let session = Session::new(adapter);
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    // Use Mozilla root certificates
    let root_store = RootCertStore::mozilla();

    let verifier_config = VerifierConfig::builder()
        .root_store(root_store)
        .build()?;

    // Run verifier
    let verifier = handle
        .new_verifier(verifier_config)?
        .commit()
        .await?
        .accept()
        .await?
        .run()
        .await?;

    let (
        VerifierOutput {
            transcript_commitments: _,
            ..
        },
        verifier,
    ) = verifier.verify().await?.accept().await?;

    let tls_transcript = verifier.tls_transcript().clone();
    verifier.close().await?;

    // Calculate sent/recv lengths from TLS transcript
    let sent_len = tls_transcript
        .sent()
        .iter()
        .filter_map(|record| {
            if let ContentType::ApplicationData = record.typ {
                Some(record.ciphertext.len())
            } else {
                None
            }
        })
        .sum::<usize>();

    let recv_len = tls_transcript
        .recv()
        .iter()
        .filter_map(|record| {
            if let ContentType::ApplicationData = record.typ {
                Some(record.ciphertext.len())
            } else {
                None
            }
        })
        .sum::<usize>();

    info!(
        "[{}] TLS data: {} sent, {} received",
        peer_addr,
        format_bytes(sent_len as u64),
        format_bytes(recv_len as u64)
    );

    // Create signing key and provider
    let signing_key_obj = k256::ecdsa::SigningKey::from_bytes(signing_key.as_ref().into())?;
    let signer = Box::new(Secp256k1Signer::new(&signing_key_obj.to_bytes())?);
    let mut provider = CryptoProvider::default();
    provider.signer.set_signer(signer);

    // Build attestation config (will be used when we implement full attestation flow)
    let _att_config = AttestationConfig::builder()
        .supported_signature_algs(Vec::from_iter(provider.signer.supported_algs()))
        .build()?;

    // The attestation request/response exchange happens through the session protocol
    // For the current tlsn API, this is handled internally by the verifier

    // Close session
    handle.close();
    driver_task.await??;

    SUCCESSFUL_SESSIONS.fetch_add(1, Ordering::Relaxed);

    let session_bytes_in = metrics.bytes_in.load(Ordering::Relaxed);
    let session_bytes_out = metrics.bytes_out.load(Ordering::Relaxed);

    info!(
        "[{}] Session completed - Traffic: {} in, {} out (total: {})",
        peer_addr,
        format_bytes(session_bytes_in),
        format_bytes(session_bytes_out),
        format_bytes(session_bytes_in + session_bytes_out)
    );

    Ok(metrics)
}

/// Print global metrics
fn print_metrics() {
    let total = TOTAL_SESSIONS.load(Ordering::Relaxed);
    let successful = SUCCESSFUL_SESSIONS.load(Ordering::Relaxed);
    let bytes_in = TOTAL_BYTES_IN.load(Ordering::Relaxed);
    let bytes_out = TOTAL_BYTES_OUT.load(Ordering::Relaxed);

    info!(
        "=== METRICS === Sessions: {}/{} successful | Traffic: {} in, {} out (total: {})",
        successful,
        total,
        format_bytes(bytes_in),
        format_bytes(bytes_out),
        format_bytes(bytes_in + bytes_out)
    );
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let filter = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter)),
        )
        .init();

    // Load signing key
    let signing_key = Arc::new(load_signing_key(args.signing_key.as_ref())?);

    // Print public key for verification
    let signing_key_obj = k256::ecdsa::SigningKey::from_bytes(signing_key.as_ref().into())?;
    let verifying_key = signing_key_obj.verifying_key();
    info!(
        "Notary public key: {}",
        hex::encode(verifying_key.to_encoded_point(true).as_bytes())
    );

    // Bind to address
    let addr = format!("{}:{}", args.host, args.port);
    let listener = TcpListener::bind(&addr).await?;
    info!("Notary server listening on ws://{}", addr);

    // Start metrics printer task
    if args.metrics_interval > 0 {
        let interval = args.metrics_interval;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval));
            loop {
                ticker.tick().await;
                print_metrics();
            }
        });
    }

    // Accept connections
    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let signing_key = Arc::clone(&signing_key);

                tokio::spawn(async move {
                    match handle_session(stream, signing_key, peer_addr).await {
                        Ok(_) => {}
                        Err(e) => {
                            error!("[{}] Session error: {}", peer_addr, e);
                        }
                    }
                });
            }
            Err(e) => {
                error!("Failed to accept connection: {}", e);
            }
        }
    }
}
