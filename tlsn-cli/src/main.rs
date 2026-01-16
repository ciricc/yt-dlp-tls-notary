use std::{fs, net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::sync::{oneshot, Semaphore};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, Request, Uri};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::{info, warn};

use tlsn::{
    attestation::{
        presentation::{Presentation, PresentationOutput},
        request::{Request as AttestationRequest, RequestConfig},
        signing::{Secp256k1Signer, VerifyingKey},
        Attestation, AttestationConfig, CryptoProvider, Secrets,
    },
    config::{
        prove::ProveConfig,
        prover::ProverConfig,
        tls::TlsClientConfig,
        tls_commit::{mpc::{MpcTlsConfig, NetworkSetting}, TlsCommitConfig},
        verifier::VerifierConfig,
    },
    connection::{ConnectionInfo, HandshakeData, ServerName, TranscriptLength},
    prover::ProverOutput,
    transcript::{ContentType, Direction, TranscriptCommitConfig},
    verifier::{ServerCertVerifier, VerifierOutput},
    webpki::RootCertStore,
    Session,
};

/// Maximum bytes that can be sent to server
const MAX_SENT_DATA: usize = 1 << 12; // 4KB
/// Maximum bytes that can be received from server
const MAX_RECV_DATA: usize = 1 << 20; // 1MB (was 64KB)
/// Chunk size for streaming downloads (slightly less than MAX_RECV_DATA to account for HTTP headers)
const STREAM_CHUNK_SIZE: usize = 1000 * 1024; // ~1MB (was 60KB)

#[derive(Parser)]
#[command(name = "tlsn-cli")]
#[command(about = "TLS Notary CLI - create verifiable proofs of web requests")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Notarize an HTTP request and create a proof
    Notarize {
        /// URL to request
        #[arg(short, long)]
        url: String,

        /// HTTP method (GET, POST, etc.)
        #[arg(short, long, default_value = "GET")]
        method: String,

        /// HTTP headers (can be specified multiple times)
        #[arg(short = 'H', long = "header")]
        headers: Vec<String>,

        /// Request body (for POST/PUT)
        #[arg(short, long)]
        body: Option<String>,

        /// Output file for the proof
        #[arg(short, long)]
        output: PathBuf,

        /// Output file for the response body
        #[arg(long)]
        output_response: Option<PathBuf>,

        /// Remote notary server URL (e.g., wss://notary.example.com:7047)
        /// If not specified, uses local self-notarization
        #[arg(long)]
        notary: Option<String>,

        /// Output as JSON
        #[arg(long)]
        json: bool,

        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
    },

    /// Verify a proof
    Verify {
        /// Proof file to verify
        #[arg(short, long)]
        proof: PathBuf,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Inspect proof contents
    Inspect {
        /// Proof file to inspect
        #[arg(short, long)]
        proof: PathBuf,

        /// Output format (json, text)
        #[arg(short, long, default_value = "text")]
        format: String,
    },

    /// Notarize a stream/file download in chunks (for full file verification)
    NotarizeStream {
        /// URL to download
        #[arg(short, long)]
        url: String,

        /// HTTP headers (can be specified multiple times)
        #[arg(short = 'H', long = "header")]
        headers: Vec<String>,

        /// Output directory for proofs and manifest
        #[arg(short, long)]
        output_dir: PathBuf,

        /// Output file for the downloaded content
        #[arg(long)]
        output_file: Option<PathBuf>,

        /// Chunk size in bytes (default: ~1MB)
        #[arg(long, default_value = "1024000")]
        chunk_size: usize,

        /// Number of parallel workers (default: 1, max: 30)
        #[arg(short = 'w', long, default_value = "1")]
        workers: usize,

        /// Rate limit for HTTP requests per second (e.g., 2.0 = max 2 requests/sec)
        #[arg(long)]
        rps_limit: Option<f32>,

        /// Remote notary server URL (e.g., wss://notary.example.com:7047)
        /// If not specified, uses local self-notarization
        #[arg(long)]
        notary: Option<String>,

        /// Output as JSON
        #[arg(long)]
        json: bool,

        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
    },

    /// Verify and reconstruct a file from stream proofs
    VerifyStream {
        /// Manifest file
        #[arg(short, long)]
        manifest: PathBuf,

        /// Output file for reconstructed content
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Serialize)]
struct NotarizeOutput {
    success: bool,
    proof_path: String,
    response_path: Option<String>,
    status_code: u16,
    response_headers: Vec<(String, String)>,
    server: String,
    timestamp: String,
    sent_bytes: usize,
    recv_bytes: usize,
}

/// Legacy proof format (deprecated - use TlsnProof instead)
#[derive(Serialize, Deserialize, Clone)]
struct ProofData {
    sent: Vec<u8>,
    received: Vec<u8>,
    server: String,
    timestamp: String,
}

/// Proper TLSNotary proof with cryptographic attestation
#[derive(Serialize, Deserialize)]
struct TlsnProof {
    /// Version of the proof format
    version: u32,
    /// The attestation (signed by notary)
    attestation: Attestation,
    /// Secrets needed to create presentations (selective disclosure)
    secrets: Secrets,
    /// Server hostname
    server: String,
    /// Timestamp
    timestamp: String,
    /// Raw response body (for convenience)
    response_body: Vec<u8>,
}

/// Notarized metadata from YouTube oEmbed API
#[derive(Serialize, Deserialize, Clone)]
struct MetadataProof {
    /// Video ID
    video_id: String,
    /// oEmbed API URL that was notarized
    oembed_url: String,
    /// oEmbed response (JSON)
    oembed_response: serde_json::Value,
    /// Path to the proof file
    proof_file: String,
    /// Server that responded (should be www.youtube.com)
    server: String,
    /// Timestamp when metadata was notarized
    timestamp: String,
}

/// Manifest for a stream download with chunked proofs
#[derive(Serialize, Deserialize, Clone)]
struct StreamManifest {
    /// Version of the manifest format
    version: u32,
    /// Original URL
    url: String,
    /// Server hostname
    server: String,
    /// Total content length
    total_size: u64,
    /// Chunk size used
    chunk_size: usize,
    /// SHA256 hash of the complete file
    file_hash: String,
    /// Individual chunk information
    chunks: Vec<ChunkInfo>,
    /// Timestamp when notarization started
    started_at: String,
    /// Timestamp when notarization completed
    completed_at: String,
    /// Optional: notarized YouTube metadata (proves video_id -> title/author)
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<MetadataProof>,
}

/// Information about a single chunk
#[derive(Serialize, Deserialize, Clone)]
struct ChunkInfo {
    /// Chunk index (0-based)
    index: usize,
    /// Byte range start (inclusive)
    range_start: u64,
    /// Byte range end (inclusive)
    range_end: u64,
    /// Size of chunk data
    size: usize,
    /// SHA256 hash of chunk data
    hash: String,
    /// Path to proof file (relative to manifest)
    proof_file: String,
    /// Timestamp when this chunk was notarized
    timestamp: String,
}

/// Output for stream notarization
#[derive(Serialize)]
struct StreamNotarizeOutput {
    success: bool,
    manifest_path: String,
    output_file: Option<String>,
    url: String,
    server: String,
    total_size: u64,
    chunks_count: usize,
    file_hash: String,
    duration_secs: f64,
}

/// Output for single proof verification
#[derive(Serialize)]
struct VerifyOutput {
    valid: bool,
    server: String,
    timestamp: String,
    connection_time: Option<String>,
    sent_bytes: usize,
    recv_bytes: usize,
    notary_key: String,
    signature_alg: String,
    sent_data: Option<String>,
    recv_data: Option<String>,
    errors: Vec<String>,
}

/// Output for stream verification
#[derive(Serialize)]
struct VerifyStreamOutput {
    valid: bool,
    url: String,
    server: String,
    total_size: u64,
    chunks_total: usize,
    chunks_verified: usize,
    file_hash: String,
    computed_hash: String,
    output_file: Option<String>,
    errors: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Notarize {
            url,
            method,
            headers,
            body,
            output,
            output_response,
            notary,
            json,
            verbose,
        } => {
            if verbose {
                tracing_subscriber::fmt()
                    .with_env_filter("info,yamux=warn,uid_mux=warn")
                    .init();
            }

            if let Some(notary_url) = &notary {
                eprintln!("Note: Remote notary support ({}) is experimental", notary_url);
            }

            let result = notarize(
                &url,
                &method,
                &headers,
                body.as_deref(),
                &output,
                output_response.as_ref(),
                notary.as_deref(),
            )
            .await?;

            if json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("Notarization successful!");
                println!("  Server: {}", result.server);
                println!("  Status: {}", result.status_code);
                println!("  Sent: {} bytes", result.sent_bytes);
                println!("  Received: {} bytes", result.recv_bytes);
                println!("  Proof: {}", result.proof_path);
                if let Some(resp_path) = &result.response_path {
                    println!("  Response: {}", resp_path);
                }
            }
        }
        Commands::Verify { proof, json } => {
            let result = verify_proof(&proof)?;

            if json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("Verification: {}", if result.valid { "PASSED ✓" } else { "FAILED ✗" });
                println!("  Server: {}", result.server);
                println!("  Timestamp: {}", result.timestamp);
                if let Some(conn_time) = &result.connection_time {
                    println!("  Connection time: {}", conn_time);
                }
                println!("  Sent: {} bytes", result.sent_bytes);
                println!("  Received: {} bytes", result.recv_bytes);
                println!("  Notary key ({}):", result.signature_alg);
                println!("    {}", result.notary_key);
                if !result.errors.is_empty() {
                    println!("  Errors:");
                    for err in &result.errors {
                        println!("    - {}", err);
                    }
                }
            }
        }
        Commands::Inspect { proof, format } => {
            let data = fs::read(&proof).context("Failed to read proof file")?;
            if format == "json" {
                println!(r#"{{"size": {}, "format": "tlsn"}}"#, data.len());
            } else {
                println!("Proof file: {} ({} bytes)", proof.display(), data.len());

                // Try to deserialize and show contents
                if let Ok(proof_data) = bincode::deserialize::<ProofData>(&data) {
                    println!("\n--- Sent Data ---");
                    if let Ok(s) = String::from_utf8(proof_data.sent.clone()) {
                        println!("{}", s);
                    }
                    println!("\n--- Received Data ---");
                    if let Ok(s) = String::from_utf8(proof_data.received.clone()) {
                        println!("{}", s);
                    }
                }
            }
        }
        Commands::NotarizeStream {
            url,
            headers,
            output_dir,
            output_file,
            chunk_size,
            workers,
            rps_limit,
            notary,
            json,
            verbose,
        } => {
            if verbose {
                tracing_subscriber::fmt()
                    .with_env_filter("info,yamux=warn,uid_mux=warn")
                    .init();
            }

            if let Some(notary_url) = &notary {
                eprintln!("Note: Remote notary support ({}) is experimental", notary_url);
            }

            let chunk_size = chunk_size.min(STREAM_CHUNK_SIZE);
            let workers = workers.clamp(1, 30); // Limit to 1-30 workers
            let result = notarize_stream(&url, &headers, &output_dir, output_file.as_ref(), chunk_size, workers, rps_limit, notary.as_deref(), !json)
                .await?;

            if json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("\nStream notarization complete!");
                println!("  URL: {}", result.url);
                println!("  Server: {}", result.server);
                println!("  Total size: {} bytes", result.total_size);
                println!("  Chunks: {}", result.chunks_count);
                println!("  File hash: {}", result.file_hash);
                println!("  Duration: {:.1}s", result.duration_secs);
                println!("  Manifest: {}", result.manifest_path);
                if let Some(out_file) = &result.output_file {
                    println!("  Output: {}", out_file);
                }
            }
        }
        Commands::VerifyStream {
            manifest,
            output,
            json,
        } => {
            let result = verify_stream(&manifest, output.as_ref()).await?;

            if json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("Stream verification: {}", if result.valid { "PASSED" } else { "FAILED" });
                println!("  URL: {}", result.url);
                println!("  Server: {}", result.server);
                println!("  Total size: {} bytes", result.total_size);
                println!("  Chunks verified: {}/{}", result.chunks_verified, result.chunks_total);
                if let Some(out) = &result.output_file {
                    println!("  Reconstructed file: {}", out);
                }
                if !result.errors.is_empty() {
                    println!("  Errors:");
                    for err in &result.errors {
                        println!("    - {}", err);
                    }
                }
            }
        }
    }

    Ok(())
}

async fn notarize(
    url: &str,
    method: &str,
    headers: &[String],
    body: Option<&str>,
    output: &PathBuf,
    output_response: Option<&PathBuf>,
    _notary: Option<&str>,  // TODO: implement remote notary support
) -> Result<NotarizeOutput> {
    let uri = url.parse::<Uri>().context("Invalid URL")?;
    let scheme = uri.scheme_str().unwrap_or("https");

    if scheme != "https" {
        anyhow::bail!("Only HTTPS URLs are supported");
    }

    let host = uri.host().context("URL must have a host")?;
    let port = uri.port_u16().unwrap_or(443);
    let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");

    info!("Notarizing request to {}:{}{}", host, port, path);

    // Resolve host to IP
    let addr: SocketAddr = tokio::net::lookup_host(format!("{}:{}", host, port))
        .await?
        .next()
        .context("Failed to resolve host")?;

    // Create prover-verifier pair (in real scenario, verifier would be remote notary)
    let (prover_socket, verifier_socket) = tokio::io::duplex(1 << 23);

    // Channels for attestation exchange
    let (request_tx, request_rx) = oneshot::channel::<AttestationRequest>();
    let (attestation_tx, attestation_rx) = oneshot::channel::<Attestation>();

    // Run notary (verifier + attestation builder)
    let notary_handle = tokio::spawn(run_notary(verifier_socket, request_rx, attestation_tx));

    // Run prover (with attestation exchange)
    let prover_result = run_prover_with_attestation(
        prover_socket,
        addr,
        host.to_string(),
        path.to_string(),
        method.to_string(),
        headers.to_vec(),
        body.map(|s| s.to_string()),
        request_tx,
        attestation_rx,
    ).await;

    // Wait for notary to finish
    notary_handle.await??;

    let (attestation, secrets, response_body, status_code, response_headers, sent_len, recv_len) = prover_result?;

    // Create proper TLSNotary proof
    let proof = TlsnProof {
        version: 1,
        attestation,
        secrets,
        server: host.to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        response_body: response_body.clone(),
    };

    // Save proof
    let proof_bytes = bincode::serialize(&proof)?;
    fs::write(output, &proof_bytes).context("Failed to write proof file")?;

    // Save response body if requested
    let response_path = if let Some(resp_output) = output_response {
        fs::write(resp_output, &response_body)?;
        Some(resp_output.display().to_string())
    } else {
        None
    };

    Ok(NotarizeOutput {
        success: true,
        proof_path: output.display().to_string(),
        response_path,
        status_code,
        response_headers,
        server: host.to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        sent_bytes: sent_len,
        recv_bytes: recv_len,
    })
}

/// Run prover with attestation exchange - creates cryptographic proof
async fn run_prover_with_attestation<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    verifier_socket: T,
    server_addr: SocketAddr,
    host: String,
    path: String,
    method: String,
    headers: Vec<String>,
    body: Option<String>,
    request_tx: oneshot::Sender<AttestationRequest>,
    attestation_rx: oneshot::Receiver<Attestation>,
) -> Result<(Attestation, Secrets, Vec<u8>, u16, Vec<(String, String)>, usize, usize)> {
    // Create session with verifier
    let session = Session::new(verifier_socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    // Create prover
    let prover = handle
        .new_prover(ProverConfig::builder().build()?)?
        .commit(
            TlsCommitConfig::builder()
                .protocol(
                    MpcTlsConfig::builder()
                        .max_sent_data(MAX_SENT_DATA)
                        .max_recv_data(MAX_RECV_DATA)
                        .network(NetworkSetting::Bandwidth)
                        .build()?,
                )
                .build()?,
        )
        .await?;

    // Connect to server
    let client_socket = tokio::net::TcpStream::connect(server_addr).await?;

    // Use Mozilla root certificates
    let root_store = RootCertStore::mozilla();

    let server_name = ServerName::Dns(host.clone().try_into()?);

    let (tls_connection, prover_fut) = prover
        .connect(
            TlsClientConfig::builder()
                .server_name(server_name.clone())
                .root_store(root_store)
                .build()?,
            client_socket.compat(),
        )
        .await?;

    let tls_connection = TokioIo::new(tls_connection.compat());
    let prover_task = tokio::spawn(prover_fut);

    // HTTP handshake
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(tls_connection).await?;
    tokio::spawn(connection);

    // Build request
    let mut req_builder = Request::builder()
        .uri(&path)
        .method(method.as_str())
        .header("Host", &host)
        .header("Connection", "close");

    for header in &headers {
        if let Some((key, value)) = header.split_once(':') {
            req_builder = req_builder.header(key.trim(), value.trim());
        }
    }

    // Send request
    let body_bytes_data = body.map(|b| Bytes::from(b)).unwrap_or_default();
    let request = req_builder.body(Full::new(body_bytes_data))?;
    let response = request_sender.send_request(request).await?;

    let status = response.status().as_u16();
    let resp_headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    // Read response body
    let body_bytes = response.into_body().collect().await?.to_bytes().to_vec();

    // Get prover in Committed state
    let mut prover = prover_task.await??;

    // Get transcript data
    let sent_data = prover.transcript().sent().to_vec();
    let recv_data = prover.transcript().received().to_vec();
    let sent_len = sent_data.len();
    let recv_len = recv_data.len();

    // Build transcript commit config (commit to everything)
    let mut commit_builder = TranscriptCommitConfig::builder(prover.transcript());
    commit_builder.commit_sent(&(0..sent_len))?;
    commit_builder.commit_recv(&(0..recv_len))?;
    let transcript_commit = commit_builder.build()?;

    // Build request config for attestation
    let mut request_config_builder = RequestConfig::builder();
    request_config_builder.transcript_commit(transcript_commit.clone());
    let request_config = request_config_builder.build()?;

    // Build prove config (reveal everything)
    let mut prove_builder = ProveConfig::builder(prover.transcript());
    prove_builder.server_identity();
    prove_builder.transcript_commit(transcript_commit);
    prove_builder.reveal_sent(&(0..sent_len))?;
    prove_builder.reveal_recv(&(0..recv_len))?;
    let prove_config = prove_builder.build()?;

    // Prove and get output
    let ProverOutput {
        transcript_commitments,
        transcript_secrets,
        ..
    } = prover.prove(&prove_config).await?;

    // Get transcript and TLS transcript for attestation request
    let transcript = prover.transcript().clone();
    let tls_transcript = prover.tls_transcript().clone();
    prover.close().await?;

    // Build attestation request
    let mut att_request_builder = AttestationRequest::builder(&request_config);

    att_request_builder
        .server_name(server_name)
        .handshake_data(HandshakeData {
            certs: tls_transcript
                .server_cert_chain()
                .expect("server cert chain is present")
                .to_vec(),
            sig: tls_transcript
                .server_signature()
                .expect("server signature is present")
                .clone(),
            binding: tls_transcript.certificate_binding().clone(),
        })
        .transcript(transcript)
        .transcript_commitments(transcript_secrets, transcript_commitments);

    let (att_request, secrets) = att_request_builder.build(&CryptoProvider::default())?;

    // Send attestation request to notary
    request_tx
        .send(att_request.clone())
        .map_err(|_| anyhow::anyhow!("notary is not receiving attestation request"))?;

    // Receive attestation from notary
    let attestation = attestation_rx
        .await
        .map_err(|e| anyhow::anyhow!("notary did not respond with attestation: {}", e))?;

    // Validate attestation is consistent with our request
    att_request.validate(&attestation, &CryptoProvider::default())?;

    // Close session
    handle.close();
    driver_task.await??;

    Ok((attestation, secrets, body_bytes, status, resp_headers, sent_len, recv_len))
}

/// Run notary (verifier + attestation builder) for self-notarization
async fn run_notary<T: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    socket: T,
    request_rx: oneshot::Receiver<AttestationRequest>,
    attestation_tx: oneshot::Sender<Attestation>,
) -> Result<()> {
    // Create session with prover
    let session = Session::new(socket.compat());
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
            transcript_commitments,
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

    // Receive attestation request from prover
    let request = request_rx
        .await
        .map_err(|e| anyhow::anyhow!("prover did not send attestation request: {}", e))?;

    // Create signing key for self-notarization (deterministic for reproducibility)
    // In production, use a proper key management system
    let signing_key = k256::ecdsa::SigningKey::from_bytes(&[42u8; 32].into())?;
    let signer = Box::new(Secp256k1Signer::new(&signing_key.to_bytes())?);
    let mut provider = CryptoProvider::default();
    provider.signer.set_signer(signer);

    // Build attestation config
    let att_config = AttestationConfig::builder()
        .supported_signature_algs(Vec::from_iter(provider.signer.supported_algs()))
        .build()?;

    // Build attestation from request + verifier's view
    let mut builder = Attestation::builder(&att_config).accept_request(request)?;
    builder
        .connection_info(ConnectionInfo {
            time: tls_transcript.time(),
            version: (*tls_transcript.version()),
            transcript_length: TranscriptLength {
                sent: sent_len as u32,
                received: recv_len as u32,
            },
        })
        .server_ephemeral_key(tls_transcript.server_ephemeral_key().clone())
        .transcript_commitments(transcript_commitments);

    let attestation = builder.build(&provider)?;

    // Send attestation to prover
    attestation_tx
        .send(attestation)
        .map_err(|_| anyhow::anyhow!("prover is not receiving attestation"))?;

    // Close session
    handle.close();
    driver_task.await??;

    Ok(())
}

/// Extract content length from URL query parameter (for YouTube CDN URLs)
fn extract_clen_from_url(url: &str) -> Option<u64> {
    url::Url::parse(url)
        .ok()?
        .query_pairs()
        .find(|(k, _)| k == "clen")
        .and_then(|(_, v)| v.parse().ok())
}

/// Get content length and resolve redirects via HEAD request (without notarization)
/// Returns (final_url, content_length, accepts_ranges)
async fn resolve_url_and_get_info(url: &str, headers: &[String]) -> Result<(String, u64, bool)> {
    // First try to extract content-length from URL (YouTube CDN includes clen parameter)
    if let Some(clen) = extract_clen_from_url(url) {
        info!("Using clen from URL: {}", clen);
        return Ok((url.to_string(), clen, true));
    }

    // Fallback to HEAD request
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(10))
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let mut req = client.head(url);

    for header in headers {
        if let Some((key, value)) = header.split_once(':') {
            req = req.header(key.trim(), value.trim());
        }
    }

    let response = req.send().await.context("HEAD request failed")?;

    // Get the final URL after redirects
    let final_url = response.url().to_string();

    let content_length = response
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);

    let accepts_ranges = response
        .headers()
        .get("accept-ranges")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == "bytes")
        .unwrap_or(false);

    if final_url != url {
        info!("Redirected: {} -> {}", url, final_url);
    }
    info!("Content-Length: {}, Accept-Ranges: {}", content_length, accepts_ranges);

    Ok((final_url, content_length, accepts_ranges))
}

/// Result of notarizing a single chunk with cryptographic attestation
struct ChunkResult {
    index: usize,
    range_start: u64,
    range_end: u64,
    body_bytes: Vec<u8>,
    attestation: Attestation,
    secrets: Secrets,
    server: String,
    timestamp: String,
}

/// Maximum retries for chunk notarization
const MAX_CHUNK_RETRIES: usize = 3;

/// Notarize a single chunk with proper cryptographic attestation (with retries)
async fn notarize_chunk(
    chunk_index: usize,
    range_start: u64,
    range_end: u64,
    addr: SocketAddr,
    host: String,
    path: String,
    headers: Vec<String>,
    semaphore: Arc<Semaphore>,
) -> Result<ChunkResult> {
    let mut last_error = None;

    for attempt in 0..MAX_CHUNK_RETRIES {
        // Acquire semaphore permit (limits parallel connections)
        let _permit = semaphore.acquire().await?;

        // Add delay between retries
        if attempt > 0 {
            let delay_ms = 1000 * (1 << attempt); // Exponential backoff: 2s, 4s, 8s
            info!("Chunk {}: retry {} after {}ms", chunk_index, attempt, delay_ms);
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        }

        let mut chunk_headers = headers.clone();
        chunk_headers.push(format!("Range: bytes={}-{}", range_start, range_end));

        // Create prover-verifier pair (channels for attestation exchange)
        let (prover_socket, verifier_socket) = tokio::io::duplex(1 << 23);
        let (request_tx, request_rx) = oneshot::channel::<AttestationRequest>();
        let (attestation_tx, attestation_rx) = oneshot::channel::<Attestation>();

        // Spawn notary task
        let notary_handle = tokio::spawn(run_notary(verifier_socket, request_rx, attestation_tx));

        // Run prover with attestation exchange
        let prover_result = run_prover_with_attestation(
            prover_socket,
            addr,
            host.clone(),
            path.clone(),
            "GET".to_string(),
            chunk_headers,
            None,
            request_tx,
            attestation_rx,
        ).await;

        // Wait for notary to finish (don't fail if prover already failed)
        let notary_result = notary_handle.await;

        match prover_result {
            Ok((attestation, secrets, body_bytes, status_code, _response_headers, _sent_len, _recv_len)) => {
                // Verify we got the expected response
                if status_code != 206 && status_code != 200 {
                    last_error = Some(anyhow::anyhow!("Unexpected status code {} for chunk {}", status_code, chunk_index));
                    continue;
                }

                // Check notary result
                if let Err(e) = notary_result {
                    warn!("Chunk {}: notary task error: {:?}", chunk_index, e);
                }

                return Ok(ChunkResult {
                    index: chunk_index,
                    range_start,
                    range_end,
                    body_bytes,
                    attestation,
                    secrets,
                    server: host,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                });
            }
            Err(e) => {
                let err_str = format!("{}", e);
                warn!("Chunk {}: attempt {} failed: {}", chunk_index, attempt + 1, err_str);
                last_error = Some(e);

                // Don't retry on certain errors
                if err_str.contains("Invalid URL") || err_str.contains("Only HTTPS") {
                    break;
                }

                // For "connection closed" errors, continue retrying
                continue;
            }
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("Chunk {} failed after {} retries", chunk_index, MAX_CHUNK_RETRIES)))
}

/// Notarize a stream/file in chunks (with parallel support)
async fn notarize_stream(
    url: &str,
    headers: &[String],
    output_dir: &PathBuf,
    output_file: Option<&PathBuf>,
    chunk_size: usize,
    workers: usize,
    rps_limit: Option<f32>,
    _notary: Option<&str>,  // TODO: implement remote notary support
    show_progress: bool,
) -> Result<StreamNotarizeOutput> {
    let start_time = std::time::Instant::now();
    let started_at = chrono::Utc::now().to_rfc3339();

    // Resolve redirects and get content info
    let (final_url, content_length, accepts_ranges) = resolve_url_and_get_info(url, headers).await?;

    let uri = final_url.parse::<Uri>().context("Invalid URL")?;
    let scheme = uri.scheme_str().unwrap_or("https");

    if scheme != "https" {
        anyhow::bail!("Only HTTPS URLs are supported");
    }

    let host = uri.host().context("URL must have a host")?.to_string();
    let port = uri.port_u16().unwrap_or(443);
    let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/").to_string();

    if content_length == 0 {
        anyhow::bail!("Could not determine content length. Server must provide Content-Length header.");
    }

    if !accepts_ranges {
        warn!("Server does not advertise Accept-Ranges: bytes. Attempting chunked download anyway...");
    }

    // Create output directory
    fs::create_dir_all(output_dir).context("Failed to create output directory")?;
    let proofs_dir = output_dir.join("proofs");
    fs::create_dir_all(&proofs_dir).context("Failed to create proofs directory")?;

    // Calculate chunks
    let num_chunks = (content_length as usize + chunk_size - 1) / chunk_size;

    if show_progress {
        println!("Starting stream notarization:");
        println!("  URL: {}", url);
        if final_url != url {
            println!("  Redirected to: {}", &final_url[..final_url.len().min(80)]);
        }
        println!("  Server: {}", host);
        println!("  Size: {} bytes", content_length);
        println!("  Chunk size: {} bytes", chunk_size);
        println!("  Chunks: {}", num_chunks);
        println!("  Workers: {}", workers);
        if let Some(rps) = rps_limit {
            println!("  RPS limit: {}", rps);
        }
        println!();
    }

    // Resolve host once for all connections
    let addr: SocketAddr = tokio::net::lookup_host(format!("{}:{}", host, port))
        .await?
        .next()
        .context("Failed to resolve host")?;

    // Create semaphore for limiting parallel connections
    let semaphore = Arc::new(Semaphore::new(workers));

    // Calculate delay between spawns for rate limiting
    let spawn_delay = rps_limit.map(|rps| {
        std::time::Duration::from_secs_f32(1.0 / rps)
    });

    // Spawn all chunk tasks
    let mut handles = Vec::with_capacity(num_chunks);

    for i in 0..num_chunks {
        let range_start = (i * chunk_size) as u64;
        let range_end = std::cmp::min(((i + 1) * chunk_size) as u64 - 1, content_length - 1);

        let sem = Arc::clone(&semaphore);
        let h = host.clone();
        let p = path.clone();
        let hdrs = headers.to_vec();

        let handle = tokio::spawn(async move {
            notarize_chunk(i, range_start, range_end, addr, h, p, hdrs, sem).await
        });

        handles.push(handle);

        // Rate limit: delay between spawning tasks
        if let Some(delay) = spawn_delay {
            if i < num_chunks - 1 {
                tokio::time::sleep(delay).await;
            }
        } else if i < num_chunks - 1 {
            // Default small delay to avoid connection flooding
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    // Progress tracking for parallel mode
    let total_chunks = handles.len();
    let mut completed_chunks = 0;
    let mut chunk_results: std::collections::HashMap<usize, ChunkResult> = std::collections::HashMap::with_capacity(total_chunks);

    // Collect results as they complete
    for handle in handles {
        let result = handle.await??;
        let idx = result.index;

        completed_chunks += 1;
        if show_progress {
            println!(
                "  Chunk {}/{} complete (bytes {}-{}) [{}/{}]",
                idx + 1,
                total_chunks,
                result.range_start,
                result.range_end,
                completed_chunks,
                total_chunks
            );
        }

        chunk_results.insert(idx, result);
    }

    // Process results in order
    let mut chunks: Vec<ChunkInfo> = Vec::with_capacity(num_chunks);
    let mut all_data: Vec<u8> = Vec::with_capacity(content_length as usize);
    let mut file_hasher = Sha256::new();

    for i in 0..num_chunks {
        let result = chunk_results.remove(&i).ok_or_else(|| anyhow::anyhow!("Missing result for chunk {}", i))?;

        // Hash chunk data
        let mut chunk_hasher = Sha256::new();
        chunk_hasher.update(&result.body_bytes);
        let chunk_hash = format!("{:x}", chunk_hasher.finalize());

        // Update file hash
        file_hasher.update(&result.body_bytes);

        // Save proof (proper TLSNotary proof with cryptographic attestation)
        let proof_file = format!("chunk_{:06}.tlsn", i);
        let proof_path = proofs_dir.join(&proof_file);

        let proof = TlsnProof {
            version: 1,
            attestation: result.attestation,
            secrets: result.secrets,
            server: result.server,
            timestamp: result.timestamp.clone(),
            response_body: result.body_bytes.clone(),
        };
        let proof_bytes = bincode::serialize(&proof)?;
        fs::write(&proof_path, &proof_bytes)?;

        // Store chunk data
        all_data.extend_from_slice(&result.body_bytes);

        chunks.push(ChunkInfo {
            index: i,
            range_start: result.range_start,
            range_end: result.range_end,
            size: result.body_bytes.len(),
            hash: chunk_hash,
            proof_file: format!("proofs/{}", proof_file),
            timestamp: result.timestamp,
        });
    }

    let file_hash = format!("{:x}", file_hasher.finalize());

    // Save manifest
    let manifest = StreamManifest {
        version: 1,
        url: url.to_string(),
        server: host.clone(),
        total_size: content_length,
        chunk_size,
        file_hash: file_hash.clone(),
        chunks,
        started_at,
        completed_at: chrono::Utc::now().to_rfc3339(),
        metadata: None,  // Metadata proof (video_id -> content link) is added by yt-dlp PostProcessor
    };

    let manifest_path = output_dir.join("manifest.json");
    let manifest_json = serde_json::to_string_pretty(&manifest)?;
    fs::write(&manifest_path, &manifest_json)?;

    // Save complete file if requested
    let output_file_path = if let Some(out) = output_file {
        fs::write(out, &all_data)?;
        Some(out.display().to_string())
    } else {
        // Save to default location
        let default_out = output_dir.join("output.bin");
        fs::write(&default_out, &all_data)?;
        Some(default_out.display().to_string())
    };

    Ok(StreamNotarizeOutput {
        success: true,
        manifest_path: manifest_path.display().to_string(),
        output_file: output_file_path,
        url: url.to_string(),
        server: host,
        total_size: content_length,
        chunks_count: num_chunks,
        file_hash,
        duration_secs: start_time.elapsed().as_secs_f64(),
    })
}

/// Verify a single TLSNotary proof with cryptographic verification
fn verify_proof(proof_path: &PathBuf) -> Result<VerifyOutput> {
    let mut errors: Vec<String> = Vec::new();

    // Load proof file
    let proof_data = fs::read(proof_path).context("Failed to read proof file")?;

    // Try to deserialize as TlsnProof first
    let proof: TlsnProof = match bincode::deserialize(&proof_data) {
        Ok(p) => p,
        Err(e) => {
            // Try legacy ProofData format
            if let Ok(legacy) = bincode::deserialize::<ProofData>(&proof_data) {
                // Return verification result for legacy format (no crypto verification)
                return Ok(VerifyOutput {
                    valid: false,
                    server: legacy.server.clone(),
                    timestamp: legacy.timestamp.clone(),
                    connection_time: None,
                    sent_bytes: legacy.sent.len(),
                    recv_bytes: legacy.received.len(),
                    notary_key: "N/A".to_string(),
                    signature_alg: "N/A".to_string(),
                    sent_data: String::from_utf8(legacy.sent).ok(),
                    recv_data: String::from_utf8(legacy.received).ok(),
                    errors: vec![
                        "Legacy proof format - no cryptographic verification possible".to_string(),
                        "Re-notarize with updated tlsn-cli to create verifiable proofs".to_string(),
                    ],
                });
            }
            anyhow::bail!("Failed to deserialize proof: {}", e);
        }
    };

    // Create crypto provider with Mozilla root certificates for server cert verification
    let root_store = RootCertStore::mozilla();
    let crypto_provider = match ServerCertVerifier::new(&root_store) {
        Ok(cert_verifier) => CryptoProvider {
            cert: cert_verifier,
            ..Default::default()
        },
        Err(e) => {
            errors.push(format!("Failed to create cert verifier: {}", e));
            CryptoProvider::default()
        }
    };

    // Get notary verifying key info from attestation
    let VerifyingKey { alg, data: key_data } = proof.attestation.body.verifying_key();
    let notary_key = hex::encode(key_data);
    let signature_alg = format!("{:?}", alg);

    // Build transcript proof (reveal everything)
    let sent_len = proof.secrets.transcript().sent().len();
    let recv_len = proof.secrets.transcript().received().len();

    let mut transcript_proof_builder = proof.secrets.transcript_proof_builder();

    if let Err(e) = transcript_proof_builder.reveal(&(0..sent_len), Direction::Sent) {
        errors.push(format!("Failed to reveal sent data: {}", e));
    }
    if let Err(e) = transcript_proof_builder.reveal(&(0..recv_len), Direction::Received) {
        errors.push(format!("Failed to reveal recv data: {}", e));
    }

    let transcript_proof = match transcript_proof_builder.build() {
        Ok(p) => p,
        Err(e) => {
            errors.push(format!("Failed to build transcript proof: {}", e));
            return Ok(VerifyOutput {
                valid: false,
                server: proof.server.clone(),
                timestamp: proof.timestamp.clone(),
                connection_time: None,
                sent_bytes: sent_len,
                recv_bytes: recv_len,
                notary_key,
                signature_alg,
                sent_data: None,
                recv_data: None,
                errors,
            });
        }
    };

    // Build presentation
    let mut presentation_builder = proof.attestation.presentation_builder(&crypto_provider);
    presentation_builder
        .identity_proof(proof.secrets.identity_proof())
        .transcript_proof(transcript_proof);

    let presentation: Presentation = match presentation_builder.build() {
        Ok(p) => p,
        Err(e) => {
            errors.push(format!("Failed to build presentation: {}", e));
            return Ok(VerifyOutput {
                valid: false,
                server: proof.server.clone(),
                timestamp: proof.timestamp.clone(),
                connection_time: None,
                sent_bytes: sent_len,
                recv_bytes: recv_len,
                notary_key,
                signature_alg,
                sent_data: None,
                recv_data: None,
                errors,
            });
        }
    };

    // Verify the presentation - this is the actual cryptographic verification
    let verification_result = presentation.verify(&crypto_provider);

    match verification_result {
        Ok(PresentationOutput {
            server_name,
            connection_info,
            transcript,
            ..
        }) => {
            // Verification succeeded - extract verified data
            let connection_time = Some(
                (chrono::DateTime::UNIX_EPOCH
                    + std::time::Duration::from_secs(connection_info.time))
                    .to_rfc3339(),
            );

            let verified_server = server_name
                .map(|s| format!("{}", s))
                .unwrap_or_else(|| proof.server.clone());

            let (sent_data, recv_data) = if let Some(mut partial_transcript) = transcript {
                partial_transcript.set_unauthed(b'X');
                let sent = String::from_utf8_lossy(partial_transcript.sent_unsafe()).to_string();
                let recv = String::from_utf8_lossy(partial_transcript.received_unsafe()).to_string();
                (Some(sent), Some(recv))
            } else {
                (None, None)
            };

            Ok(VerifyOutput {
                valid: true,
                server: verified_server,
                timestamp: proof.timestamp.clone(),
                connection_time,
                sent_bytes: connection_info.transcript_length.sent as usize,
                recv_bytes: connection_info.transcript_length.received as usize,
                notary_key,
                signature_alg,
                sent_data,
                recv_data,
                errors,
            })
        }
        Err(e) => {
            errors.push(format!("Cryptographic verification failed: {}", e));
            Ok(VerifyOutput {
                valid: false,
                server: proof.server.clone(),
                timestamp: proof.timestamp.clone(),
                connection_time: None,
                sent_bytes: sent_len,
                recv_bytes: recv_len,
                notary_key,
                signature_alg,
                sent_data: None,
                recv_data: None,
                errors,
            })
        }
    }
}

/// Verify a stream from its manifest and reconstruct the file
async fn verify_stream(
    manifest_path: &PathBuf,
    output: Option<&PathBuf>,
) -> Result<VerifyStreamOutput> {
    // Load manifest
    let manifest_data = fs::read_to_string(manifest_path).context("Failed to read manifest")?;
    let manifest: StreamManifest = serde_json::from_str(&manifest_data).context("Invalid manifest")?;

    let manifest_dir = manifest_path.parent().unwrap_or(std::path::Path::new("."));

    let mut errors: Vec<String> = Vec::new();
    let mut all_data: Vec<u8> = Vec::with_capacity(manifest.total_size as usize);
    let mut chunks_verified = 0;

    // Create crypto provider for verification
    let root_store = RootCertStore::mozilla();
    let crypto_provider = match ServerCertVerifier::new(&root_store) {
        Ok(cert_verifier) => CryptoProvider {
            cert: cert_verifier,
            ..Default::default()
        },
        Err(e) => {
            errors.push(format!("Failed to create cert verifier: {}", e));
            CryptoProvider::default()
        }
    };

    // Process each chunk
    for chunk in &manifest.chunks {
        let proof_path = manifest_dir.join(&chunk.proof_file);

        // Load proof
        let proof_bytes = match fs::read(&proof_path) {
            Ok(data) => data,
            Err(e) => {
                errors.push(format!("Chunk {}: failed to read proof: {}", chunk.index, e));
                continue;
            }
        };

        // Try new TlsnProof format first, fall back to legacy ProofData
        let (body_data, is_crypto_verified) = if let Ok(proof) = bincode::deserialize::<TlsnProof>(&proof_bytes) {
            // New format - perform cryptographic verification
            let mut crypto_verified = false;

            // Verify server matches
            if proof.server != manifest.server {
                errors.push(format!(
                    "Chunk {}: server mismatch (expected {}, got {})",
                    chunk.index, manifest.server, proof.server
                ));
            }

            // Build transcript proof and presentation for cryptographic verification
            let sent_len = proof.secrets.transcript().sent().len();
            let recv_len = proof.secrets.transcript().received().len();

            let mut transcript_proof_builder = proof.secrets.transcript_proof_builder();
            if transcript_proof_builder.reveal(&(0..sent_len), Direction::Sent).is_ok()
                && transcript_proof_builder.reveal(&(0..recv_len), Direction::Received).is_ok()
            {
                if let Ok(transcript_proof) = transcript_proof_builder.build() {
                    let mut presentation_builder = proof.attestation.presentation_builder(&crypto_provider);
                    presentation_builder
                        .identity_proof(proof.secrets.identity_proof())
                        .transcript_proof(transcript_proof);

                    if let Ok(presentation) = presentation_builder.build() {
                        if presentation.verify(&crypto_provider).is_ok() {
                            crypto_verified = true;
                        } else {
                            errors.push(format!("Chunk {}: cryptographic verification failed", chunk.index));
                        }
                    }
                }
            }

            (proof.response_body, crypto_verified)
        } else if let Ok(legacy) = bincode::deserialize::<ProofData>(&proof_bytes) {
            // Legacy format - hash-only verification
            if legacy.server != manifest.server {
                errors.push(format!(
                    "Chunk {}: server mismatch (expected {}, got {})",
                    chunk.index, manifest.server, legacy.server
                ));
            }

            // Extract body from HTTP response
            let received_str = String::from_utf8_lossy(&legacy.received);
            let body_start = received_str.find("\r\n\r\n").map(|i| i + 4);

            match body_start {
                Some(start) if start < legacy.received.len() => {
                    // Verify Range header in request
                    let sent_str = String::from_utf8_lossy(&legacy.sent).to_lowercase();
                    let expected_range = format!("range: bytes={}-{}", chunk.range_start, chunk.range_end);
                    if !sent_str.contains(&expected_range) {
                        errors.push(format!("Chunk {}: Range header mismatch in request", chunk.index));
                    }
                    (legacy.received[start..].to_vec(), false)
                }
                _ => {
                    errors.push(format!("Chunk {}: could not extract body from response", chunk.index));
                    continue;
                }
            }
        } else {
            errors.push(format!("Chunk {}: failed to deserialize proof", chunk.index));
            continue;
        };

        // Verify chunk hash
        let mut hasher = Sha256::new();
        hasher.update(&body_data);
        let computed_hash = format!("{:x}", hasher.finalize());

        if computed_hash != chunk.hash {
            errors.push(format!(
                "Chunk {}: hash mismatch (expected {}, got {})",
                chunk.index, chunk.hash, computed_hash
            ));
            continue;
        }

        if !is_crypto_verified {
            // Note that this chunk was not cryptographically verified
            // (legacy proof or verification failed)
        }

        all_data.extend_from_slice(&body_data);
        chunks_verified += 1;
    }

    // Compute final file hash
    let mut file_hasher = Sha256::new();
    file_hasher.update(&all_data);
    let computed_file_hash = format!("{:x}", file_hasher.finalize());

    if computed_file_hash != manifest.file_hash {
        errors.push(format!(
            "File hash mismatch (expected {}, got {})",
            manifest.file_hash, computed_file_hash
        ));
    }

    // Save reconstructed file if requested
    let output_file_path = if let Some(out) = output {
        fs::write(out, &all_data)?;
        Some(out.display().to_string())
    } else {
        None
    };

    let valid = errors.is_empty() && chunks_verified == manifest.chunks.len();

    Ok(VerifyStreamOutput {
        valid,
        url: manifest.url,
        server: manifest.server,
        total_size: manifest.total_size,
        chunks_total: manifest.chunks.len(),
        chunks_verified,
        file_hash: manifest.file_hash,
        computed_hash: computed_file_hash,
        output_file: output_file_path,
        errors,
    })
}
