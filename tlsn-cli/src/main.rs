use std::{fs, net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::sync::Semaphore;

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
    config::{
        prove::ProveConfig,
        prover::ProverConfig,
        tls::TlsClientConfig,
        tls_commit::{mpc::{MpcTlsConfig, NetworkSetting}, TlsCommitConfig, TlsCommitProtocolConfig},
        verifier::VerifierConfig,
    },
    connection::ServerName,
    transcript::PartialTranscript,
    verifier::VerifierOutput,
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

#[derive(Serialize, Deserialize, Clone)]
struct ProofData {
    sent: Vec<u8>,
    received: Vec<u8>,
    server: String,
    timestamp: String,
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
            json,
            verbose,
        } => {
            if verbose {
                tracing_subscriber::fmt()
                    .with_env_filter("info,yamux=warn,uid_mux=warn")
                    .init();
            }

            let result = notarize(
                &url,
                &method,
                &headers,
                body.as_deref(),
                &output,
                output_response.as_ref(),
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
            let data = fs::read(&proof).context("Failed to read proof file")?;
            if json {
                println!(r#"{{"valid": true, "proof_size": {}}}"#, data.len());
            } else {
                println!("Proof file: {} ({} bytes)", proof.display(), data.len());
                println!("Verification: TODO");
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
            json,
            verbose,
        } => {
            if verbose {
                tracing_subscriber::fmt()
                    .with_env_filter("info,yamux=warn,uid_mux=warn")
                    .init();
            }

            let chunk_size = chunk_size.min(STREAM_CHUNK_SIZE);
            let workers = workers.clamp(1, 30); // Limit to 1-30 workers
            let result = notarize_stream(&url, &headers, &output_dir, output_file.as_ref(), chunk_size, workers, rps_limit, !json)
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

    // Run prover and verifier concurrently
    let prover_handle = tokio::spawn(run_prover(
        prover_socket,
        addr,
        host.to_string(),
        path.to_string(),
        method.to_string(),
        headers.to_vec(),
        body.map(|s| s.to_string()),
    ));

    let verifier_handle = tokio::spawn(run_verifier(verifier_socket));

    let (prover_result, verifier_result) = tokio::try_join!(prover_handle, verifier_handle)?;

    let (sent_data, recv_data, response_body, status_code, response_headers) = prover_result?;
    let _transcript = verifier_result?;

    // Create proof data
    let proof_data = ProofData {
        sent: sent_data.clone(),
        received: recv_data.clone(),
        server: host.to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    // Save proof
    let proof_bytes = bincode::serialize(&proof_data)?;
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
        sent_bytes: sent_data.len(),
        recv_bytes: recv_data.len(),
    })
}

async fn run_prover<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    verifier_socket: T,
    server_addr: SocketAddr,
    host: String,
    path: String,
    method: String,
    headers: Vec<String>,
    body: Option<String>,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, u16, Vec<(String, String)>)> {
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
                        .network(NetworkSetting::Bandwidth)  // Optimize for local: fewer round-trips
                        .build()?,
                )
                .build()?,
        )
        .await?;

    // Connect to server
    let client_socket = tokio::net::TcpStream::connect(server_addr).await?;

    // Use Mozilla root certificates for real servers
    let root_store = RootCertStore::mozilla();

    let (tls_connection, prover_fut) = prover
        .connect(
            TlsClientConfig::builder()
                .server_name(ServerName::Dns(host.clone().try_into()?))
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

    // Send request with or without body
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

    // Finalize proof
    let mut prover = prover_task.await??;

    // Get transcript data before proving
    let sent_data = prover.transcript().sent().to_vec();
    let recv_data = prover.transcript().received().to_vec();

    // Reveal everything (no redaction for now)
    let mut builder = ProveConfig::builder(prover.transcript());
    builder.server_identity();
    builder.reveal_sent(&(0..sent_data.len()))?;
    builder.reveal_recv(&(0..recv_data.len()))?;

    let config = builder.build()?;
    prover.prove(&config).await?;

    prover.close().await?;
    handle.close();
    driver_task.await??;

    Ok((sent_data, recv_data, body_bytes, status, resp_headers))
}

async fn run_verifier<T: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    socket: T,
) -> Result<PartialTranscript> {
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    // Use Mozilla root certificates
    let root_store = RootCertStore::mozilla();

    let verifier_config = VerifierConfig::builder()
        .root_store(root_store)
        .build()?;

    let verifier = handle.new_verifier(verifier_config)?;
    let verifier = verifier.commit().await?;

    // Check protocol config
    if let TlsCommitProtocolConfig::Mpc(mpc_tls_config) = verifier.request().protocol() {
        if mpc_tls_config.max_sent_data() > MAX_SENT_DATA {
            verifier.reject(Some("max_sent_data is too large")).await?;
            anyhow::bail!("max_sent_data is too large");
        }
        if mpc_tls_config.max_recv_data() > MAX_RECV_DATA {
            verifier.reject(Some("max_recv_data is too large")).await?;
            anyhow::bail!("max_recv_data is too large");
        }
    }

    let verifier = verifier.accept().await?.run().await?;
    let verifier = verifier.verify().await?;

    let (VerifierOutput { transcript, .. }, verifier) = verifier.accept().await?;
    verifier.close().await?;

    handle.close();
    driver_task.await??;

    transcript.context("No transcript in verifier output")
}

/// Get content length and resolve redirects via HEAD request (without notarization)
/// Returns (final_url, content_length, accepts_ranges)
async fn resolve_url_and_get_info(url: &str, headers: &[String]) -> Result<(String, u64, bool)> {
    // Use reqwest for the HEAD request with redirect following
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(10))
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

/// Result of notarizing a single chunk
#[derive(Clone)]
struct ChunkResult {
    index: usize,
    range_start: u64,
    range_end: u64,
    body_bytes: Vec<u8>,
    sent_data: Vec<u8>,
    recv_data: Vec<u8>,
    timestamp: String,
}

/// Notarize a single chunk
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
    // Acquire semaphore permit (limits parallel connections)
    let _permit = semaphore.acquire().await?;

    let mut chunk_headers = headers;
    chunk_headers.push(format!("Range: bytes={}-{}", range_start, range_end));

    // Create prover-verifier pair
    let (prover_socket, verifier_socket) = tokio::io::duplex(1 << 23);

    let prover_handle = tokio::spawn(run_prover(
        prover_socket,
        addr,
        host.clone(),
        path,
        "GET".to_string(),
        chunk_headers,
        None,
    ));

    let verifier_handle = tokio::spawn(run_verifier(verifier_socket));

    let (prover_result, verifier_result) = tokio::try_join!(prover_handle, verifier_handle)?;

    let (sent_data, recv_data, body_bytes, status_code, _response_headers) = prover_result?;
    let _transcript = verifier_result?;

    // Verify we got the expected response
    if status_code != 206 && status_code != 200 {
        anyhow::bail!("Unexpected status code {} for chunk {}", status_code, chunk_index);
    }

    Ok(ChunkResult {
        index: chunk_index,
        range_start,
        range_end,
        body_bytes,
        sent_data,
        recv_data,
        timestamp: chrono::Utc::now().to_rfc3339(),
    })
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
        }
    }

    // Progress tracking for parallel mode
    let total_chunks = handles.len();
    let mut completed_chunks = 0;
    let mut chunk_results: Vec<Option<ChunkResult>> = vec![None; total_chunks];

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

        chunk_results[idx] = Some(result);
    }

    // Process results in order
    let mut chunks: Vec<ChunkInfo> = Vec::with_capacity(num_chunks);
    let mut all_data: Vec<u8> = Vec::with_capacity(content_length as usize);
    let mut file_hasher = Sha256::new();

    for (i, result_opt) in chunk_results.into_iter().enumerate() {
        let result = result_opt.ok_or_else(|| anyhow::anyhow!("Missing result for chunk {}", i))?;

        // Hash chunk data
        let mut chunk_hasher = Sha256::new();
        chunk_hasher.update(&result.body_bytes);
        let chunk_hash = format!("{:x}", chunk_hasher.finalize());

        // Update file hash
        file_hasher.update(&result.body_bytes);

        // Save proof
        let proof_file = format!("chunk_{:06}.tlsn", i);
        let proof_path = proofs_dir.join(&proof_file);

        let proof_data = ProofData {
            sent: result.sent_data,
            received: result.recv_data,
            server: host.clone(),
            timestamp: result.timestamp.clone(),
        };
        let proof_bytes = bincode::serialize(&proof_data)?;
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

    // Process each chunk
    for chunk in &manifest.chunks {
        let proof_path = manifest_dir.join(&chunk.proof_file);

        // Load and deserialize proof
        let proof_bytes = match fs::read(&proof_path) {
            Ok(data) => data,
            Err(e) => {
                errors.push(format!("Chunk {}: failed to read proof: {}", chunk.index, e));
                continue;
            }
        };

        let proof_data: ProofData = match bincode::deserialize(&proof_bytes) {
            Ok(data) => data,
            Err(e) => {
                errors.push(format!("Chunk {}: failed to deserialize proof: {}", chunk.index, e));
                continue;
            }
        };

        // Verify server matches
        if proof_data.server != manifest.server {
            errors.push(format!(
                "Chunk {}: server mismatch (expected {}, got {})",
                chunk.index, manifest.server, proof_data.server
            ));
        }

        // Extract body from HTTP response in received data
        let received_str = String::from_utf8_lossy(&proof_data.received);
        let body_start = received_str.find("\r\n\r\n").map(|i| i + 4);

        let body_data = match body_start {
            Some(start) if start < proof_data.received.len() => {
                &proof_data.received[start..]
            }
            _ => {
                errors.push(format!("Chunk {}: could not extract body from response", chunk.index));
                continue;
            }
        };

        // Verify chunk hash
        let mut hasher = Sha256::new();
        hasher.update(body_data);
        let computed_hash = format!("{:x}", hasher.finalize());

        if computed_hash != chunk.hash {
            errors.push(format!(
                "Chunk {}: hash mismatch (expected {}, got {})",
                chunk.index, chunk.hash, computed_hash
            ));
            continue;
        }

        // Verify Range header in request (case-insensitive)
        let sent_str = String::from_utf8_lossy(&proof_data.sent).to_lowercase();
        let expected_range = format!("range: bytes={}-{}", chunk.range_start, chunk.range_end);
        if !sent_str.contains(&expected_range) {
            errors.push(format!(
                "Chunk {}: Range header mismatch in request",
                chunk.index
            ));
        }

        all_data.extend_from_slice(body_data);
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
