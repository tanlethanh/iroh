//! relay-bench: Relay-client RTT benchmark for QUIC vs WebSocket transport.
//!
//! Connects directly as an iroh relay client — bypassing iroh endpoint overhead —
//! and benchmarks the transport layer using the relay protocol's built-in Ping/Pong.
//! The relay server responds to every Ping immediately with a Pong, so RTT measures
//! the full transport round-trip: client → relay → client.
//!
//! Modes:
//!   --ws    — WebSocket/TLS/TCP (port 443)   — existing relay transport
//!   --quic  — QUIC relay (port 7843/UDP)     — new QUIC relay transport
//!
//! Run both transports in sequence to compare:
//!   cargo run --manifest-path vendor/iroh/iroh-relay/Cargo.toml \
//!     --features server,test-utils --bin relay-bench -- \
//!     --relay-url https://sg1.relay.zedra.dev --ws --quic
//!
//! The relay server must be deployed with enable_quic_relay = true for --quic.

use std::{net::SocketAddr, sync::Arc, time::{Duration, Instant}};

use anyhow::{Context, Result};
use clap::Parser;
use iroh_base::{RelayUrl, SecretKey};
use iroh_relay::{
    client::ClientBuilder,
    dns::DnsResolver,
    protos::relay::{ClientToRelayMsg, RelayToClientMsg},
    ALPN_QUIC_RELAY,
};
use n0_future::{SinkExt, StreamExt};
use rand::RngCore;

#[derive(Parser)]
#[command(name = "relay-bench", about = "Relay-client RTT benchmark: WS vs QUIC")]
struct Cli {
    /// Relay URL (e.g. https://sg1.relay.zedra.dev)
    #[arg(long, default_value = "https://sg1.relay.zedra.dev")]
    relay_url: String,

    /// Number of pings per benchmark
    #[arg(long, short = 'c', default_value = "20")]
    count: u32,

    /// Delay between pings (ms)
    #[arg(long, default_value = "200")]
    interval_ms: u64,

    /// Benchmark via WebSocket/TLS/TCP relay transport
    #[arg(long)]
    ws: bool,

    /// Benchmark via QUIC relay transport (our new transport, port 7843/UDP)
    #[arg(long)]
    quic: bool,

    /// QUIC relay port (default 7843)
    #[arg(long, default_value = "7843")]
    quic_port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let cli = Cli::parse();

    if !cli.ws && !cli.quic {
        eprintln!("Specify at least one of --ws or --quic");
        eprintln!("Example: relay-bench --relay-url https://sg1.relay.zedra.dev --ws --quic");
        std::process::exit(1);
    }

    if cli.ws {
        eprintln!("\n=== Relay-client RTT via WebSocket/TLS/TCP ===");
        eprintln!("Relay: {}", cli.relay_url);
        let stats = bench_ws(&cli.relay_url, cli.count, cli.interval_ms).await?;
        print_stats("relay-ws", &stats);
    }

    if cli.quic {
        eprintln!("\n=== Relay-client RTT via QUIC (port {}/UDP) ===", cli.quic_port);
        eprintln!("Relay: {}", cli.relay_url);
        let stats =
            bench_quic(&cli.relay_url, cli.quic_port, cli.count, cli.interval_ms).await?;
        print_stats("relay-quic", &stats);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// WebSocket benchmark
// ---------------------------------------------------------------------------

async fn bench_ws(relay_url_str: &str, count: u32, interval_ms: u64) -> Result<BenchStats> {
    let relay_url: RelayUrl = relay_url_str.parse().context("invalid relay URL")?;
    let secret_key = SecretKey::generate(&mut rand::thread_rng());
    let dns = DnsResolver::default();
    let mut client = ClientBuilder::new(relay_url, secret_key, dns)
        .connect()
        .await
        .context("WebSocket connect failed")?;
    ping_loop(&mut client, count, interval_ms, "WS").await
}

// ---------------------------------------------------------------------------
// QUIC relay benchmark
// ---------------------------------------------------------------------------

async fn bench_quic(
    relay_url_str: &str,
    quic_port: u16,
    count: u32,
    interval_ms: u64,
) -> Result<BenchStats> {
    let relay_url: RelayUrl = relay_url_str.parse().context("invalid relay URL")?;
    let secret_key = SecretKey::generate(&mut rand::thread_rng());
    let dns = DnsResolver::default();

    // Resolve relay hostname → SocketAddr for QUIC (UDP, port 7843).
    let host = relay_url.host_str().context("no host in relay URL")?;
    let relay_addr: SocketAddr = tokio::net::lookup_host(format!("{}:{}", host, quic_port))
        .await
        .with_context(|| format!("DNS lookup for {host}:{quic_port}"))?
        .next()
        .with_context(|| format!("no address for {host}:{quic_port}"))?;
    eprintln!("QUIC relay addr: {relay_addr}");

    let quic_ep = make_quic_endpoint()?;
    let mut client = ClientBuilder::new(relay_url, secret_key, dns)
        .connect_quic(&quic_ep, relay_addr)
        .await
        .context("QUIC relay connect failed")?;

    ping_loop(&mut client, count, interval_ms, "QUIC").await
}

/// Build a QUIC endpoint that trusts public CAs (webpki-roots) for relay TLS.
fn make_quic_endpoint() -> Result<noq::Endpoint> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut client_crypto = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| anyhow::anyhow!("TLS versions: {e}"))?
    .with_root_certificates(roots)
    .with_no_client_auth();

    // ALPN must match what the QUIC relay server advertises.
    client_crypto.alpn_protocols = vec![ALPN_QUIC_RELAY.to_vec()];

    let client_config = noq::ClientConfig::new(Arc::new(
        noq::crypto::rustls::QuicClientConfig::try_from(client_crypto)
            .map_err(|e| anyhow::anyhow!("QUIC client config: {e}"))?,
    ));

    let mut endpoint = noq::Endpoint::client("0.0.0.0:0".parse().unwrap())
        .map_err(|e| anyhow::anyhow!("QUIC endpoint bind: {e}"))?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

// ---------------------------------------------------------------------------
// Shared ping loop — works with any Stream+Sink that speaks relay protocol
// ---------------------------------------------------------------------------

async fn ping_loop<S>(
    client: &mut S,
    count: u32,
    interval_ms: u64,
    label: &str,
) -> Result<BenchStats>
where
    S: n0_future::Sink<ClientToRelayMsg, Error = iroh_relay::client::SendError>
        + n0_future::Stream<Item = Result<RelayToClientMsg, iroh_relay::client::RecvError>>
        + Unpin,
{
    eprintln!("{:<6} {:>10}  transport", "seq", "rtt");
    eprintln!("{}", "-".repeat(40));

    let mut stats = BenchStats::default();
    let mut payload = [0u8; 8];

    for seq in 1u32..=count {
        payload[..4].copy_from_slice(&seq.to_le_bytes());
        let t0 = Instant::now();

        client
            .send(ClientToRelayMsg::Ping(payload))
            .await
            .map_err(|e| anyhow::anyhow!("send Ping: {e}"))?;

        // Drain until we receive our Pong back.
        loop {
            match client.next().await {
                Some(Ok(RelayToClientMsg::Pong(p))) if p == payload => break,
                Some(Ok(_)) => continue, // health, endpoint-gone, etc.
                Some(Err(e)) => return Err(anyhow::anyhow!("recv: {e}")),
                None => return Err(anyhow::anyhow!("connection closed")),
            }
        }

        let rtt = t0.elapsed().as_millis() as u64;
        stats.rtts.push(rtt);
        println!("{:<6} {:>8}ms  {}", seq, rtt, label);

        if seq < count {
            tokio::time::sleep(Duration::from_millis(interval_ms)).await;
        }
    }

    Ok(stats)
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

#[derive(Default)]
struct BenchStats {
    rtts: Vec<u64>,
}

impl BenchStats {
    fn min(&self) -> u64 {
        self.rtts.iter().min().copied().unwrap_or(0)
    }
    fn max(&self) -> u64 {
        self.rtts.iter().max().copied().unwrap_or(0)
    }
    fn avg(&self) -> u64 {
        if self.rtts.is_empty() {
            return 0;
        }
        self.rtts.iter().sum::<u64>() / self.rtts.len() as u64
    }
    fn p95(&self) -> u64 {
        if self.rtts.is_empty() {
            return 0;
        }
        let mut s = self.rtts.clone();
        s.sort_unstable();
        s[((s.len() as f64 * 0.95) as usize).min(s.len() - 1)]
    }
}

fn print_stats(label: &str, stats: &BenchStats) {
    if stats.rtts.is_empty() {
        eprintln!("\n--- {label} stats: no samples ---");
        return;
    }
    eprintln!(
        "\n--- {label} ({} pings) ---\nmin={}ms  avg={}ms  p95={}ms  max={}ms",
        stats.rtts.len(),
        stats.min(),
        stats.avg(),
        stats.p95(),
        stats.max(),
    );
}
