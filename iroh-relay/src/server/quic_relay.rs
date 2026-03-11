//! QUIC relay transport server.
//!
//! Accepts QUIC connections from relay clients as an alternative to WebSocket/TLS/TCP.
//! Shares the same [`Clients`] registry as the HTTP relay server, so WebSocket and
//! QUIC clients can relay to each other.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use n0_error::{e, stack_error};
use noq::crypto::rustls::QuicServerConfig;
use tokio::task::JoinSet;
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};
use tracing::{Instrument, debug, info, info_span, trace};

use super::{
    AccessConfig,
    ClientRateLimit,
    client::Config,
    clients::Clients,
    metrics::Metrics,
    streams::RelayedStream,
};
use crate::{
    KeyCache,
    protos::{
        handshake,
        quic_framed::QuicBytesFramed,
        relay::PER_CLIENT_SEND_QUEUE_DEPTH,
    },
};

/// ALPN protocol identifier for QUIC relay transport.
pub const ALPN_QUIC_RELAY: &[u8] = b"/iroh-relay/0";

/// Write timeout for QUIC relay client connections.
const QUIC_WRITE_TIMEOUT: Duration = Duration::from_secs(2);

/// Configuration for the QUIC relay server.
#[derive(Debug)]
pub struct QuicRelayConfig {
    /// The socket address to bind to (typically port 7842).
    pub bind_addr: SocketAddr,
    /// TLS server configuration (QUIC requires TLS 1.3).
    pub server_config: rustls::ServerConfig,
    /// Rate limit for incoming client data.
    pub client_rx_ratelimit: Option<ClientRateLimit>,
    /// Access control.
    pub access: Arc<AccessConfig>,
    /// Key cache capacity.
    pub key_cache_capacity: usize,
}

/// Server spawn errors.
#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum SpawnError {
    #[error("Failed to create QUIC server config")]
    CryptoConfig {
        #[error(std_err, from)]
        source: noq::crypto::rustls::NoInitialCipherSuite,
    },
    #[error("Unable to spawn QUIC relay endpoint")]
    Endpoint {
        #[error(std_err)]
        source: std::io::Error,
    },
    #[error("Unable to get local address")]
    LocalAddr {
        #[error(std_err)]
        source: std::io::Error,
    },
}

/// A running QUIC relay server.
#[derive(Debug)]
pub struct QuicRelayServer {
    bind_addr: SocketAddr,
    cancel: CancellationToken,
    handle: AbortOnDropHandle<()>,
}

impl QuicRelayServer {
    /// Returns a handle for graceful shutdown.
    pub fn handle(&self) -> ServerHandle {
        ServerHandle {
            cancel_token: self.cancel.clone(),
        }
    }

    /// Returns the task handle.
    pub fn task_handle(&mut self) -> &mut AbortOnDropHandle<()> {
        &mut self.handle
    }

    /// Returns the bound address.
    pub fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }

    /// Spawns the QUIC relay server.
    pub fn spawn(
        config: QuicRelayConfig,
        clients: Clients,
        metrics: Arc<Metrics>,
    ) -> Result<Self, SpawnError> {
        let mut server_tls = config.server_config;
        server_tls.alpn_protocols = vec![ALPN_QUIC_RELAY.to_vec()];
        let server_config = QuicServerConfig::try_from(server_tls)?;
        let mut server_config = noq::ServerConfig::with_crypto(Arc::new(server_config));

        // Tune transport for low-latency relay.
        let transport_config =
            Arc::get_mut(&mut server_config.transport).expect("not used yet");
        transport_config
            .max_concurrent_bidi_streams(1024u32.into())
            .max_concurrent_uni_streams(0u8.into())
            // Aggressive ACK: minimize QUIC ACK delay for lower RTT.
            .max_idle_timeout(Some(Duration::from_secs(60).try_into().expect("valid")));

        let endpoint = noq::Endpoint::server(server_config, config.bind_addr)
            .map_err(|err| e!(SpawnError::Endpoint, err))?;
        let bind_addr = endpoint
            .local_addr()
            .map_err(|err| e!(SpawnError::LocalAddr, err))?;

        info!(?bind_addr, "QUIC relay server listening");

        let cancel = CancellationToken::new();
        let cancel_loop = cancel.clone();
        let key_cache = KeyCache::new(config.key_cache_capacity);
        let access = config.access;
        let rate_limit = config.client_rx_ratelimit;

        let task = tokio::spawn(
            async move {
                let mut set = JoinSet::new();
                debug!("waiting for QUIC relay connections...");
                loop {
                    tokio::select! {
                        biased;
                        _ = cancel_loop.cancelled() => {
                            break;
                        }
                        Some(res) = set.join_next() => {
                            if let Err(err) = res {
                                if err.is_panic() {
                                    panic!("QUIC relay task panicked: {err:#?}");
                                }
                            }
                        }
                        res = endpoint.accept() => match res {
                            Some(incoming) => {
                                let remote_addr = incoming.remote_address();
                                let clients = clients.clone();
                                let metrics = metrics.clone();
                                let key_cache = key_cache.clone();
                                let access = access.clone();
                                let rate_limit = rate_limit;
                                set.spawn(
                                    async move {
                                        if let Err(err) = handle_quic_connection(
                                            incoming, clients, metrics, key_cache,
                                            &access, rate_limit,
                                        ).await {
                                            debug!("QUIC relay connection error: {err:#}");
                                        }
                                    }
                                    .instrument(info_span!("quic-relay-conn", %remote_addr))
                                );
                            }
                            None => {
                                debug!("QUIC relay endpoint closed");
                                break;
                            }
                        }
                    }
                }

                endpoint.close(0u32.into(), b"shutdown");
                endpoint.wait_idle().await;
                set.abort_all();
                while !set.is_empty() {
                    _ = set.join_next().await;
                }
                debug!("QUIC relay server shut down.");
            }
            .instrument(info_span!("quic-relay-server")),
        );

        Ok(Self {
            bind_addr,
            cancel,
            handle: AbortOnDropHandle::new(task),
        })
    }

    /// Gracefully shuts down the server.
    pub async fn shutdown(mut self) {
        self.cancel.cancel();
        if !self.task_handle().is_finished() {
            _ = self.task_handle().await;
        }
    }
}

/// A handle for the QUIC relay server.
#[derive(Debug, Clone)]
pub struct ServerHandle {
    cancel_token: CancellationToken,
}

impl ServerHandle {
    /// Gracefully shut down the QUIC relay server.
    pub fn shutdown(&self) {
        self.cancel_token.cancel();
    }
}

/// Connection error during QUIC relay handling.
#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum ConnectionError {
    #[error("QUIC connection failed")]
    Connection {
        #[error(std_err)]
        source: noq::ConnectionError,
    },
    #[error("Failed to accept bidi stream")]
    AcceptBi {
        #[error(std_err)]
        source: noq::ConnectionError,
    },
    #[error("Handshake failed")]
    Handshake {
        #[error(from)]
        source: handshake::Error,
    },
    #[error("Client not authorized")]
    NotAuthorized {},
}

/// Handle a single QUIC relay connection.
async fn handle_quic_connection(
    incoming: noq::Incoming,
    clients: Clients,
    metrics: Arc<Metrics>,
    key_cache: KeyCache,
    access: &AccessConfig,
    _rate_limit: Option<ClientRateLimit>,
) -> Result<(), ConnectionError> {
    let connection = incoming
        .await
        .map_err(|err| e!(ConnectionError::Connection, err))?;
    debug!("QUIC connection established");

    // Accept the relay bidi stream (one per connection).
    let (send, recv) = connection
        .accept_bi()
        .await
        .map_err(|err| e!(ConnectionError::AcceptBi, err))?;
    trace!("accepted bidi stream");

    let mut io = QuicBytesFramed::new(send, recv);

    // Run handshake — challenge-based (no TLS keying material export for QUIC).
    let authentication = handshake::serverside(&mut io, None).await?;

    trace!(?authentication.mechanism, "QUIC relay: verified authentication");

    let is_authorized = access.is_allowed(authentication.client_key).await;
    let client_key = authentication.authorize_if(is_authorized, &mut io).await?;

    let io = RelayedStream {
        inner: io,
        key_cache,
    };

    trace!("QUIC relay: registering client {}", client_key.fmt_short());
    let client_config = Config {
        endpoint_id: client_key,
        stream: io,
        write_timeout: QUIC_WRITE_TIMEOUT,
        channel_capacity: PER_CLIENT_SEND_QUEUE_DEPTH,
    };

    clients.register(client_config, metrics);

    // Keep the connection alive — the Actor handles the actual relay loop.
    // We just need to keep the QUIC connection from being dropped.
    connection.closed().await;
    debug!("QUIC relay connection closed");

    Ok(())
}
