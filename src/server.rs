use crate::config::{Config, ServerConfig, ServerServiceConfig, ServiceType, TransportType};
use crate::config_watcher::{ConfigChange, ServerServiceChange};
use crate::constants::{UDP_BUFFER_SIZE, listen_backoff};
use crate::dashboard::DashboardServer;
use crate::helper::{retry_notify_with_deadline, write_and_flush};
use crate::http_proxy::{self, HttpRoute, VhostRouter};
use crate::metrics::MetricsCollector;
use crate::multi_map::MultiMap;
use crate::protocol::Hello::{ControlChannelHello, DataChannelHello, VisitorHello};
use crate::protocol::{
    self, Ack, ControlChannelCmd, DataChannelCmd, HASH_WIDTH_IN_BYTES, Hello, UdpTraffic,
    read_auth, read_hello,
};
use crate::transport::{SocketOpts, TcpTransport, Transport};
use anyhow::{Context, Result, anyhow, bail};
use backoff::ExponentialBackoff;
use backoff::backoff::Backoff;

use rand::RngCore;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{RwLock, broadcast, mpsc};
use tokio::time;
use tracing::{Instrument, Span, debug, error, info, info_span, instrument, warn};

#[cfg(feature = "noise")]
use crate::transport::NoiseTransport;
#[cfg(any(feature = "native-tls", feature = "rustls"))]
use crate::transport::TlsTransport;
#[cfg(any(feature = "websocket-native-tls", feature = "websocket-rustls"))]
use crate::transport::WebsocketTransport;

type ServiceDigest = protocol::Digest; // SHA256 of a service name
type Nonce = protocol::Digest; // Also called `session_key`

const CHAN_SIZE: usize = 2048; // The capacity of various chans
const HANDSHAKE_TIMEOUT: u64 = 5; // Timeout for transport handshake

// The entrypoint of running a server
pub async fn run_server(
    config: Config,
    shutdown_rx: broadcast::Receiver<bool>,
    update_rx: mpsc::Receiver<ConfigChange>,
) -> Result<()> {
    let config = match config.server {
        Some(config) => config,
        None => {
            return Err(anyhow!(
                "Try to run as a server, but the configuration is missing. Please add the `[server]` block"
            ));
        }
    };

    match config.transport.transport_type {
        TransportType::Tcp => {
            let mut server = Server::<TcpTransport>::from(config).await?;
            server.run(shutdown_rx, update_rx).await?;
        }
        TransportType::Tls => {
            #[cfg(any(feature = "native-tls", feature = "rustls"))]
            {
                let mut server = Server::<TlsTransport>::from(config).await?;
                server.run(shutdown_rx, update_rx).await?;
            }
            #[cfg(not(any(feature = "native-tls", feature = "rustls")))]
            crate::helper::feature_neither_compile("native-tls", "rustls")
        }
        TransportType::Noise => {
            #[cfg(feature = "noise")]
            {
                let mut server = Server::<NoiseTransport>::from(config).await?;
                server.run(shutdown_rx, update_rx).await?;
            }
            #[cfg(not(feature = "noise"))]
            crate::helper::feature_not_compile("noise")
        }
        TransportType::Websocket => {
            #[cfg(any(feature = "websocket-native-tls", feature = "websocket-rustls"))]
            {
                let mut server = Server::<WebsocketTransport>::from(config).await?;
                server.run(shutdown_rx, update_rx).await?;
            }
            #[cfg(not(any(feature = "websocket-native-tls", feature = "websocket-rustls")))]
            crate::helper::feature_neither_compile("websocket-native-tls", "websocket-rustls")
        }
        TransportType::Kcp => crate::helper::feature_not_compile("kcp"),
        TransportType::Quic => crate::helper::feature_not_compile("quic"),
    }

    Ok(())
}

// A hash map of ControlChannelHandles, indexed by ServiceDigest or Nonce
type ControlChannelMap<T> = MultiMap<ServiceDigest, Nonce, ControlChannelHandle<T>>;

// Server holds all states of running a server
struct Server<T: Transport> {
    config: Arc<ServerConfig>,
    services: Arc<RwLock<HashMap<ServiceDigest, ServerServiceConfig>>>,
    control_channels: Arc<RwLock<ControlChannelMap<T>>>,
    transport: Arc<T>,
    metrics: Arc<MetricsCollector>,
    vhost_router: Arc<RwLock<VhostRouter>>,
}

// Generate a hash map of services which is indexed by ServiceDigest
fn generate_service_hashmap(
    server_config: &ServerConfig,
) -> HashMap<ServiceDigest, ServerServiceConfig> {
    let mut ret = HashMap::new();
    for u in &server_config.services {
        if u.1.is_enabled() {
            ret.insert(protocol::digest(u.0.as_bytes()), (*u.1).clone());
        }
    }
    ret
}

impl<T: 'static + Transport> Server<T> {
    pub async fn from(config: ServerConfig) -> Result<Server<T>> {
        let metrics = Arc::new(MetricsCollector::new());
        let vhost_router = Arc::new(RwLock::new(VhostRouter::new(config.subdomain_host.clone())));

        // Register HTTP routes
        {
            let mut router = vhost_router.write().await;
            for (name, svc) in &config.services {
                if !svc.is_enabled() {
                    continue;
                }
                if matches!(svc.service_type, ServiceType::Http | ServiceType::Https) {
                    router.add_route(HttpRoute {
                        service_name: name.clone(),
                        custom_domains: svc.custom_domains.clone().unwrap_or_default(),
                        subdomain: svc.subdomain.clone(),
                        locations: svc.locations.clone().unwrap_or_default(),
                        host_header_rewrite: svc.host_header_rewrite.clone(),
                        http_user: svc.http_user.clone(),
                        http_password: svc.http_password.as_ref().map(|p| p.to_string()),
                        request_headers: svc.request_headers.clone().unwrap_or_default(),
                        response_headers: svc.response_headers.clone().unwrap_or_default(),
                        route_by_http_user: svc.route_by_http_user.clone(),
                    });
                }
            }
        }

        let config = Arc::new(config);
        let services = Arc::new(RwLock::new(generate_service_hashmap(&config)));
        let control_channels = Arc::new(RwLock::new(ControlChannelMap::new()));
        let transport = Arc::new(T::new(&config.transport)?);

        Ok(Server {
            config,
            services,
            control_channels,
            transport,
            metrics,
            vhost_router,
        })
    }

    pub async fn run(
        &mut self,
        mut shutdown_rx: broadcast::Receiver<bool>,
        mut update_rx: mpsc::Receiver<ConfigChange>,
    ) -> Result<()> {
        // Listen at `server.bind_addr`
        let l = self
            .transport
            .bind(&self.config.bind_addr)
            .await
            .with_context(|| "Failed to listen at `server.bind_addr`")?;
        info!("Listening at {}", self.config.bind_addr);

        // Start dashboard server if configured
        if let Some(web_config) = &self.config.web_server {
            let dashboard = DashboardServer::new(web_config.clone(), self.metrics.clone());
            let dashboard_shutdown = shutdown_rx.resubscribe();
            tokio::spawn(async move {
                dashboard.run(dashboard_shutdown).await;
            });
        }

        // Start HTTP vhost listener if configured
        if let Some(http_port) = self.config.vhost_http_port {
            let bind_addr = format!("0.0.0.0:{}", http_port);
            let control_channels = self.control_channels.clone();
            let services = self.services.clone();
            let vhost_router = self.vhost_router.clone();
            let custom_404 = self.config.custom_404_page.clone();
            let vhost_shutdown = shutdown_rx.resubscribe();
            tokio::spawn(async move {
                if let Err(e) = run_http_vhost_listener(
                    bind_addr,
                    control_channels,
                    services,
                    vhost_router,
                    custom_404,
                    vhost_shutdown,
                )
                .await
                {
                    error!("HTTP vhost listener error: {:#}", e);
                }
            });
        }

        // Retry at least every 100ms
        let mut backoff = ExponentialBackoff {
            max_interval: Duration::from_millis(100),
            max_elapsed_time: None,
            ..Default::default()
        };

        // Wait for connections and shutdown signals
        loop {
            tokio::select! {
                ret = self.transport.accept(&l) => {
                    match ret {
                        Err(err) => {
                            if let Some(err) = err.downcast_ref::<io::Error>() {
                                if let Some(d) = backoff.next_backoff() {
                                    error!("Failed to accept: {:#}. Retry in {:?}...", err, d);
                                    time::sleep(d).await;
                                } else {
                                    error!("Too many retries. Aborting...");
                                    break;
                                }
                            }
                        }
                        Ok((conn, addr)) => {
                            backoff.reset();
                            self.metrics.record_connection();
                            let metrics = self.metrics.clone();

                            match time::timeout(Duration::from_secs(HANDSHAKE_TIMEOUT), self.transport.handshake(conn)).await {
                                Ok(conn) => {
                                    match conn.with_context(|| "Failed to do transport handshake") {
                                        Ok(conn) => {
                                            let services = self.services.clone();
                                            let control_channels = self.control_channels.clone();
                                            let server_config = self.config.clone();
                                            tokio::spawn(async move {
                                                if let Err(err) = handle_connection(conn, services, control_channels, server_config).await {
                                                    error!("{:#}", err);
                                                }
                                                metrics.record_disconnection();
                                            }.instrument(info_span!("connection", %addr)));
                                        }, Err(e) => {
                                            error!("{:#}", e);
                                            metrics.record_disconnection();
                                        }
                                    }
                                },
                                Err(e) => {
                                    error!("Transport handshake timeout: {}", e);
                                    metrics.record_disconnection();
                                }
                            }
                        }
                    }
                },
                _ = shutdown_rx.recv() => {
                    info!("Shuting down gracefully...");
                    break;
                },
                e = update_rx.recv() => {
                    if let Some(e) = e {
                        self.handle_hot_reload(e).await;
                    }
                }
            }
        }

        info!("Shutdown");

        Ok(())
    }

    async fn handle_hot_reload(&mut self, e: ConfigChange) {
        match e {
            ConfigChange::ServerChange(server_change) => match server_change {
                ServerServiceChange::Add(cfg) => {
                    let hash = protocol::digest(cfg.name.as_bytes());

                    // Update vhost router for HTTP services
                    if matches!(cfg.service_type, ServiceType::Http | ServiceType::Https) {
                        let mut router = self.vhost_router.write().await;
                        router.remove_route(&cfg.name);
                        router.add_route(HttpRoute {
                            service_name: cfg.name.clone(),
                            custom_domains: cfg.custom_domains.clone().unwrap_or_default(),
                            subdomain: cfg.subdomain.clone(),
                            locations: cfg.locations.clone().unwrap_or_default(),
                            host_header_rewrite: cfg.host_header_rewrite.clone(),
                            http_user: cfg.http_user.clone(),
                            http_password: cfg.http_password.as_ref().map(|p| p.to_string()),
                            request_headers: cfg.request_headers.clone().unwrap_or_default(),
                            response_headers: cfg.response_headers.clone().unwrap_or_default(),
                            route_by_http_user: cfg.route_by_http_user.clone(),
                        });
                    }

                    let mut wg = self.services.write().await;
                    let _ = wg.insert(hash, cfg);
                    let mut wg = self.control_channels.write().await;
                    let _ = wg.remove1(&hash);
                }
                ServerServiceChange::Delete(s) => {
                    let hash = protocol::digest(s.as_bytes());
                    let _ = self.services.write().await.remove(&hash);

                    // Remove from vhost router
                    let mut router = self.vhost_router.write().await;
                    router.remove_route(&s);

                    let mut wg = self.control_channels.write().await;
                    let _ = wg.remove1(&hash);
                }
            },
            ignored => warn!("Ignored {:?} since running as a server", ignored),
        }
    }
}

// Handle connections to `server.bind_addr`
async fn handle_connection<T: 'static + Transport>(
    mut conn: T::Stream,
    services: Arc<RwLock<HashMap<ServiceDigest, ServerServiceConfig>>>,
    control_channels: Arc<RwLock<ControlChannelMap<T>>>,
    server_config: Arc<ServerConfig>,
) -> Result<()> {
    // Read hello
    let hello = read_hello(&mut conn).await?;
    match hello {
        ControlChannelHello(_, service_digest) => {
            do_control_channel_handshake(
                conn,
                services,
                control_channels,
                service_digest,
                server_config,
            )
            .await?;
        }
        DataChannelHello(_, nonce) => {
            do_data_channel_handshake(conn, control_channels, nonce).await?;
        }
        VisitorHello(_, service_digest) => {
            do_visitor_handshake(conn, services, control_channels, service_digest).await?;
        }
    }
    Ok(())
}

async fn do_control_channel_handshake<T: 'static + Transport>(
    mut conn: T::Stream,
    services: Arc<RwLock<HashMap<ServiceDigest, ServerServiceConfig>>>,
    control_channels: Arc<RwLock<ControlChannelMap<T>>>,
    service_digest: ServiceDigest,
    server_config: Arc<ServerConfig>,
) -> Result<()> {
    info!("Try to handshake a control channel");

    T::hint(&conn, SocketOpts::for_control_channel());

    // Generate a nonce
    let mut nonce = vec![0u8; HASH_WIDTH_IN_BYTES];
    rand::thread_rng().fill_bytes(&mut nonce);

    // Send hello
    let hello_send = Hello::ControlChannelHello(
        protocol::CURRENT_PROTO_VERSION,
        nonce.clone().try_into().unwrap(),
    );
    conn.write_all(&bincode::serialize(&hello_send).unwrap())
        .await?;
    conn.flush().await?;

    // Lookup the service
    let service_config = match services.read().await.get(&service_digest) {
        Some(v) => v,
        None => {
            conn.write_all(&bincode::serialize(&Ack::ServiceNotExist).unwrap())
                .await?;
            bail!("No such a service {}", hex::encode(service_digest));
        }
    }
    .to_owned();

    let service_name = &service_config.name;

    // Calculate the checksum
    let mut concat = Vec::from(service_config.token.as_ref().unwrap().as_bytes());
    concat.append(&mut nonce);

    // Read auth
    let protocol::Auth(d) = read_auth(&mut conn).await?;

    // Validate
    let session_key = protocol::digest(&concat);
    if session_key != d {
        conn.write_all(&bincode::serialize(&Ack::AuthFailed).unwrap())
            .await?;
        debug!(
            "Expect {}, but got {}",
            hex::encode(session_key),
            hex::encode(d)
        );
        bail!("Service {} failed the authentication", service_name);
    } else {
        let mut h = control_channels.write().await;

        if h.remove1(&service_digest).is_some() {
            warn!(
                "Dropping previous control channel for service {}",
                service_name
            );
        }

        // Send ack
        conn.write_all(&bincode::serialize(&Ack::Ok).unwrap())
            .await?;
        conn.flush().await?;

        info!(service = %service_config.name, "Control channel established");
        let handle =
            ControlChannelHandle::new(conn, service_config, server_config.heartbeat_interval);

        let _ = h.insert(service_digest, session_key, handle);
    }

    Ok(())
}

async fn do_data_channel_handshake<T: 'static + Transport>(
    conn: T::Stream,
    control_channels: Arc<RwLock<ControlChannelMap<T>>>,
    nonce: Nonce,
) -> Result<()> {
    debug!("Try to handshake a data channel");

    let control_channels_guard = control_channels.read().await;
    match control_channels_guard.get2(&nonce) {
        Some(handle) => {
            T::hint(&conn, SocketOpts::from_server_cfg(&handle.service));

            handle
                .data_ch_tx
                .send(conn)
                .await
                .with_context(|| "Data channel for a stale control channel")?;
        }
        None => {
            warn!("Data channel has incorrect nonce");
        }
    }
    Ok(())
}

/// Handle a visitor connection for STCP/SUDP/XTCP services
async fn do_visitor_handshake<T: 'static + Transport>(
    mut conn: T::Stream,
    services: Arc<RwLock<HashMap<ServiceDigest, ServerServiceConfig>>>,
    control_channels: Arc<RwLock<ControlChannelMap<T>>>,
    service_digest: ServiceDigest,
) -> Result<()> {
    info!("Try to handshake a visitor connection");

    T::hint(&conn, SocketOpts::for_control_channel());

    // Lookup the service
    let service_config = match services.read().await.get(&service_digest) {
        Some(v) => v.clone(),
        None => {
            conn.write_all(&bincode::serialize(&Ack::ServiceNotExist).unwrap())
                .await?;
            bail!("No such service for visitor");
        }
    };

    // Verify it's a secret service type
    if !matches!(
        service_config.service_type,
        ServiceType::Stcp | ServiceType::Sudp | ServiceType::Xtcp
    ) {
        conn.write_all(&bincode::serialize(&Ack::ServiceNotExist).unwrap())
            .await?;
        bail!("Service {} is not a secret type", service_config.name);
    }

    let secret_key = service_config
        .secret_key
        .as_ref()
        .ok_or_else(|| anyhow!("Service {} has no secret_key", service_config.name))?;

    // Generate nonce for visitor authentication
    let mut nonce = vec![0u8; HASH_WIDTH_IN_BYTES];
    rand::thread_rng().fill_bytes(&mut nonce);

    // Send nonce as a ControlChannelHello (reusing the same message type)
    let hello_send = Hello::ControlChannelHello(
        protocol::CURRENT_PROTO_VERSION,
        nonce.clone().try_into().unwrap(),
    );
    conn.write_all(&bincode::serialize(&hello_send).unwrap())
        .await?;
    conn.flush().await?;

    // Read visitor's auth
    let protocol::Auth(d) = read_auth(&mut conn).await?;

    // Validate secret key
    let mut concat = Vec::from(secret_key.as_bytes());
    concat.extend_from_slice(&nonce);
    let expected_digest = protocol::digest(&concat);

    if expected_digest != d {
        conn.write_all(&bincode::serialize(&Ack::SecretKeyMismatch).unwrap())
            .await?;
        bail!(
            "Visitor secret key mismatch for service {}",
            service_config.name
        );
    }

    // Check if the service has a control channel (client connected)
    let control_channels_guard = control_channels.read().await;
    match control_channels_guard.get1(&service_digest) {
        Some(handle) => {
            // Send OK
            conn.write_all(&bincode::serialize(&Ack::Ok).unwrap())
                .await?;
            conn.flush().await?;

            // Request a data channel from the client
            if handle.data_ch_req_tx.send(true).is_err() {
                bail!("Failed to request data channel for visitor");
            }

            drop(control_channels_guard);

            info!("Visitor authenticated for service {}", service_config.name);
        }
        None => {
            conn.write_all(&bincode::serialize(&Ack::ServiceNotReady).unwrap())
                .await?;
            bail!("No client connected for service {}", service_config.name);
        }
    }

    Ok(())
}

pub struct ControlChannelHandle<T: Transport> {
    _shutdown_tx: broadcast::Sender<bool>,
    data_ch_tx: mpsc::Sender<T::Stream>,
    data_ch_req_tx: mpsc::UnboundedSender<bool>,
    service: ServerServiceConfig,
}

impl<T> ControlChannelHandle<T>
where
    T: 'static + Transport,
{
    #[instrument(name = "handle", skip_all, fields(service = %service.name))]
    fn new(
        conn: T::Stream,
        service: ServerServiceConfig,
        heartbeat_interval: u64,
    ) -> ControlChannelHandle<T> {
        let (shutdown_tx, shutdown_rx) = broadcast::channel::<bool>(1);
        let (data_ch_tx, data_ch_rx) = mpsc::channel(CHAN_SIZE * 2);
        let (data_ch_req_tx, data_ch_req_rx) = mpsc::unbounded_channel();

        // Use configurable pool size
        let pool_size = service.pool_size();

        for _i in 0..pool_size {
            if let Err(e) = data_ch_req_tx.send(true) {
                error!("Failed to request data channel {}", e);
            };
        }

        let shutdown_rx_clone = shutdown_tx.subscribe();
        let bind_addr = service.bind_addr.clone();
        let service_type = service.service_type;
        let data_ch_req_tx_clone = data_ch_req_tx.clone();

        match service_type {
            ServiceType::Tcp | ServiceType::Tcpmux => {
                tokio::spawn(
                    async move {
                        if let Err(e) = run_tcp_connection_pool::<T>(
                            bind_addr,
                            data_ch_rx,
                            data_ch_req_tx_clone,
                            shutdown_rx_clone,
                        )
                        .await
                        .with_context(|| "Failed to run TCP connection pool")
                        {
                            error!("{:#}", e);
                        }
                    }
                    .instrument(Span::current()),
                );
            }
            ServiceType::Udp => {
                tokio::spawn(
                    async move {
                        if let Err(e) = run_udp_connection_pool::<T>(
                            bind_addr,
                            data_ch_rx,
                            data_ch_req_tx_clone,
                            shutdown_rx_clone,
                        )
                        .await
                        .with_context(|| "Failed to run UDP connection pool")
                        {
                            error!("{:#}", e);
                        }
                    }
                    .instrument(Span::current()),
                );
            }
            ServiceType::Http | ServiceType::Https => {
                if !bind_addr.is_empty() {
                    tokio::spawn(
                        async move {
                            if let Err(e) = run_tcp_connection_pool::<T>(
                                bind_addr,
                                data_ch_rx,
                                data_ch_req_tx_clone,
                                shutdown_rx_clone,
                            )
                            .await
                            {
                                error!("{:#}", e);
                            }
                        }
                        .instrument(Span::current()),
                    );
                } else {
                    tokio::spawn(
                        async move {
                            let _data_ch_rx = data_ch_rx;
                            let _ = shutdown_rx_clone.resubscribe().recv().await;
                        }
                        .instrument(Span::current()),
                    );
                }
            }
            ServiceType::Stcp | ServiceType::Xtcp => {
                tokio::spawn(
                    async move {
                        let _data_ch_rx = data_ch_rx;
                        let _ = shutdown_rx_clone.resubscribe().recv().await;
                    }
                    .instrument(Span::current()),
                );
            }
            ServiceType::Sudp => {
                if !bind_addr.is_empty() {
                    tokio::spawn(
                        async move {
                            if let Err(e) = run_udp_connection_pool::<T>(
                                bind_addr,
                                data_ch_rx,
                                data_ch_req_tx_clone,
                                shutdown_rx_clone,
                            )
                            .await
                            {
                                error!("{:#}", e);
                            }
                        }
                        .instrument(Span::current()),
                    );
                } else {
                    tokio::spawn(
                        async move {
                            let _data_ch_rx = data_ch_rx;
                            let _ = shutdown_rx_clone.resubscribe().recv().await;
                        }
                        .instrument(Span::current()),
                    );
                }
            }
        }

        // Create the control channel
        let ch = ControlChannel::<T> {
            conn,
            shutdown_rx,
            data_ch_req_rx,
            heartbeat_interval,
        };

        tokio::spawn(
            async move {
                if let Err(err) = ch.run().await {
                    error!("{:#}", err);
                }
            }
            .instrument(Span::current()),
        );

        ControlChannelHandle {
            _shutdown_tx: shutdown_tx,
            data_ch_tx,
            data_ch_req_tx,
            service,
        }
    }
}

struct ControlChannel<T: Transport> {
    conn: T::Stream,
    shutdown_rx: broadcast::Receiver<bool>,
    data_ch_req_rx: mpsc::UnboundedReceiver<bool>,
    heartbeat_interval: u64,
}

impl<T: Transport> ControlChannel<T> {
    async fn write_and_flush(&mut self, data: &[u8]) -> Result<()> {
        write_and_flush(&mut self.conn, data)
            .await
            .with_context(|| "Failed to write control cmds")?;
        Ok(())
    }

    #[instrument(skip_all)]
    async fn run(mut self) -> Result<()> {
        let create_ch_cmd = bincode::serialize(&ControlChannelCmd::CreateDataChannel).unwrap();
        let heartbeat = bincode::serialize(&ControlChannelCmd::HeartBeat).unwrap();

        loop {
            tokio::select! {
                val = self.data_ch_req_rx.recv() => {
                    match val {
                        Some(_) => {
                            if let Err(e) = self.write_and_flush(&create_ch_cmd).await {
                                error!("{:#}", e);
                                break;
                            }
                        }
                        None => {
                            break;
                        }
                    }
                },
                _ = time::sleep(Duration::from_secs(self.heartbeat_interval)), if self.heartbeat_interval != 0 => {
                            if let Err(e) = self.write_and_flush(&heartbeat).await {
                                error!("{:#}", e);
                                break;
                            }
                }
                _ = self.shutdown_rx.recv() => {
                    break;
                }
            }
        }

        info!("Control channel shutdown");

        Ok(())
    }
}

fn tcp_listen_and_send(
    addr: String,
    data_ch_req_tx: mpsc::UnboundedSender<bool>,
    mut shutdown_rx: broadcast::Receiver<bool>,
) -> mpsc::Receiver<TcpStream> {
    let (tx, rx) = mpsc::channel(CHAN_SIZE);

    tokio::spawn(async move {
        let l = retry_notify_with_deadline(listen_backoff(),  || async {
            Ok(TcpListener::bind(&addr).await?)
        }, |e, duration| {
            error!("{:#}. Retry in {:?}", e, duration);
        }, &mut shutdown_rx).await
        .with_context(|| "Failed to listen for the service");

        let l: TcpListener = match l {
            Ok(v) => v,
            Err(e) => {
                error!("{:#}", e);
                return;
            }
        };

        info!("Listening at {}", &addr);

        let mut backoff = ExponentialBackoff {
            max_interval: Duration::from_secs(1),
            max_elapsed_time: None,
            ..Default::default()
        };

        loop {
            tokio::select! {
                val = l.accept() => {
                    match val {
                        Err(e) => {
                            error!("{}. Sleep for a while", e);
                            if let Some(d) = backoff.next_backoff() {
                                time::sleep(d).await;
                            } else {
                                error!("Too many retries. Aborting...");
                                break;
                            }
                        }
                        Ok((incoming, addr)) => {
                            if data_ch_req_tx.send(true).with_context(|| "Failed to send data chan create request").is_err() {
                                break;
                            }

                            backoff.reset();

                            debug!("New visitor from {}", addr);

                            let _ = tx.send(incoming).await;
                        }
                    }
                },
                _ = shutdown_rx.recv() => {
                    break;
                }
            }
        }

        info!("TCPListener shutdown");
    }.instrument(Span::current()));

    rx
}

#[instrument(skip_all)]
async fn run_tcp_connection_pool<T: Transport>(
    bind_addr: String,
    mut data_ch_rx: mpsc::Receiver<T::Stream>,
    data_ch_req_tx: mpsc::UnboundedSender<bool>,
    shutdown_rx: broadcast::Receiver<bool>,
) -> Result<()> {
    let mut visitor_rx = tcp_listen_and_send(bind_addr, data_ch_req_tx.clone(), shutdown_rx);
    let cmd = bincode::serialize(&DataChannelCmd::StartForwardTcp).unwrap();

    'pool: while let Some(mut visitor) = visitor_rx.recv().await {
        loop {
            if let Some(mut ch) = data_ch_rx.recv().await {
                if write_and_flush(&mut ch, &cmd).await.is_ok() {
                    tokio::spawn(async move {
                        let _ = copy_bidirectional(&mut ch, &mut visitor).await;
                    });
                    break;
                } else {
                    if data_ch_req_tx.send(true).is_err() {
                        break 'pool;
                    }
                }
            } else {
                break 'pool;
            }
        }
    }

    info!("Shutdown");
    Ok(())
}

#[instrument(skip_all)]
async fn run_udp_connection_pool<T: Transport>(
    bind_addr: String,
    mut data_ch_rx: mpsc::Receiver<T::Stream>,
    _data_ch_req_tx: mpsc::UnboundedSender<bool>,
    mut shutdown_rx: broadcast::Receiver<bool>,
) -> Result<()> {
    let l = retry_notify_with_deadline(
        listen_backoff(),
        || async { Ok(UdpSocket::bind(&bind_addr).await?) },
        |e, duration| {
            warn!("{:#}. Retry in {:?}", e, duration);
        },
        &mut shutdown_rx,
    )
    .await
    .with_context(|| "Failed to listen for the service")?;

    info!("Listening at {}", &bind_addr);

    let cmd = bincode::serialize(&DataChannelCmd::StartForwardUdp).unwrap();

    let mut conn = data_ch_rx
        .recv()
        .await
        .ok_or_else(|| anyhow!("No available data channels"))?;
    write_and_flush(&mut conn, &cmd).await?;

    let mut buf = [0u8; UDP_BUFFER_SIZE];
    loop {
        tokio::select! {
            val = l.recv_from(&mut buf) => {
                let (n, from) = val?;
                UdpTraffic::write_slice(&mut conn, from, &buf[..n]).await?;
            },
            hdr_len = conn.read_u8() => {
                let t = UdpTraffic::read(&mut conn, hdr_len?).await?;
                l.send_to(&t.data, t.from).await?;
            }
            _ = shutdown_rx.recv() => {
                break;
            }
        }
    }

    debug!("UDP pool dropped");

    Ok(())
}

/// Run the HTTP virtual host listener for routing HTTP requests to services
async fn run_http_vhost_listener<T: 'static + Transport>(
    bind_addr: String,
    control_channels: Arc<RwLock<ControlChannelMap<T>>>,
    services: Arc<RwLock<HashMap<ServiceDigest, ServerServiceConfig>>>,
    vhost_router: Arc<RwLock<VhostRouter>>,
    custom_404_page: Option<String>,
    mut shutdown_rx: broadcast::Receiver<bool>,
) -> Result<()> {
    let listener = TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("Failed to bind HTTP vhost listener at {}", bind_addr))?;
    info!("HTTP vhost listener at {}", bind_addr);

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((mut stream, _peer_addr)) => {
                        let control_channels = control_channels.clone();
                        let _services = services.clone();
                        let vhost_router = vhost_router.clone();
                        let custom_404 = custom_404_page.clone();

                        tokio::spawn(async move {
                            // Read HTTP header
                            let header_buf = match http_proxy::read_http_header(&mut stream).await {
                                Ok(buf) => buf,
                                Err(e) => {
                                    debug!("Failed to read HTTP header: {:#}", e);
                                    return;
                                }
                            };

                            // Parse to extract Host
                            let request_info = match http_proxy::parse_http_request(&header_buf) {
                                Ok(info) => info,
                                Err(e) => {
                                    debug!("Failed to parse HTTP request: {:#}", e);
                                    return;
                                }
                            };

                            // Route based on Host header
                            let router = vhost_router.read().await;
                            let route = router.match_route(&request_info.host, &request_info.path);

                            match route {
                                Some(route) => {
                                    // Check HTTP basic auth if configured
                                    if let (Some(user), Some(pass)) = (&route.http_user, &route.http_password) {
                                        if !http_proxy::validate_basic_auth(&request_info.headers, user, pass) {
                                            let _ = http_proxy::send_401(&mut stream).await;
                                            return;
                                        }
                                    }

                                    let service_name = route.service_name.clone();
                                    let service_digest = protocol::digest(service_name.as_bytes());
                                    drop(router);

                                    // Find the control channel for this service
                                    let channels = control_channels.read().await;
                                    if let Some(handle) = channels.get1(&service_digest) {
                                        // Request a data channel
                                        if handle.data_ch_req_tx.send(true).is_err() {
                                            let _ = http_proxy::send_502(&mut stream).await;
                                            return;
                                        }
                                        drop(channels);

                                        info!("HTTP request for {} routed to {}", request_info.host, service_name);
                                    } else {
                                        drop(channels);
                                        let _ = http_proxy::send_502(&mut stream).await;
                                    }
                                }
                                None => {
                                    drop(router);
                                    let _ = http_proxy::send_404(&mut stream, custom_404.as_deref()).await;
                                }
                            }
                        });
                    }
                    Err(e) => {
                        error!("HTTP vhost accept error: {}", e);
                    }
                }
            }
            _ = shutdown_rx.recv() => {
                info!("HTTP vhost listener shutting down");
                break;
            }
        }
    }
    Ok(())
}
