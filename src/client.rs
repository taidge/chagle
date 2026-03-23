use crate::config::{ClientConfig, ClientServiceConfig, Config, ServiceType, TransportType};
use crate::config_watcher::{ClientServiceChange, ConfigChange};
use crate::helper::udp_connect;
use crate::protocol::Hello::{self, *};
use crate::protocol::{
    self, Ack, Auth, CURRENT_PROTO_VERSION, ControlChannelCmd, DataChannelCmd, HASH_WIDTH_IN_BYTES,
    UdpTraffic, read_ack, read_control_cmd, read_data_cmd, read_hello,
};
use crate::transport::{AddrMaybeCached, SocketOpts, TcpTransport, Transport};
use anyhow::{Context, Result, anyhow, bail};
use backoff::ExponentialBackoff;
use backoff::backoff::Backoff;
use backoff::future::retry_notify;
use bytes::{Bytes, BytesMut};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{RwLock, broadcast, mpsc, oneshot};
use tokio::time::{self, Duration, Instant};
use tracing::{Instrument, Span, debug, error, info, instrument, trace, warn};

#[cfg(feature = "noise")]
use crate::transport::NoiseTransport;
#[cfg(any(feature = "native-tls", feature = "rustls"))]
use crate::transport::TlsTransport;
#[cfg(any(feature = "websocket-native-tls", feature = "websocket-rustls"))]
use crate::transport::WebsocketTransport;

use crate::constants::{UDP_BUFFER_SIZE, UDP_SENDQ_SIZE, UDP_TIMEOUT, run_control_chan_backoff};

// The entrypoint of running a client
pub async fn run_client(
    config: Config,
    shutdown_rx: broadcast::Receiver<bool>,
    update_rx: mpsc::Receiver<ConfigChange>,
) -> Result<()> {
    let config = config.client.ok_or_else(|| {
        anyhow!(
        "Try to run as a client, but the configuration is missing. Please add the `[client]` block"
    )
    })?;

    match config.transport.transport_type {
        TransportType::Tcp => {
            let mut client = Client::<TcpTransport>::from(config).await?;
            client.run(shutdown_rx, update_rx).await
        }
        TransportType::Tls => {
            #[cfg(any(feature = "native-tls", feature = "rustls"))]
            {
                let mut client = Client::<TlsTransport>::from(config).await?;
                client.run(shutdown_rx, update_rx).await
            }
            #[cfg(not(any(feature = "native-tls", feature = "rustls")))]
            crate::helper::feature_neither_compile("native-tls", "rustls")
        }
        TransportType::Noise => {
            #[cfg(feature = "noise")]
            {
                let mut client = Client::<NoiseTransport>::from(config).await?;
                client.run(shutdown_rx, update_rx).await
            }
            #[cfg(not(feature = "noise"))]
            crate::helper::feature_not_compile("noise")
        }
        TransportType::Websocket => {
            #[cfg(any(feature = "websocket-native-tls", feature = "websocket-rustls"))]
            {
                let mut client = Client::<WebsocketTransport>::from(config).await?;
                client.run(shutdown_rx, update_rx).await
            }
            #[cfg(not(any(feature = "websocket-native-tls", feature = "websocket-rustls")))]
            crate::helper::feature_neither_compile("websocket-native-tls", "websocket-rustls")
        }
        TransportType::Kcp => crate::helper::feature_not_compile("kcp"),
        TransportType::Quic => crate::helper::feature_not_compile("quic"),
    }
}

type ServiceDigest = protocol::Digest;
type Nonce = protocol::Digest;

struct Client<T: Transport> {
    config: ClientConfig,
    service_handles: HashMap<String, ControlChannelHandle>,
    transport: Arc<T>,
}

impl<T: 'static + Transport> Client<T> {
    async fn from(config: ClientConfig) -> Result<Client<T>> {
        let transport =
            Arc::new(T::new(&config.transport).with_context(|| "Failed to create the transport")?);
        Ok(Client {
            config,
            service_handles: HashMap::new(),
            transport,
        })
    }

    async fn run(
        &mut self,
        mut shutdown_rx: broadcast::Receiver<bool>,
        mut update_rx: mpsc::Receiver<ConfigChange>,
    ) -> Result<()> {
        let start_filter = self.config.start.as_ref();

        for (name, config) in &self.config.services {
            // Skip disabled services
            if !config.is_enabled() {
                debug!("Service {} is disabled, skipping", name);
                continue;
            }

            // Apply start filter
            if let Some(start) = start_filter
                && !start.contains(name) {
                    debug!("Service {} not in start list, skipping", name);
                    continue;
                }

            // Skip visitor services (they don't create control channels)
            if config.is_visitor() {
                info!("Service {} is a visitor, starting visitor mode", name);
                let _handle = VisitorHandle::new(
                    (*config).clone(),
                    self.config.remote_addr.clone(),
                    self.transport.clone(),
                );
                continue;
            }

            let handle = ControlChannelHandle::new(
                (*config).clone(),
                self.config.remote_addr.clone(),
                self.transport.clone(),
                self.config.heartbeat_timeout,
            );
            self.service_handles.insert(name.clone(), handle);
        }

        // Wait for the shutdown signal
        loop {
            tokio::select! {
                val = shutdown_rx.recv() => {
                    match val {
                        Ok(_) => {}
                        Err(err) => {
                            error!("Unable to listen for shutdown signal: {}", err);
                        }
                    }
                    break;
                },
                e = update_rx.recv() => {
                    if let Some(e) = e {
                        self.handle_hot_reload(e).await;
                    }
                }
            }
        }

        // Shutdown all services
        for (_, handle) in self.service_handles.drain() {
            handle.shutdown();
        }

        Ok(())
    }

    async fn handle_hot_reload(&mut self, e: ConfigChange) {
        match e {
            ConfigChange::ClientChange(client_change) => match client_change {
                ClientServiceChange::Add(cfg) => {
                    if !cfg.is_enabled() {
                        return;
                    }
                    let name = cfg.name.clone();
                    let handle = ControlChannelHandle::new(
                        *cfg,
                        self.config.remote_addr.clone(),
                        self.transport.clone(),
                        self.config.heartbeat_timeout,
                    );
                    let _ = self.service_handles.insert(name, handle);
                }
                ClientServiceChange::Delete(s) => {
                    let _ = self.service_handles.remove(&s);
                }
            },
            ignored => warn!("Ignored {:?} since running as a client", ignored),
        }
    }
}

struct RunDataChannelArgs<T: Transport> {
    session_key: Nonce,
    remote_addr: AddrMaybeCached,
    connector: Arc<T>,
    socket_opts: SocketOpts,
    service: ClientServiceConfig,
}

async fn do_data_channel_handshake<T: Transport>(
    args: Arc<RunDataChannelArgs<T>>,
) -> Result<T::Stream> {
    let backoff = ExponentialBackoff {
        max_interval: Duration::from_millis(100),
        max_elapsed_time: Some(Duration::from_secs(10)),
        ..Default::default()
    };

    let mut conn: T::Stream = retry_notify(
        backoff,
        || async {
            args.connector
                .connect(&args.remote_addr)
                .await
                .with_context(|| format!("Failed to connect to {}", &args.remote_addr))
                .map_err(backoff::Error::transient)
        },
        |e, duration| {
            warn!("{:#}. Retry in {:?}", e, duration);
        },
    )
    .await?;

    T::hint(&conn, args.socket_opts);

    let v: &[u8; HASH_WIDTH_IN_BYTES] = args.session_key[..].try_into().unwrap();
    let hello = Hello::DataChannelHello(CURRENT_PROTO_VERSION, v.to_owned());
    conn.write_all(&bincode::serialize(&hello).unwrap()).await?;
    conn.flush().await?;

    Ok(conn)
}

async fn run_data_channel<T: Transport>(args: Arc<RunDataChannelArgs<T>>) -> Result<()> {
    let mut conn = do_data_channel_handshake(args.clone()).await?;

    match read_data_cmd(&mut conn).await? {
        DataChannelCmd::StartForwardTcp => {
            if !matches!(
                args.service.service_type,
                ServiceType::Tcp
                    | ServiceType::Http
                    | ServiceType::Https
                    | ServiceType::Tcpmux
                    | ServiceType::Stcp
            ) {
                bail!(
                    "Unexpected TCP forward for service type {:?}",
                    args.service.service_type
                )
            }
            run_data_channel_for_tcp::<T>(conn, &args.service.local_addr).await?;
        }
        DataChannelCmd::StartForwardUdp => {
            if !matches!(
                args.service.service_type,
                ServiceType::Udp | ServiceType::Sudp
            ) {
                bail!(
                    "Unexpected UDP forward for service type {:?}",
                    args.service.service_type
                )
            }
            run_data_channel_for_udp::<T>(conn, &args.service.local_addr, args.service.prefer_ipv6)
                .await?;
        }
        DataChannelCmd::StartForwardHttp => {
            run_data_channel_for_tcp::<T>(conn, &args.service.local_addr).await?;
        }
        DataChannelCmd::StartForwardStcp => {
            run_data_channel_for_tcp::<T>(conn, &args.service.local_addr).await?;
        }
    }
    Ok(())
}

#[instrument(skip(conn))]
async fn run_data_channel_for_tcp<T: Transport>(
    mut conn: T::Stream,
    local_addr: &str,
) -> Result<()> {
    debug!("New data channel starts forwarding");

    let mut local = TcpStream::connect(local_addr)
        .await
        .with_context(|| format!("Failed to connect to {}", local_addr))?;
    let _ = copy_bidirectional(&mut conn, &mut local).await;
    Ok(())
}

type UdpPortMap = Arc<RwLock<HashMap<SocketAddr, mpsc::Sender<Bytes>>>>;

#[instrument(skip(conn))]
async fn run_data_channel_for_udp<T: Transport>(
    conn: T::Stream,
    local_addr: &str,
    prefer_ipv6: bool,
) -> Result<()> {
    debug!("New data channel starts forwarding");

    let port_map: UdpPortMap = Arc::new(RwLock::new(HashMap::new()));
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<UdpTraffic>(UDP_SENDQ_SIZE);

    let (mut rd, mut wr) = io::split(conn);

    tokio::spawn(async move {
        while let Some(t) = outbound_rx.recv().await {
            trace!("outbound {:?}", t);
            if let Err(e) = t
                .write(&mut wr)
                .await
                .with_context(|| "Failed to forward UDP traffic to the server")
            {
                debug!("{:?}", e);
                break;
            }
        }
    });

    loop {
        let hdr_len = rd.read_u8().await?;
        let packet = UdpTraffic::read(&mut rd, hdr_len)
            .await
            .with_context(|| "Failed to read UDPTraffic from the server")?;
        let m = port_map.read().await;

        if m.get(&packet.from).is_none() {
            drop(m);
            let mut m = port_map.write().await;

            match udp_connect(local_addr, prefer_ipv6).await {
                Ok(s) => {
                    let (inbound_tx, inbound_rx) = mpsc::channel(UDP_SENDQ_SIZE);
                    m.insert(packet.from, inbound_tx);
                    tokio::spawn(run_udp_forwarder(
                        s,
                        inbound_rx,
                        outbound_tx.clone(),
                        packet.from,
                        port_map.clone(),
                    ));
                }
                Err(e) => {
                    error!("{:#}", e);
                }
            }
        }

        let m = port_map.read().await;
        if let Some(tx) = m.get(&packet.from) {
            let _ = tx.send(packet.data).await;
        }
    }
}

#[instrument(skip_all, fields(from))]
async fn run_udp_forwarder(
    s: UdpSocket,
    mut inbound_rx: mpsc::Receiver<Bytes>,
    outbount_tx: mpsc::Sender<UdpTraffic>,
    from: SocketAddr,
    port_map: UdpPortMap,
) -> Result<()> {
    debug!("Forwarder created");
    let mut buf = BytesMut::new();
    buf.resize(UDP_BUFFER_SIZE, 0);

    loop {
        tokio::select! {
            data = inbound_rx.recv() => {
                if let Some(data) = data {
                    s.send(&data).await?;
                } else {
                    break;
                }
            },
            val = s.recv(&mut buf) => {
                let len = match val {
                    Ok(v) => v,
                    Err(_) => break
                };

                let t = UdpTraffic{
                    from,
                    data: Bytes::copy_from_slice(&buf[..len])
                };

                outbount_tx.send(t).await?;
            },
            _ = time::sleep(Duration::from_secs(UDP_TIMEOUT)) => {
                break;
            }
        }
    }

    let mut port_map = port_map.write().await;
    port_map.remove(&from);

    debug!("Forwarder dropped");
    Ok(())
}

struct ControlChannel<T: Transport> {
    digest: ServiceDigest,
    service: ClientServiceConfig,
    shutdown_rx: oneshot::Receiver<u8>,
    remote_addr: String,
    transport: Arc<T>,
    heartbeat_timeout: u64,
}

struct ControlChannelHandle {
    shutdown_tx: oneshot::Sender<u8>,
}

impl<T: 'static + Transport> ControlChannel<T> {
    #[instrument(skip_all)]
    async fn run(&mut self) -> Result<()> {
        let mut remote_addr = AddrMaybeCached::new(&self.remote_addr);
        remote_addr.resolve().await?;

        let mut conn = self
            .transport
            .connect(&remote_addr)
            .await
            .with_context(|| format!("Failed to connect to {}", &self.remote_addr))?;
        T::hint(&conn, SocketOpts::for_control_channel());

        debug!("Sending hello");
        let hello_send =
            Hello::ControlChannelHello(CURRENT_PROTO_VERSION, self.digest[..].try_into().unwrap());
        conn.write_all(&bincode::serialize(&hello_send).unwrap())
            .await?;
        conn.flush().await?;

        debug!("Reading hello");
        let nonce = match read_hello(&mut conn).await? {
            ControlChannelHello(_, d) => d,
            _ => {
                bail!("Unexpected type of hello");
            }
        };

        debug!("Sending auth");
        let mut concat = Vec::from(self.service.token.as_ref().unwrap().as_bytes());
        concat.extend_from_slice(&nonce);

        let session_key = protocol::digest(&concat);
        let auth = Auth(session_key);
        conn.write_all(&bincode::serialize(&auth).unwrap()).await?;
        conn.flush().await?;

        debug!("Reading ack");
        match read_ack(&mut conn).await? {
            Ack::Ok => {}
            v => {
                return Err(anyhow!("{}", v))
                    .with_context(|| format!("Authentication failed: {}", self.service.name));
            }
        }

        info!("Control channel established");

        let socket_opts = SocketOpts::from_client_cfg(&self.service);
        let data_ch_args = Arc::new(RunDataChannelArgs {
            session_key,
            remote_addr,
            connector: self.transport.clone(),
            socket_opts,
            service: self.service.clone(),
        });

        loop {
            tokio::select! {
                val = read_control_cmd(&mut conn) => {
                    let val = val?;
                    debug!( "Received {:?}", val);
                    match val {
                        ControlChannelCmd::CreateDataChannel => {
                            let args = data_ch_args.clone();
                            tokio::spawn(async move {
                                if let Err(e) = run_data_channel(args).await.with_context(|| "Failed to run the data channel") {
                                    warn!("{:#}", e);
                                }
                            }.instrument(Span::current()));
                        },
                        ControlChannelCmd::HeartBeat => ()
                    }
                },
                _ = time::sleep(Duration::from_secs(self.heartbeat_timeout)), if self.heartbeat_timeout != 0 => {
                    return Err(anyhow!("Heartbeat timed out"))
                }
                _ = &mut self.shutdown_rx => {
                    break;
                }
            }
        }

        info!("Control channel shutdown");
        Ok(())
    }
}

impl ControlChannelHandle {
    #[instrument(name="handle", skip_all, fields(service = %service.name))]
    fn new<T: 'static + Transport>(
        service: ClientServiceConfig,
        remote_addr: String,
        transport: Arc<T>,
        heartbeat_timeout: u64,
    ) -> ControlChannelHandle {
        let digest = protocol::digest(service.name.as_bytes());

        info!("Starting {}", hex::encode(digest));
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let mut retry_backoff = run_control_chan_backoff(service.retry_interval.unwrap());

        let mut s = ControlChannel {
            digest,
            service,
            shutdown_rx,
            remote_addr,
            transport,
            heartbeat_timeout,
        };

        tokio::spawn(
            async move {
                let mut start = Instant::now();

                while let Err(err) = s
                    .run()
                    .await
                    .with_context(|| "Failed to run the control channel")
                {
                    if s.shutdown_rx.try_recv() != Err(oneshot::error::TryRecvError::Empty) {
                        break;
                    }

                    if start.elapsed() > Duration::from_secs(3) {
                        retry_backoff.reset();
                    }

                    if let Some(duration) = retry_backoff.next_backoff() {
                        error!("{:#}. Retry in {:?}...", err, duration);
                        time::sleep(duration).await;
                    } else {
                        panic!("{:#}. Break", err);
                    }

                    start = Instant::now();
                }
            }
            .instrument(Span::current()),
        );

        ControlChannelHandle { shutdown_tx }
    }

    fn shutdown(self) {
        let _ = self.shutdown_tx.send(0u8);
    }
}

/// Handle for STCP/SUDP/XTCP visitor connections
struct VisitorHandle {
    _shutdown_tx: oneshot::Sender<u8>,
}

impl VisitorHandle {
    fn new<T: 'static + Transport>(
        service: ClientServiceConfig,
        remote_addr: String,
        transport: Arc<T>,
    ) -> VisitorHandle {
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let service_name = service.name.clone();

        tokio::spawn(async move {
            info!("Starting visitor for {}", service_name);

            // Visitors listen locally and forward to the remote STCP service
            let bind_addr = service.bind_addr.as_deref().unwrap_or("127.0.0.1");
            let bind_port = service.bind_port.unwrap_or(0);
            let listen_addr = format!("{}:{}", bind_addr, bind_port);

            let listener = match tokio::net::TcpListener::bind(&listen_addr).await {
                Ok(l) => l,
                Err(e) => {
                    error!("Visitor failed to bind {}: {}", listen_addr, e);
                    return;
                }
            };

            info!("Visitor listening at {}", listen_addr);

            let server_name = service.server_name.as_deref().unwrap_or(&service_name);
            let secret_key = service.secret_key.as_ref().map(|k| k.to_string());

            loop {
                tokio::select! {
                    result = listener.accept() => {
                        match result {
                            Ok((mut local_conn, peer_addr)) => {
                                debug!("Visitor connection from {}", peer_addr);

                                let transport = transport.clone();
                                let remote_addr = remote_addr.clone();
                                let server_name = server_name.to_string();
                                let secret_key = secret_key.clone();

                                tokio::spawn(async move {
                                    if let Err(e) = handle_visitor_connection::<T>(
                                        &mut local_conn,
                                        transport,
                                        &remote_addr,
                                        &server_name,
                                        secret_key.as_deref(),
                                    ).await {
                                        warn!("Visitor connection error: {:#}", e);
                                    }
                                });
                            }
                            Err(e) => {
                                error!("Visitor accept error: {}", e);
                            }
                        }
                    }
                    _ = &mut shutdown_rx => {
                        break;
                    }
                }
            }

            info!("Visitor for {} shutdown", service_name);
        });

        VisitorHandle {
            _shutdown_tx: shutdown_tx,
        }
    }
}

/// Handle a single visitor connection: authenticate with server and relay traffic
async fn handle_visitor_connection<T: Transport>(
    local_conn: &mut TcpStream,
    transport: Arc<T>,
    remote_addr: &str,
    server_name: &str,
    secret_key: Option<&str>,
) -> Result<()> {
    let mut remote = AddrMaybeCached::new(remote_addr);
    remote.resolve().await?;

    let mut conn = transport.connect(&remote).await?;

    // Send VisitorHello
    let digest = protocol::digest(server_name.as_bytes());
    let hello = Hello::VisitorHello(CURRENT_PROTO_VERSION, digest);
    conn.write_all(&bincode::serialize(&hello).unwrap()).await?;
    conn.flush().await?;

    // Read nonce from server
    let nonce = match read_hello(&mut conn).await? {
        ControlChannelHello(_, d) => d,
        _ => bail!("Unexpected response from server"),
    };

    // Send auth with secret_key
    let key = secret_key.ok_or_else(|| anyhow!("No secret_key configured for visitor"))?;
    let mut concat = Vec::from(key.as_bytes());
    concat.extend_from_slice(&nonce);
    let auth_digest = protocol::digest(&concat);
    let auth = Auth(auth_digest);
    conn.write_all(&bincode::serialize(&auth).unwrap()).await?;
    conn.flush().await?;

    // Read ack
    match read_ack(&mut conn).await? {
        Ack::Ok => {}
        v => bail!("Visitor authentication failed: {}", v),
    }

    // Relay traffic
    let _ = copy_bidirectional(&mut conn, local_conn).await;

    Ok(())
}
