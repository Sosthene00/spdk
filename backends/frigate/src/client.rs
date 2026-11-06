use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use bitcoin::absolute::Height;
use bitcoin::constants::ChainHash;
use bitcoin::{BlockHash, Network, Txid};
use electrum_streaming_client::response::{FullTx, HeaderResp, HeadersSubscribeResp};
use electrum_streaming_client::{
    AsyncClient, ElectrumScriptHash, ElectrumScriptStatus, Event, request,
};
use futures::channel::mpsc::UnboundedReceiver;
use log::{debug, info, warn};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{self};

/// Number of attempts per request before the failure is surfaced to the caller.
const REQUEST_ATTEMPTS: u32 = 3;
/// Backoff before request retry `n`: `REQUEST_RETRY_BACKOFF * n`.
const REQUEST_RETRY_BACKOFF: Duration = Duration::from_millis(500);

/// Sends one request with the client's request timeout, retrying it up to
/// [`REQUEST_ATTEMPTS`] attempts with a `REQUEST_RETRY_BACKOFF * attempt`
/// backoff between attempts.
///
/// `$req` is re-evaluated on every attempt (`send_request` consumes the
/// request), so it must be a cheap request-building expression.
macro_rules! retry_request {
    ($self:ident, $what:literal, $($req:tt)*) => {{
        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            let result = timeout($self.request_timeout, $self.client.send_request($($req)*))
                .await
                .map_err(|_| FrigateError::Timeout(format!("{} timed out", $what)))
                .and_then(|response| {
                    response.map_err(|e| FrigateError::Request(format!("{} failed: {e}", $what)))
                });
            match result {
                Ok(response) => break Ok(response),
                Err(err) => {
                    if attempt >= REQUEST_ATTEMPTS {
                        break Err(err);
                    }
                    warn!("{err}; retrying in {:?}", REQUEST_RETRY_BACKOFF * attempt);
                    sleep(REQUEST_RETRY_BACKOFF * attempt).await;
                }
            }
        }
    }};
}

pub struct FrigateClient {
    pub client: AsyncClient,
    pub events: UnboundedReceiver<Event>,
    pub worker: JoinHandle<Result<(), std::io::Error>>,
    pub request_timeout: Duration,
    protocol_version: String,
    /// Consecutive `get_transaction` calls whose request retries were all
    /// exhausted; every successful fetch resets it to zero. The scanner ends
    /// the scan when the count exceeds its budget, treating the connection as
    /// broken: a connection that fails every transaction fetch keeps the
    /// event stream alive, so this counter is the only broken-connection
    /// signal the scanner has.
    consecutive_tx_fetch_failures: AtomicU32,
}

#[derive(Debug)]
pub enum FrigateError {
    Connection(String),
    Timeout(String),
    Request(String),
}

type Result<T, E = FrigateError> = std::result::Result<T, E>;

impl std::fmt::Display for FrigateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connection(msg) => write!(f, "connection error: {msg}"),
            Self::Timeout(msg) => write!(f, "request timeout: {msg}"),
            Self::Request(msg) => write!(f, "request error: {msg}"),
        }
    }
}

impl std::error::Error for FrigateError {}

impl FrigateClient {
    /// Default timeout for the version handshake and later requests.
    pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

    /// Connects to a Frigate electrum server and negotiates `server.version`
    /// before returning.
    ///
    /// `host_url` is either `host:port` for a plain TCP connection or
    /// `ssl://host:port` for TLS. The scan private key crosses the wire on
    /// every subscribe, so endpoints outside a trusted LAN must be reached
    /// over `ssl://`; TLS certificates are verified against the webpki-roots
    /// public trust store with SNI taken from the host part of the URL.
    ///
    /// `request_timeout` applies to that handshake and to every later request.
    /// The handshake is the first request on the connection. If it fails, the
    /// reader task is aborted.
    pub async fn connect(host_url: &str, request_timeout: Option<Duration>) -> Result<Self> {
        let request_timeout = request_timeout.unwrap_or(Self::DEFAULT_REQUEST_TIMEOUT);
        let (reader, writer) = match host_url.strip_prefix("ssl://") {
            Some(host) => Self::connect_tls(host).await?,
            None => Self::connect_plain(host_url).await?,
        };

        let mut client = Self::new(reader, writer);
        client.request_timeout = request_timeout;

        let protocol_version = match negotiate_version(&client.client, request_timeout).await {
            Ok(protocol_version) => protocol_version,
            Err(err) => {
                client.worker.abort();
                return Err(err);
            }
        };
        client.protocol_version = protocol_version;

        Ok(client)
    }

    /// Plain TCP connect: behavior identical to before TLS support existed.
    async fn connect_plain(
        host_url: &str,
    ) -> Result<(
        Box<dyn AsyncRead + Send + Unpin>,
        Box<dyn AsyncWrite + Send + Unpin>,
    )> {
        let stream = TcpStream::connect(host_url).await.map_err(|err| {
            FrigateError::Connection(format!("can't connect to socket '{host_url}': {err}"))
        })?;

        let (reader, writer) = stream.into_split();
        Ok((Box::new(reader), Box::new(writer)))
    }

    /// TLS connect for the host part of an `ssl://host:port` URL (the prefix
    /// is already stripped). Plain TCP is wrapped with rustls; the negotiated
    /// TLS stream is split into read/write halves for the streaming client.
    async fn connect_tls(
        host: &str,
    ) -> Result<(
        Box<dyn AsyncRead + Send + Unpin>,
        Box<dyn AsyncWrite + Send + Unpin>,
    )> {
        let (server_name, port) = host.rsplit_once(':').ok_or_else(|| {
            FrigateError::Connection(format!("ssl:// URL '{host}' must be 'ssl://host:port'"))
        })?;
        let port: u16 = port.parse().map_err(|err| {
            FrigateError::Connection(format!("invalid port in ssl:// URL '{host}': {err}"))
        })?;

        let stream = TcpStream::connect((server_name, port))
            .await
            .map_err(|err| {
                FrigateError::Connection(format!("can't connect to socket '{host}': {err}"))
            })?;

        let roots = webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .cloned()
            .collect::<rustls::RootCertStore>();
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

        let server_name = ServerName::try_from(server_name.to_owned()).map_err(|err| {
            FrigateError::Connection(format!("invalid TLS server name '{server_name}': {err}"))
        })?;

        let tls = connector
            .connect(server_name, stream)
            .await
            .map_err(|err| {
                FrigateError::Connection(format!("TLS handshake with '{host}' failed: {err}"))
            })?;

        let (reader, writer) = tokio::io::split(tls);
        Ok((Box::new(reader), Box::new(writer)))
    }

    fn new<R, W>(reader: R, writer: W) -> Self
    where
        R: AsyncRead + Send + Unpin + 'static,
        W: AsyncWrite + Send + Unpin + 'static,
    {
        let (client, events, worker) = AsyncClient::new_tokio(reader, writer);

        Self {
            client,
            events,
            worker: tokio::spawn(worker),
            request_timeout: Self::DEFAULT_REQUEST_TIMEOUT,
            protocol_version: String::new(),
            consecutive_tx_fetch_failures: AtomicU32::new(0),
        }
    }

    /// Protocol version negotiated with the server during [`Self::connect`].
    pub fn version(&self) -> &str {
        &self.protocol_version
    }

    /// Number of consecutive `get_transaction` calls whose request retries
    /// were all exhausted (a successful fetch resets the count to zero).
    pub fn consecutive_tx_fetch_failures(&self) -> u32 {
        self.consecutive_tx_fetch_failures.load(Ordering::Relaxed)
    }

    /// Returns the network this server is following.
    ///
    /// Identified from the genesis hash in `server.features`. Only the networks known to
    /// rust-bitcoin are recognized: mainnet, testnet3, testnet4, the default signet, and regtest.
    /// A custom signet genesis hash is rejected.
    ///
    /// NOTE: frigate <= 1.4.1 servers reject `server.features` with an internal error, so
    /// this call fails against them; the scanner does not use it.
    pub async fn network(&self) -> Result<Network> {
        let res = timeout(
            self.request_timeout,
            self.client.send_request(request::Features),
        )
        .await
        .map_err(|_| FrigateError::Timeout("Features request timed out".to_owned()))?
        .map_err(|e| FrigateError::Request(format!("Features request failed: {e}")))?;

        let chain_hash = ChainHash::from_genesis_block_hash(res.genesis_hash);
        Network::from_chain_hash(chain_hash).ok_or_else(|| {
            FrigateError::Request(format!("unrecognized genesis hash {}", res.genesis_hash))
        })
    }

    /// Returns the height, hash and header of the chain tip.
    ///
    /// Electrum exposes the tip through `blockchain.headers.subscribe`. That call also subscribes
    /// this connection to later tip notifications, which arrive on [`Self::events`]. There is no
    /// headers unsubscribe, so those notifications continue until the connection closes. Drain
    /// `events`, or use a connection that is not shared with a scan, if this client stays open.
    pub async fn subscribe_header(&self) -> Result<HeadersSubscribeResp> {
        retry_request!(self, "Headers subscribe request", request::HeadersSubscribe)
    }

    /// Returns the `(height, block hash)` of the chain tip, subscribing to tip
    /// notifications as a side effect (see [`Self::subscribe_header`]).
    pub async fn block_height(&self) -> Result<(Height, BlockHash)> {
        let tip = self.subscribe_header().await?;
        let height = Height::from_consensus(tip.height).map_err(|err| {
            FrigateError::Request(format!("invalid tip height {}: {err}", tip.height))
        })?;
        Ok((height, tip.header.block_hash()))
    }

    /// Fetches the block header at `height`, retrying transient failures.
    pub async fn get_block_header(&self, height: u32) -> Result<HeaderResp> {
        retry_request!(self, "Header request", request::Header { height })
    }

    /// Fetches a full transaction by txid, retrying transient failures.
    ///
    /// A call whose request retries were all exhausted counts as one
    /// consecutive transaction-fetch failure on this client; a successful
    /// call resets the count to zero. Callers use the count to detect a
    /// broken connection.
    pub async fn get_transaction(&self, txid: Txid) -> Result<FullTx> {
        let result = retry_request!(self, "GetTx request", request::GetTx { txid });
        match result {
            Ok(full_tx) => {
                self.consecutive_tx_fetch_failures
                    .store(0, Ordering::Relaxed);
                Ok(full_tx)
            }
            Err(err) => {
                self.consecutive_tx_fetch_failures
                    .fetch_add(1, Ordering::Relaxed);
                Err(err)
            }
        }
    }

    /// Make a request to the Frigate electrum server to subscribe to the outputs beloging to the
    /// given silent payment address Once the server receives the request notification will be
    /// sent to the client everytime an ouput is found.
    ///
    /// See: <https://github.com/sparrowwallet/frigate#blockchainsilentpaymentssubscribe>
    pub async fn subscribe(&self, subscribe_req: request::SpSubscribe) -> Result<String> {
        debug!("Sending subscribe event request...");

        let res = timeout(
            self.request_timeout,
            self.client.send_request(subscribe_req),
        )
        .await
        .map_err(|_| FrigateError::Timeout("Subscribe request timed out".to_owned()))?
        .map_err(|e| FrigateError::Request(format!("Subscribe request failed: {e}")))?;

        info!("Subscribed to silent payment address: {res}");
        Ok(res)
    }

    pub async fn unsubscribe(&self, unsub_req: request::SpUnsubscribe) -> Result<()> {
        let res = timeout(self.request_timeout, self.client.send_request(unsub_req))
            .await
            .map_err(|_| FrigateError::Timeout("Unsubscribe request timed out".to_owned()))?
            .map_err(|e| FrigateError::Request(format!("Unsubscribe request failed: {e}")))?;

        info!("Unsubscribed to silent payment address: {res:?}");
        Ok(())
    }

    /// Subscribes to `script_hash`, retrying transient failures.
    pub async fn scripthash_subscribe(
        &self,
        sub_req: request::ScriptHashSubscribe,
    ) -> Result<Option<ElectrumScriptStatus>> {
        let res = retry_request!(
            self,
            "Script hash subscription",
            request::ScriptHashSubscribe {
                script_hash: sub_req.script_hash
            }
        )?;

        info!("Subscribed to script: {res:?}");
        Ok(res)
    }

    /// Fetches the history of `script_hash`, retrying transient failures.
    pub async fn get_history(
        &self,
        script_hash: ElectrumScriptHash,
    ) -> Result<Vec<electrum_streaming_client::response::Tx>> {
        retry_request!(
            self,
            "Script history request",
            request::GetHistory { script_hash }
        )
    }
}

async fn negotiate_version(client: &AsyncClient, request_timeout: Duration) -> Result<String> {
    debug!("Sending version request to Frigate server...");
    let res = timeout(
        request_timeout,
        client.send_request(request::ServerVersion {
            client_name: "spdk".into(),
            protocol_version: request::SupportedVersion::Range(["1.3.2".into(), "1.4.1".into()]),
        }),
    )
    .await
    .map_err(|_| FrigateError::Timeout("Version request timed out".to_owned()))?
    .map_err(|e| FrigateError::Request(format!("Version request failed: {e}")))?;
    Ok(res.protocol_version)
}
