use std::sync::Arc;
use std::time::Duration;

use bitcoin::Txid;
use electrum_streaming_client::response::{FullTx, HeaderResp};
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

/// Sends one request with the client's per-request timeout, retrying it up to
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
    protocol_version: Option<String>,
    /// Consecutive `get_transaction` calls whose request retries were all
    /// exhausted; every successful fetch resets it to zero. The scanner ends
    /// the scan task when the count exceeds ten, treating the connection as
    /// broken (see `FrigateScanner`'s failure semantics).
    consecutive_tx_fetch_failures: u32,
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
    /// Connects to a Frigate electrum server.
    ///
    /// `host_url` is either `host:port` for a plain TCP connection (unchanged
    /// behavior, no TLS handshake attempted) or `ssl://host:port` for TLS. The
    /// scan private key crosses the wire on every subscribe, so endpoints
    /// outside a trusted LAN must be reached over `ssl://`; TLS certificates
    /// are verified against the webpki-roots public trust store with SNI taken
    /// from the host part of the URL.
    pub async fn connect(host_url: &str) -> Result<Self> {
        match host_url.strip_prefix("ssl://") {
            Some(host) => Self::connect_tls(host).await,
            None => Self::connect_plain(host_url).await,
        }
    }

    /// Plain TCP connect: behavior identical to before TLS support existed.
    async fn connect_plain(host_url: &str) -> Result<Self> {
        let stream = TcpStream::connect(host_url).await.map_err(|err| {
            FrigateError::Connection(format!("can't connect to socket '{host_url}': {err}"))
        })?;

        let (reader, writer) = stream.into_split();
        Ok(Self::new(reader, writer))
    }

    /// TLS connect for the host part of an `ssl://host:port` URL (the prefix
    /// is already stripped). Plain TCP is wrapped with rustls; the negotiated
    /// TLS stream is split into read/write halves for the streaming client.
    async fn connect_tls(host: &str) -> Result<Self> {
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

        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
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
        Ok(Self::new(reader, writer))
    }

    fn new<R, W>(reader: R, writer: W) -> Self
    where
        R: AsyncRead + Send + Unpin + 'static,
        W: AsyncWrite + Send + Unpin + 'static,
    {
        let (client, events, worker) = AsyncClient::new_tokio(reader, writer);

        let worker = tokio::spawn(worker);

        Self {
            client,
            events,
            worker,
            request_timeout: Duration::from_secs(10),
            protocol_version: None,
            consecutive_tx_fetch_failures: 0,
        }
    }

    /// Sets a custom request timeout for this client.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Number of consecutive `get_transaction` calls whose request retries
    /// were all exhausted (a successful fetch resets the count to zero).
    pub const fn consecutive_tx_fetch_failures(&self) -> u32 {
        self.consecutive_tx_fetch_failures
    }

    /// Fetches the block header at `height`, retrying transient failures.
    pub async fn get_block_header(&mut self, height: u32) -> Result<HeaderResp> {
        self.version().await?;

        retry_request!(self, "Header request", request::Header { height })
    }

    /// Fetches a full transaction by txid, retrying transient failures.
    ///
    /// A call whose request retries were all exhausted counts as one
    /// consecutive transaction-fetch failure on this client; a successful
    /// call resets the count to zero. Callers use the count to detect a
    /// broken connection (see `FrigateScanner`'s failure semantics).
    pub async fn get_transaction(&mut self, txid: Txid) -> Result<FullTx> {
        self.version().await?;

        let result = retry_request!(self, "GetTx request", request::GetTx { txid });
        match result {
            Ok(full_tx) => {
                self.consecutive_tx_fetch_failures = 0;
                Ok(full_tx)
            }
            Err(err) => {
                self.consecutive_tx_fetch_failures += 1;
                Err(err)
            }
        }
    }

    /// Negotiate the Frigate protocol version once and cache the result.
    ///
    /// The negotiation is sent as the first request on the connection. Later calls return the
    /// cached version without sending another request.
    pub async fn version(&mut self) -> Result<String> {
        if let Some(protocol_version) = &self.protocol_version {
            return Ok(protocol_version.clone());
        }

        debug!("Sending version request to Frigate server...");
        let res = timeout(
            self.request_timeout,
            self.client.send_request(request::ServerVersion {
                client_name: "spdk".into(),
                protocol_version: request::SupportedVersion::Range([
                    "1.3.2".into(),
                    "1.4.1".into(),
                ]),
            }),
        )
        .await
        .map_err(|_| FrigateError::Timeout("Version request timed out".to_owned()))?
        .map_err(|e| FrigateError::Request(format!("Version request failed: {e}")))?;
        self.protocol_version = Some(res.protocol_version.clone());
        Ok(res.protocol_version)
    }

    /// Make a request to the Frigate electrum server to subscribe to the outputs beloging to the
    /// given silent payment address Once the server receives the request notification will be
    /// sent to the client everytime an ouput is found.
    ///
    /// See: <https://github.com/sparrowwallet/frigate#blockchainsilentpaymentssubscribe>
    ///
    /// A failure here is not fatal for the scan: the scanner retries the whole connect +
    /// subscribe with backoff (see `FrigateScanner`'s failure semantics).
    pub async fn subscribe(&mut self, subscribe_req: request::SpSubscribe) -> Result<String> {
        self.version().await?;
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

    pub async fn unsubscribe(&mut self, unsub_req: request::SpUnsubscribe) -> Result<()> {
        self.version().await?;

        let res = timeout(self.request_timeout, self.client.send_request(unsub_req))
            .await
            .map_err(|_| FrigateError::Timeout("Unsubscribe request timed out".to_owned()))?
            .map_err(|e| FrigateError::Request(format!("Unsubscribe request failed: {e}")))?;

        info!("Unsubscribed to silent payment address: {res:?}");
        Ok(())
    }

    /// Subscribes to `script_hash`, retrying transient failures.
    pub async fn scripthash_subscribe(
        &mut self,
        sub_req: request::ScriptHashSubscribe,
    ) -> Result<Option<ElectrumScriptStatus>> {
        self.version().await?;
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
        &mut self,
        script_hash: ElectrumScriptHash,
    ) -> Result<Vec<electrum_streaming_client::response::Tx>> {
        self.version().await?;

        retry_request!(
            self,
            "Script history request",
            request::GetHistory { script_hash }
        )
    }
}
