use std::time::Duration;

use anyhow::{Context as _, Result};
use bitcoin::absolute::Height;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Amount, BlockHash, Txid};
use reqwest::{Client, Url};
use serde::de::DeserializeOwned;

use super::api_structs::{
    BlockHashResponse, BlockHeightResponse, FilterResponse, ForwardTxRequest, InfoResponse,
    SpentIndexResponse, UtxoResponse,
};

/// A blindbit server answered with an error we understood.
///
/// Blindbit backends report failures as `{"error": "<message>"}` bodies
/// (normally with a non-2xx status). Surfacing them typed — status plus the
/// server's own message — lets callers distinguish server-side rejections
/// from transport or parse failures instead of staring at serde noise like
/// "invalid type: map, expected a sequence".
#[derive(Debug)]
pub struct ServerError {
    pub status: u16,
    pub message: String,
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "blindbit server error (HTTP {}): {}",
            self.status, self.message
        )
    }
}

impl std::error::Error for ServerError {}

/// Detects a blindbit error envelope: a JSON *object* carrying an `error`
/// string. (A plain `serde` struct match is not enough — derived
/// deserializers also accept sequences positionally, which would swallow
/// single-element tweak arrays like `["03.."]` as `{"error": "03.."}`.)
fn error_envelope(text: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    value.as_object()?.get("error")?.as_str().map(str::to_owned)
}

/// Performs a GET and decodes the JSON body, treating blindbit error
/// envelopes (`{"error": ...}`) as typed [`ServerError`]s regardless of the
/// HTTP status — an error map is never a valid endpoint payload.
async fn get_json<T: DeserializeOwned>(client: &Client, url: Url) -> Result<T> {
    let res = client
        .get(url.clone())
        .timeout(Duration::from_secs(5))
        .send()
        .await?;
    decode_response::<T>(res, url).await
}

async fn decode_response<T: DeserializeOwned>(res: reqwest::Response, url: Url) -> Result<T> {
    let status = res.status();
    let text = res.text().await?;
    if let Some(message) = error_envelope(&text) {
        return Err(anyhow::Error::new(ServerError {
            status: status.as_u16(),
            message,
        }));
    }
    if !status.is_success() {
        anyhow::bail!("blindbit server returned HTTP {status} for {url}: {text}");
    }
    serde_json::from_str(&text)
        .with_context(|| format!("unexpected response body from {url}: {text}"))
}

/// Appends the dustLimit query only when the caller actually wants one.
///
/// Servers without dust-filter support reject the parameter outright
/// ("Server does not allow dustLimits") or silently ignore it; callers probe
/// `/info` and omit it when unsupported.
fn with_dust_limit(mut url: Url, dust_limit: Option<Amount>) -> Url {
    if let Some(dust_limit) = dust_limit {
        url.query_pairs_mut()
            .append_pair("dustLimit", &dust_limit.to_sat().to_string());
    }
    url
}

#[derive(Clone, Debug)]
pub struct BlindbitClient {
    client: Client,
    host_url: Url,
}

impl BlindbitClient {
    /// Creates a client from a blindbit host URL.
    ///
    /// The grammar mirrors the frigate client's lenient endpoint format:
    /// the scheme is optional and each backend defaults to its natural
    /// transport. Here a bare `host:port` (or `host:port/base/path`) is
    /// read as `http://`; an explicit `http://` or `https://` passes
    /// through; any other scheme is rejected with a clear error instead
    /// of failing obscurely at request time.
    pub fn new(host_url: &str) -> Result<Self> {
        const DEFAULT_SCHEME: &str = "http";

        let parsed = Url::parse(host_url);
        let mut host_url = match parsed {
            // Full URL with a host: use as-is (scheme validity checked below).
            Ok(url) if url.host_str().is_some() => url,
            // No scheme, or a scheme-like prefix without a host
            // (`localhost:8001` parses as scheme `localhost`): default it.
            _ => Url::parse(&format!("{DEFAULT_SCHEME}://{host_url}"))?,
        };

        match host_url.scheme() {
            "http" | "https" => {}
            other => anyhow::bail!(
                "unsupported scheme '{other}://' in blindbit url \
                 (expected http:// or https://, scheme optional): {host_url}"
            ),
        }

        let client = reqwest::Client::new();

        // we need a trailing slash, if not present we append it
        if !host_url.path().ends_with('/') {
            host_url.set_path(&format!("{}/", host_url.path()));
        }

        Ok(Self { client, host_url })
    }

    pub async fn block_height(&self) -> Result<Height> {
        let url = self.host_url.join("block-height")?;
        Ok(get_json::<BlockHeightResponse>(&self.client, url)
            .await?
            .block_height)
    }

    pub async fn block_hash(&self, block_height: Height) -> Result<BlockHash> {
        let url = self.host_url.join(&format!("block-hash/{block_height}"))?;
        Ok(get_json::<BlockHashResponse>(&self.client, url)
            .await?
            .block_hash)
    }

    /// Cut-through tweaks for a block, filtered server-side by `dust_limit`
    /// when one is requested. Only meaningful on servers that report
    /// `tweaks_cut_through_with_dust_filter: true`; elsewhere the endpoint
    /// may answer a silent empty list, so callers must consult `/info`
    /// before choosing it.
    pub async fn tweaks(
        &self,
        block_height: Height,
        dust_limit: Option<Amount>,
    ) -> Result<Vec<PublicKey>> {
        let url = self.host_url.join(&format!("tweaks/{block_height}"))?;
        get_json(&self.client, with_dust_limit(url, dust_limit)).await
    }

    /// Full tweak index for a block. The `dustLimit` query is sent only when
    /// the server reports dust-filter support (`tweaks_full_with_dust_filter`);
    /// servers without it reject any non-zero dustLimit outright.
    pub async fn tweak_index(
        &self,
        block_height: Height,
        dust_limit: Option<Amount>,
    ) -> Result<Vec<PublicKey>> {
        let url = self.host_url.join(&format!("tweak-index/{block_height}"))?;
        get_json(&self.client, with_dust_limit(url, dust_limit)).await
    }

    pub async fn utxos(&self, block_height: Height) -> Result<Vec<UtxoResponse>> {
        let url = self.host_url.join(&format!("utxos/{block_height}"))?;
        get_json(&self.client, url).await
    }

    pub async fn spent_index(&self, block_height: Height) -> Result<SpentIndexResponse> {
        let url = self.host_url.join(&format!("spent-index/{block_height}"))?;
        get_json(&self.client, url).await
    }

    pub async fn filter_new_utxos(&self, block_height: Height) -> Result<FilterResponse> {
        let url = self
            .host_url
            .join(&format!("filter/new-utxos/{block_height}"))?;
        get_json(&self.client, url).await
    }

    pub async fn filter_spent(&self, block_height: Height) -> Result<FilterResponse> {
        let url = self
            .host_url
            .join(&format!("filter/spent/{block_height}"))?;
        get_json(&self.client, url).await
    }

    pub async fn forward_tx(&self, tx_hex: String) -> Result<Txid> {
        let url = self.host_url.join("forward-tx")?;

        let body = ForwardTxRequest::new(tx_hex);

        let res = self.client.post(url.clone()).json(&body).send().await?;
        decode_response::<Txid>(res, url).await
    }

    pub async fn info(&self) -> Result<InfoResponse> {
        let url = self.host_url.join("info")?;
        get_json(&self.client, url).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url_of(input: &str) -> Url {
        BlindbitClient::new(input).expect(input).host_url
    }

    #[test]
    fn bare_host_port_defaults_to_http() {
        let url = url_of("192.168.1.44:8001");
        assert_eq!(url.scheme(), "http");
        assert_eq!(url.host_str(), Some("192.168.1.44"));
        assert_eq!(url.port(), Some(8001));
    }

    #[test]
    fn schemeless_localhost_defaults_to_http() {
        // "localhost:8001" parses as scheme `localhost` with no host;
        // the default must still apply.
        let url = url_of("localhost:8001");
        assert_eq!(url.scheme(), "http");
        assert_eq!(url.host_str(), Some("localhost"));
        assert_eq!(url.port(), Some(8001));
    }

    #[test]
    fn explicit_http_and_https_pass_through() {
        assert_eq!(url_of("http://10.0.2.2:8001").scheme(), "http");
        assert_eq!(url_of("https://blindbit.example.com").scheme(), "https");
    }

    #[test]
    fn trailing_slash_appended_once() {
        assert_eq!(url_of("http://h:1").path(), "/");
        assert_eq!(url_of("http://h:1/base").path(), "/base/");
        assert_eq!(url_of("http://h:1/base/").path(), "/base/");
    }

    #[test]
    fn unsupported_scheme_is_rejected_with_clear_error() {
        let err = BlindbitClient::new("ftp://h:1").expect_err("must reject");
        assert!(err.to_string().contains("unsupported scheme 'ftp://'"));
    }

    #[test]
    fn garbage_still_fails() {
        assert!(BlindbitClient::new("::").is_err());
    }
}
