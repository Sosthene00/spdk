use std::time::Duration;

use anyhow::Result;
use bitcoin::absolute::Height;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Amount, BlockHash, Txid};
use reqwest::{Client, Url};

use super::api_structs::{
    BlockHashResponse, BlockHeightResponse, FilterResponse, ForwardTxRequest, InfoResponse,
    SpentIndexResponse, UtxoResponse,
};

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

        let res = self
            .client
            .get(url)
            .timeout(Duration::from_secs(5))
            .send()
            .await?;
        let blkheight: BlockHeightResponse = serde_json::from_str(&res.text().await?)?;
        Ok(blkheight.block_height)
    }

    pub async fn block_hash(&self, block_height: Height) -> Result<BlockHash> {
        let url = self.host_url.join(&format!("block-hash/{block_height}"))?;

        let res = self
            .client
            .get(url)
            .timeout(Duration::from_secs(5))
            .send()
            .await?;
        let blkhash: BlockHashResponse = serde_json::from_str(&res.text().await?)?;
        Ok(blkhash.block_hash)
    }

    pub async fn tweaks(&self, block_height: Height, dust_limit: Amount) -> Result<Vec<PublicKey>> {
        let url = self.host_url.join(&format!("tweaks/{block_height}"))?;

        let res = self
            .client
            .get(url)
            .query(&[("dustLimit", format!("{}", dust_limit.to_sat()))])
            .send()
            .await?;
        Ok(serde_json::from_str(&res.text().await?)?)
    }

    pub async fn tweak_index(
        &self,
        block_height: Height,
        dust_limit: Amount,
    ) -> Result<Vec<PublicKey>> {
        let url = self.host_url.join(&format!("tweak-index/{block_height}"))?;

        let res = self
            .client
            .get(url)
            .query(&[("dustLimit", format!("{}", dust_limit.to_sat()))])
            .send()
            .await?;
        Ok(serde_json::from_str(&res.text().await?)?)
    }

    pub async fn utxos(&self, block_height: Height) -> Result<Vec<UtxoResponse>> {
        let url = self.host_url.join(&format!("utxos/{block_height}"))?;
        let res = self.client.get(url).send().await?;

        Ok(serde_json::from_str(&res.text().await?)?)
    }

    pub async fn spent_index(&self, block_height: Height) -> Result<SpentIndexResponse> {
        let url = self.host_url.join(&format!("spent-index/{block_height}"))?;
        let res = self.client.get(url).send().await?;

        Ok(serde_json::from_str(&res.text().await?)?)
    }

    pub async fn filter_new_utxos(&self, block_height: Height) -> Result<FilterResponse> {
        let url = self
            .host_url
            .join(&format!("filter/new-utxos/{block_height}"))?;

        let res = self.client.get(url).send().await?;

        Ok(serde_json::from_str(&res.text().await?)?)
    }

    pub async fn filter_spent(&self, block_height: Height) -> Result<FilterResponse> {
        let url = self
            .host_url
            .join(&format!("filter/spent/{block_height}"))?;

        let res = self.client.get(url).send().await?;

        Ok(serde_json::from_str(&res.text().await?)?)
    }

    pub async fn forward_tx(&self, tx_hex: String) -> Result<Txid> {
        let url = self.host_url.join("forward-tx")?;

        let body = ForwardTxRequest::new(tx_hex);

        let res = self.client.post(url).json(&body).send().await?;

        Ok(serde_json::from_str(&res.text().await?)?)
    }

    pub async fn info(&self) -> Result<InfoResponse> {
        let url = self.host_url.join("info")?;

        let res = self.client.get(url).send().await?;
        Ok(serde_json::from_str(&res.text().await?)?)
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
