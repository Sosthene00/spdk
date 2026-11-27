use std::time::Duration;

use anyhow::Result;
use bitcoin::absolute::Height;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Amount, Txid};
use reqwest::{Client, Url};

use super::api_structs::{
    BlockHeightResponse, FilterResponse, ForwardTxRequest, InfoResponse, SpentIndexResponse,
    UtxoResponse,
};
use crate::error::BlindbitError;

#[derive(Clone, Debug)]
pub struct BlindbitClient {
    client: Client,
    host_url: Url,
}

/// Extract the message from a structured `{"error": ...}` body, if the
/// body is one.
///
/// Detection is done on the parsed `serde_json::Value` rather than by
/// deserializing into a struct: serde would happily deserialize a
/// struct from a one-element *sequence*, which is exactly the shape of
/// a success body.
fn extract_error_message(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    value.get("error")?.as_str().map(str::to_owned)
}

/// Shared response handling for the tweak endpoints: a non-success HTTP
/// status and a structured `{"error": ...}` body surface as typed
/// errors, and a body that fails to parse as a sequence of public keys
/// is a typed malformed-body error — never silently coerced into an
/// empty result.
async fn parse_tweak_list(res: reqwest::Response, endpoint: &str) -> Result<Vec<PublicKey>> {
    let status = res.status();
    let body = res.text().await?;

    if !status.is_success() {
        return Err(match extract_error_message(&body) {
            Some(message) => BlindbitError::ServerError {
                endpoint: endpoint.to_owned(),
                status,
                message,
            },
            None => BlindbitError::HttpError {
                endpoint: endpoint.to_owned(),
                status,
                body,
            },
        }
        .into());
    }

    if let Some(message) = extract_error_message(&body) {
        return Err(BlindbitError::ServerError {
            endpoint: endpoint.to_owned(),
            status,
            message,
        }
        .into());
    }

    let tweaks: Vec<PublicKey> =
        serde_json::from_str(&body).map_err(|source| BlindbitError::MalformedBody {
            endpoint: endpoint.to_owned(),
            body: body.clone(),
            source,
        })?;
    Ok(tweaks)
}

impl BlindbitClient {
    pub fn new(host_url: &str) -> Result<Self> {
        let mut host_url = Url::parse(host_url)?;
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

    pub async fn tweaks(&self, block_height: Height, dust_limit: Amount) -> Result<Vec<PublicKey>> {
        let url = self.host_url.join(&format!("tweaks/{block_height}"))?;

        let res = self
            .client
            .get(url)
            .query(&[("dustLimit", format!("{}", dust_limit.to_sat()))])
            .send()
            .await?;
        parse_tweak_list(res, "/tweaks").await
    }

    /// Fetch the full basic tweak index for a block. The Blindbit basic
    /// flavor serves the unfiltered index: `dust_limit` must be `None`
    /// and NO `dustLimit` query parameter is sent in that case.
    pub async fn tweak_index(
        &self,
        block_height: Height,
        dust_limit: Option<Amount>,
    ) -> Result<Vec<PublicKey>> {
        let url = self.host_url.join(&format!("tweak-index/{block_height}"))?;

        let mut req = self.client.get(url);
        if let Some(dust_limit) = dust_limit {
            req = req.query(&[("dustLimit", format!("{}", dust_limit.to_sat()))]);
        }
        let res = req.send().await?;
        parse_tweak_list(res, "/tweak-index").await
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
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;

    const FUNDING_TWEAK: &str =
        "03a1dfd4c02951de05e5e278088cbdc5a0b6fa765e0814b71a731444ccdd91d76a";

    fn height(n: u32) -> Height {
        Height::from_consensus(n).unwrap()
    }

    /// Serve exactly one canned HTTP response on an ephemeral port;
    /// returns the base URL for a client pointed at it.
    async fn serve_once(status_line: &str, body: String) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let status_line = status_line.to_owned();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = sock.read(&mut buf).await; // discard the request head
            let response = format!(
                "{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_line,
                body.len(),
                body
            );
            sock.write_all(response.as_bytes()).await.unwrap();
        });
        format!("http://{addr}/")
    }

    #[tokio::test]
    async fn tweaks_structured_error_body_is_a_typed_error() {
        let url = serve_once(
            "HTTP/1.1 200 OK",
            r#"{"error":"Server does not allow dustLimits"}"#.to_owned(),
        )
        .await;
        let client = BlindbitClient::new(&url).unwrap();

        let err = client
            .tweaks(height(19773), Amount::from_sat(546))
            .await
            .unwrap_err()
            .downcast::<BlindbitError>()
            .unwrap();

        let BlindbitError::ServerError {
            endpoint,
            status,
            message,
        } = err
        else {
            panic!("expected ServerError, got {err:?}");
        };
        assert_eq!(endpoint, "/tweaks");
        assert_eq!(u16::from(status), 200);
        assert_eq!(message, "Server does not allow dustLimits");
    }

    #[tokio::test]
    async fn tweak_index_structured_error_body_is_a_typed_error() {
        let url = serve_once(
            "HTTP/1.1 200 OK",
            r#"{"error":"Server does not allow dustLimits"}"#.to_owned(),
        )
        .await;
        let client = BlindbitClient::new(&url).unwrap();

        let err = client
            .tweak_index(height(19773), Some(Amount::from_sat(546)))
            .await
            .unwrap_err()
            .downcast::<BlindbitError>()
            .unwrap();

        let BlindbitError::ServerError {
            endpoint, message, ..
        } = err
        else {
            panic!("expected ServerError, got {err:?}");
        };
        assert_eq!(endpoint, "/tweak-index");
        assert_eq!(message, "Server does not allow dustLimits");
    }

    #[tokio::test]
    async fn non_success_status_without_error_body_is_a_typed_http_error() {
        let url = serve_once(
            "HTTP/1.1 503 Service Unavailable",
            "backend overloaded".to_owned(),
        )
        .await;
        let client = BlindbitClient::new(&url).unwrap();

        let err = client
            .tweak_index(height(19773), None)
            .await
            .unwrap_err()
            .downcast::<BlindbitError>()
            .unwrap();

        let BlindbitError::HttpError {
            endpoint,
            status,
            body,
        } = err
        else {
            panic!("expected HttpError, got {err:?}");
        };
        assert_eq!(endpoint, "/tweak-index");
        assert_eq!(u16::from(status), 503);
        assert_eq!(body, "backend overloaded");
    }

    #[tokio::test]
    async fn non_sequence_body_is_a_typed_malformed_body_error() {
        let url = serve_once("HTTP/1.1 200 OK", r#"{"not":"a sequence"}"#.to_owned()).await;
        let client = BlindbitClient::new(&url).unwrap();

        let err = client
            .tweaks(height(19773), Amount::from_sat(546))
            .await
            .unwrap_err()
            .downcast::<BlindbitError>()
            .unwrap();

        let BlindbitError::MalformedBody { endpoint, body, .. } = err else {
            panic!("expected MalformedBody, got {err:?}");
        };
        assert_eq!(endpoint, "/tweaks");
        assert_eq!(body, r#"{"not":"a sequence"}"#);
    }

    #[tokio::test]
    async fn tweak_sequence_body_still_parses() {
        let body = format!(r#"["{FUNDING_TWEAK}"]"#);
        let url = serve_once("HTTP/1.1 200 OK", body).await;
        let client = BlindbitClient::new(&url).unwrap();

        let tweaks = client.tweak_index(height(19773), None).await.unwrap();

        assert_eq!(tweaks.len(), 1);
        assert_eq!(tweaks[0].to_string(), FUNDING_TWEAK);
    }
}
