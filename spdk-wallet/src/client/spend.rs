use anyhow::Result;
use bitcoin::consensus::serialize;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::{OutPoint};
use psbt::Psbt;
use silentpayments::utils::sending::TypedSecretKey;
use silentpayments::utils::common::InputHashApplied;
use silentpayments::utils as sp_utils;

use spdk_core::updater::DiscoveredOutput;

use super::SpClient;

impl SpClient {
    pub fn sign_transaction(
        &self,
        mut psbt: Psbt,
    ) -> Result<Psbt> {
        let k: SecretKey = self.get_spend_key().try_into()?;
        let secp = Secp256k1::new();
        let _xonly_keys = psbt.sign_silent_payment_inputs(&k, &secp);
        Ok(psbt)
    }

    pub fn get_partial_secret_for_selected_utxos(
        &self,
        selected_utxos: &[(OutPoint, DiscoveredOutput)],
    ) -> Result<TypedSecretKey<InputHashApplied>> {
        let secp = Secp256k1::signing_only();
        let b_spend = self.try_get_secret_spend_key()?;

        let outpoints: Vec<[u8; 36]> = selected_utxos
            .iter()
            .map(|(outpoint, _)| {
                serialize(&outpoint)
                    .try_into()
                    .expect("OutPoint type guarantee 36 bytes")
            })
            .collect();
        let input_privkeys = selected_utxos
            .iter()
            .map(|(_, output)| Ok((b_spend.add_tweak(&output.tweak)?, true)))
            .collect::<Result<Vec<_>>>()?;

        let partial_secret =
            sp_utils::sending::calculate_partial_secret(&secp, &input_privkeys, &outpoints)?;

        Ok(partial_secret)
    }
}
