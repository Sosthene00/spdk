use std::str::FromStr;

use anyhow::{Error, Result};
use bdk_coin_select::{
    Candidate, ChangePolicy, CoinSelector, DrainWeights, TR_DUST_RELAY_MIN_VALUE, Target,
    TargetFee, TargetOutputs,
};
use bitcoin::consensus::serialize;
use bitcoin::key::TapTweak;
use bitcoin::script::PushBytesBuf;
use bitcoin::secp256k1::rand::seq::SliceRandom;
use bitcoin::secp256k1::{Secp256k1, SecretKey, rand};
use bitcoin::{
    Amount, Network, OutPoint, ScriptBuf, TxOut,
};
use psbt::Psbt;
use psbt::core::{Input, Output};
use psbt_v2::v2::{Constructor, Creator, Modifiable};
use silentpayments::utils::sending::TypedSecretKey;
use silentpayments::{Network as SpNetwork, utils::common::InputHashApplied};
use silentpayments::utils as sp_utils;

use spdk_core::constants::{DATA_CARRIER_SIZE, NUMS};
use spdk_core::updater::DiscoveredOutput;

use super::{FeeRate, Recipient, RecipientAddress, SpClient};

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
