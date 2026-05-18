use bitcoin::hashes::Hash;
use bitcoin::{OutPoint, Script, TxOut, Txid};
use psbt_v2::v2::{Constructor, Creator, Input, Modifiable, Output};
use silentpayments::utils::NUMS_H;

use crate::Error;

/// Check if an input is eligible for silent payments (BIP-352)
pub(crate) fn is_input_eligible(input: &Input) -> Result<bool, Error> {
    let funding_utxo = input
        .funding_utxo()
        .map_err(|_| Error::Other(format!("Input doesn't have funding utxo yet")))?;

    let script: &Script = funding_utxo.script_pubkey.as_ref();

    // P2WPKH (SegWit v0) - eligible
    if script.is_p2wpkh() {
        return Ok(true);
    }

    // P2TR (Taproot, SegWit v1) - eligible unless internal key is NUMS point (BIP-352)
    if script.is_p2tr() {
        if let Some(internal_key) = &input.tap_internal_key {
            if internal_key.serialize() == NUMS_H {
                return Ok(false);
            }
        }
        return Ok(true);
    }

    // P2PKH (legacy) - eligible
    if script.is_p2pkh() {
        return Ok(true);
    }

    // P2SH - only eligible if it's P2SH-P2WPKH
    if script.is_p2sh() {
        if let Some(redeem_script) = &input.redeem_script {
            return Ok(redeem_script.is_p2wpkh());
        }
        return Ok(false);
    }

    // All other types are ineligible (multisig, etc.)
    Ok(false)
}
