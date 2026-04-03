use std::str::FromStr;

use anyhow::{Error, Result};
use bdk_coin_select::{
    Candidate, ChangePolicy, CoinSelector, DrainWeights, TR_DUST_RELAY_MIN_VALUE, Target,
    TargetFee, TargetOutputs,
};
use bitcoin::key::TapTweak;
use bitcoin::script::PushBytesBuf;
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use bitcoin::transaction::Version;
use bitcoin::{Amount, Network, OutPoint, ScriptBuf, Sequence};
use silentpayments::Network as SpNetwork;

use spdk_core::constants::{DATA_CARRIER_SIZE, NUMS};
use spdk_core::psbt::core::{Bip375PsbtExt, PsbtInput, PsbtOutput, SilentPaymentPsbt};
use spdk_core::psbt::roles::{
    add_ecdh_shares_full, construct_psbt, create_psbt, extract_transaction, finalize_sp_outputs,
    sign_inputs,
};
use spdk_core::updater::DiscoveredOutput;

use super::{FeeRate, Recipient, RecipientAddress, SpClient};

impl SpClient {
    // For now it's only suitable for wallet that spends only silent payments outputs that it owns
    pub fn create_new_transaction(
        &self,
        available_utxos: Vec<(OutPoint, DiscoveredOutput)>,
        mut recipients: Vec<Recipient>,
        fee_rate: FeeRate,
        network: Network,
    ) -> Result<SilentPaymentPsbt> {
        let placeholder_spk = ScriptBuf::new_p2tr_tweaked(
            bitcoin::XOnlyPublicKey::from_str(NUMS)
                .expect("NUMS is always valid")
                .dangerous_assume_tweaked(),
        );

        let address_sp_network = match network {
            Network::Bitcoin => SpNetwork::Mainnet,
            Network::Testnet | Network::Signet => SpNetwork::Testnet,
            Network::Regtest => SpNetwork::Regtest,
            _ => unreachable!(),
        };

        let tx_outs = recipients
            .iter()
            .map(|recipient| match &recipient.address {
                RecipientAddress::LegacyAddress(unchecked_address) => {
                    let value = recipient.amount;
                    let script_pubkey = unchecked_address
                        .clone()
                        .require_network(network)?
                        .script_pubkey();

                    Ok(bitcoin::TxOut {
                        value,
                        script_pubkey,
                    })
                }
                RecipientAddress::SpAddress(sp_address) => {
                    if sp_address.get_network() != address_sp_network {
                        return Err(Error::msg(format!(
                            "Wrong network for address {}",
                            sp_address
                        )));
                    }

                    Ok(bitcoin::TxOut {
                        value: recipient.amount,
                        script_pubkey: placeholder_spk.clone(),
                    })
                }
                RecipientAddress::Data(data) => {
                    let value = recipient.amount;
                    let data_len = data.len();
                    if value > Amount::from_sat(0) {
                        Err(Error::msg("Data output must have an amount of 0!"))
                    } else if data_len > DATA_CARRIER_SIZE {
                        Err(Error::msg(format!(
                            "Can't embed data of length {}. Max length: {}",
                            data_len, DATA_CARRIER_SIZE
                        )))
                    } else {
                        let mut op_return = PushBytesBuf::with_capacity(data_len);
                        op_return.extend_from_slice(data)?;
                        Ok(bitcoin::TxOut {
                            value,
                            script_pubkey: ScriptBuf::new_op_return(op_return),
                        })
                    }
                }
            })
            .collect::<Result<Vec<bitcoin::TxOut>>>()?;

        let candidates: Vec<Candidate> = available_utxos
            .iter()
            .map(|(_, o)| Candidate::new_tr_keyspend(o.value.to_sat()))
            .collect();

        let mut coin_selector = CoinSelector::new(&candidates);

        let change_policy =
            ChangePolicy::min_value(DrainWeights::TR_KEYSPEND, TR_DUST_RELAY_MIN_VALUE);

        let target = Target {
            fee: TargetFee::from_feerate(fee_rate),
            outputs: TargetOutputs::fund_outputs(
                tx_outs
                    .iter()
                    .map(|o| (o.weight().to_wu(), o.value.to_sat())),
            ),
        };

        coin_selector.select_until_target_met(target)?;

        let selected_indices = coin_selector.selected_indices();
        let mut selected_utxos = vec![];
        for i in selected_indices {
            let (outpoint, output) = &available_utxos[*i];
            selected_utxos.push((*outpoint, output.clone()));
        }

        let change = coin_selector.drain(target, change_policy);
        let change_value = if change.is_some() { change.value } else { 0 };
        if change_value > 0 {
            let change_address = self.sp_receiver.get_change_address();
            recipients.push(Recipient {
                address: RecipientAddress::SpAddress(change_address),
                amount: Amount::from_sat(change_value),
            });
        }

        self.build_psbt(&selected_utxos, &recipients, network, address_sp_network)
    }

    /// A drain transaction spends all the available utxos to a single RecipientAddress.
    pub fn create_drain_transaction(
        &self,
        available_utxos: Vec<(OutPoint, DiscoveredOutput)>,
        recipient: RecipientAddress,
        fee_rate: FeeRate,
        network: Network,
    ) -> Result<SilentPaymentPsbt> {
        let placeholder_spk = ScriptBuf::new_p2tr_tweaked(
            bitcoin::XOnlyPublicKey::from_str(NUMS)
                .expect("NUMS is always valid")
                .dangerous_assume_tweaked(),
        );

        let address_sp_network = match network {
            Network::Bitcoin => SpNetwork::Mainnet,
            Network::Testnet | Network::Signet => SpNetwork::Testnet,
            Network::Regtest => SpNetwork::Regtest,
            _ => unreachable!(),
        };

        let output = match &recipient {
            RecipientAddress::LegacyAddress(address) => Ok(bitcoin::TxOut {
                value: Amount::ZERO,
                script_pubkey: address.clone().require_network(network)?.script_pubkey(),
            }),
            RecipientAddress::SpAddress(sp_address) => {
                if sp_address.get_network() != address_sp_network {
                    return Err(Error::msg(format!(
                        "Wrong network for address {}",
                        sp_address
                    )));
                }

                Ok(bitcoin::TxOut {
                    value: Amount::ZERO,
                    script_pubkey: placeholder_spk.clone(),
                })
            }
            RecipientAddress::Data(_) => Err(Error::msg("Draining to OP_RETURN not allowed")),
        }?;

        let target_outputs = TargetOutputs {
            value_sum: 0,
            weight_sum: 0,
            n_outputs: 0,
        };

        let drain_output = DrainWeights {
            output_weight: output.weight().to_wu(),
            spend_weight: 0,
            n_outputs: 1,
        };

        let candidates: Vec<Candidate> = available_utxos
            .iter()
            .map(|(_, o)| Candidate::new_tr_keyspend(o.value.to_sat()))
            .collect();

        let mut coin_selector = CoinSelector::new(&candidates);

        let change_policy = ChangePolicy::min_value(drain_output, 0);

        let target = Target {
            fee: TargetFee::from_feerate(fee_rate),
            outputs: target_outputs,
        };

        coin_selector.select_all();

        let change = coin_selector.drain(target, change_policy);

        if change.is_none() {
            return Err(Error::msg("No funds available"));
        }

        let recipients = vec![Recipient {
            address: recipient,
            amount: Amount::from_sat(change.value),
        }];

        self.build_psbt(&available_utxos, &recipients, network, address_sp_network)
    }

    /// Builds a SilentPaymentPsbt from selected UTXOs and recipients.
    ///
    /// Constructs inputs/outputs, adds ECDH shares (using each input's tweaked spend key),
    /// and stores the SP tweak per input so a downstream signer can reconstruct the signing key.
    fn build_psbt(
        &self,
        selected_utxos: &[(OutPoint, DiscoveredOutput)],
        recipients: &[Recipient],
        network: Network,
        address_sp_network: SpNetwork,
    ) -> Result<SilentPaymentPsbt> {
        let b_spend = self.try_get_secret_spend_key()?;
        let secp = Secp256k1::new();

        // Build PsbtInputs with tweaked signing keys for ECDH share computation
        let psbt_inputs: Vec<PsbtInput> = selected_utxos
            .iter()
            .map(|(outpoint, output)| {
                let tweaked_key = b_spend.add_tweak(&output.tweak)?;
                Ok(PsbtInput::new(
                    *outpoint,
                    bitcoin::TxOut {
                        value: output.value,
                        script_pubkey: output.script_pubkey.clone(),
                    },
                    Sequence::MAX,
                    Some(tweaked_key),
                ))
            })
            .collect::<Result<Vec<_>>>()?;

        // Build PsbtOutputs
        let psbt_outputs: Vec<PsbtOutput> = recipients
            .iter()
            .map(|recipient| match &recipient.address {
                RecipientAddress::LegacyAddress(unchecked_address) => {
                    let script = unchecked_address
                        .clone()
                        .require_network(network)?
                        .script_pubkey();
                    Ok(PsbtOutput::regular(recipient.amount, script))
                }
                RecipientAddress::SpAddress(sp_address) => {
                    if sp_address.get_network() != address_sp_network {
                        return Err(Error::msg(format!(
                            "Wrong network for address {}",
                            sp_address
                        )));
                    }
                    Ok(PsbtOutput::silent_payment(recipient.amount, sp_address.clone(), None))
                }
                RecipientAddress::Data(data) => {
                    if recipient.amount > Amount::from_sat(0) {
                        return Err(Error::msg("Data output must have an amount of 0!"));
                    }
                    let data_len = data.len();
                    if data_len > DATA_CARRIER_SIZE {
                        return Err(Error::msg(format!(
                            "Can't embed data of length {}. Max length: {}",
                            data_len, DATA_CARRIER_SIZE
                        )));
                    }
                    let mut op_return = PushBytesBuf::with_capacity(data_len);
                    op_return.extend_from_slice(data)?;
                    Ok(PsbtOutput::regular(
                        recipient.amount,
                        ScriptBuf::new_op_return(op_return),
                    ))
                }
            })
            .collect::<Result<Vec<_>>>()?;

        let mut psbt = create_psbt(psbt_inputs.len(), psbt_outputs.len());
        psbt.global.tx_version = Version::TWO;

        construct_psbt(&mut psbt, &psbt_inputs, &psbt_outputs)
            .map_err(|e| Error::msg(e.to_string()))?;

        // Store the SP tweak per input so the signer can reconstruct the tweaked key
        for (i, (_, output)) in selected_utxos.iter().enumerate() {
            psbt.set_input_sp_tweak(i, output.tweak.to_be_bytes())
                .map_err(|e| Error::msg(e.to_string()))?;
        }

        // Collect unique scan keys from SP recipients for ECDH share computation
        let scan_keys: Vec<PublicKey> = {
            let mut keys = vec![];
            for recipient in recipients {
                if let RecipientAddress::SpAddress(sp_address) = &recipient.address {
                    let scan_key = sp_address.get_scan_key();
                    if !keys.contains(&scan_key) {
                        keys.push(scan_key);
                    }
                }
            }
            keys
        };

        if !scan_keys.is_empty() {
            add_ecdh_shares_full(&secp, &mut psbt, &psbt_inputs, &scan_keys, true)
                .map_err(|e| Error::msg(e.to_string()))?;
        }

        Ok(psbt)
    }

    /// Computes final output scripts for silent payment outputs from the ECDH shares in the PSBT.
    pub fn finalize_transaction(psbt: &mut SilentPaymentPsbt) -> Result<()> {
        let secp = Secp256k1::new();
        finalize_sp_outputs(&secp, psbt).map_err(|e| Error::msg(e.to_string()))
    }

    /// Signs all inputs and extracts the final transaction.
    pub fn sign_transaction(
        &self,
        mut psbt: SilentPaymentPsbt,
        _aux_rand: &[u8; 32],
    ) -> Result<bitcoin::Transaction> {
        let b_spend = self.try_get_secret_spend_key()?;
        let secp = Secp256k1::new();

        // Reconstruct PsbtInputs with the base spend key.
        // sign_inputs will apply PSBT_IN_SP_TWEAK automatically for each P2TR input.
        let psbt_inputs: Vec<PsbtInput> = psbt
            .inputs
            .iter()
            .map(|input| {
                let outpoint = OutPoint {
                    txid: input.previous_txid,
                    vout: input.spent_output_index,
                };
                let witness_utxo = input
                    .witness_utxo
                    .clone()
                    .map(|u| bitcoin::TxOut {
                        value: u.value,
                        script_pubkey: u.script_pubkey,
                    })
                    .unwrap_or(bitcoin::TxOut {
                        value: Amount::ZERO,
                        script_pubkey: ScriptBuf::new(),
                    });
                PsbtInput::new(
                    outpoint,
                    witness_utxo,
                    input.sequence.unwrap_or(Sequence::MAX),
                    Some(b_spend),
                )
            })
            .collect();

        sign_inputs(&secp, &mut psbt, &psbt_inputs).map_err(|e| Error::msg(e.to_string()))?;

        extract_transaction(&mut psbt).map_err(|e| Error::msg(e.to_string()))
    }

    pub fn get_partial_secret_for_selected_utxos(
        &self,
        selected_utxos: &[(OutPoint, DiscoveredOutput)],
    ) -> Result<bitcoin::secp256k1::SecretKey> {
        use silentpayments::utils as sp_utils;

        let b_spend = self.try_get_secret_spend_key()?;

        let outpoints: Vec<_> = selected_utxos
            .iter()
            .map(|(outpoint, _)| (outpoint.txid.to_string(), outpoint.vout))
            .collect();
        let input_privkeys = selected_utxos
            .iter()
            .map(|(_, output)| Ok((b_spend.add_tweak(&output.tweak)?, true)))
            .collect::<Result<Vec<_>>>()?;

        let partial_secret =
            sp_utils::sending::calculate_partial_secret(&input_privkeys, &outpoints)?;

        Ok(partial_secret)
    }
}
