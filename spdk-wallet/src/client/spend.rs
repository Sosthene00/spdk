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
use psbt::roles::Bip375OutputConstructorExt;
use psbt_v2::v2::{Constructor, Creator, Modifiable};
use silentpayments::utils::sending::TypedSecretKey;
use silentpayments::{Network as SpNetwork, utils::common::InputHashApplied};
use silentpayments::utils as sp_utils;

use spdk_core::constants::{DATA_CARRIER_SIZE, NUMS};
use spdk_core::updater::DiscoveredOutput;

use super::{FeeRate, Recipient, RecipientAddress, SpClient};

impl SpClient {
    // For now it's only suitable for wallet that spends only silent payments outputs that it owns
    pub fn create_new_transaction(
        &self,
        available_utxos: Vec<(OutPoint, DiscoveredOutput)>,
        recipients: Vec<Recipient>,
        fee_rate: FeeRate,
        network: Network,
    ) -> Result<Psbt> {
        // used to estimate the size of a taproot output
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

        let mut tx_outs = recipients
            .iter()
            .map(|recipient| match &recipient.address {
                RecipientAddress::LegacyAddress(unchecked_address) => {
                    let value = recipient.amount;
                    let script_pubkey = unchecked_address
                        .clone()
                        .require_network(network)?
                        .script_pubkey();

                    Ok((
                        &recipient.address,
                        TxOut {
                            value,
                            script_pubkey,
                        },
                    ))
                }
                RecipientAddress::SpAddress(sp_address) => {
                    if sp_address.get_network() != address_sp_network {
                        return Err(Error::msg(format!(
                            "Wrong network for address {}",
                            sp_address
                        )));
                    }

                    Ok((
                        &recipient.address,
                        TxOut {
                            value: recipient.amount,
                            script_pubkey: placeholder_spk.clone(),
                        },
                    ))
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
                        let script_pubkey = ScriptBuf::new_op_return(op_return);

                        Ok((
                            &recipient.address,
                            TxOut {
                                value,
                                script_pubkey,
                            },
                        ))
                    }
                }
            })
            .collect::<Result<Vec<(&RecipientAddress, TxOut)>>>()?;

        // as a silent payment wallet, we only spend taproot outputs
        let candidates: Vec<Candidate> = available_utxos
            .iter()
            .map(|(_, o)| Candidate::new_tr_keyspend(o.value.to_sat()))
            .collect();

        let mut coin_selector = CoinSelector::new(&candidates);

        // The min may need to be adjusted, 2 or 3x that would be sensible
        let change_policy =
            ChangePolicy::min_value(DrainWeights::TR_KEYSPEND, TR_DUST_RELAY_MIN_VALUE);

        let target = Target {
            fee: TargetFee::from_feerate(fee_rate),
            outputs: TargetOutputs::fund_outputs(
                tx_outs
                    .iter()
                    .map(|(_, o)| (o.weight().to_wu(), o.value.to_sat())),
            ),
        };

        coin_selector.select_until_target_met(target)?;

        // get the utxos that have been chosen by the coin selector
        let selected_indices = coin_selector.selected_indices();
        let mut selected_utxos = vec![];
        for i in selected_indices {
            let (outpoint, output) = &available_utxos[*i];
            selected_utxos.push((*outpoint, output.clone()));
        }

        // if there is change, add a return address to the list of recipients
        let change = coin_selector.drain(target, change_policy);
        let change_value = if change.is_some() { change.value } else { 0 };
        let change_address = self.sp_receiver.get_change_address();
        let recipient_change = RecipientAddress::SpAddress(change_address);
        if change_value > 0 {
            tx_outs.push((
                &recipient_change,
                TxOut {
                    value: Amount::from_sat(change_value),
                    script_pubkey: ScriptBuf::default(),
                },
            ));
        };

        // Randomize the order of the outputs
        tx_outs.shuffle(&mut rand::thread_rng());

        let mut constructor = Creator::new().constructor_modifiable();

        // add inputs
        for (outpoint, _output) in selected_utxos.iter() {
            constructor = constructor.input(Input::new(outpoint));
        }

        // add outputs
        for (recipient_address, tx_out) in tx_outs {
            match recipient_address {
                RecipientAddress::SpAddress(sp_address) => {
                    let effective_tx_out = TxOut {
                        value: tx_out.value,
                        script_pubkey: ScriptBuf::default(),
                    };
                    constructor = constructor.output(Output::new(effective_tx_out));
                    // We add the sp address to the output
                    let mut psbt = constructor.psbt()?;
                    let output = psbt.outputs.last_mut().expect("we just added it");
                    output.set_sp_info(sp_address);
                    // If output is our change address we also set that
                    if change_address == *sp_address {
                        output.set_sp_label(0);
                    }
                    // We convert the psbt back to a constructor
                    constructor = Constructor::<Modifiable>::new(psbt)?;
                }
                // For other cases we can just add the output to the constructor
                _ => {
                    constructor = constructor.output(Output::new(tx_out));
                }
            }
        }

        Ok(constructor.psbt()?)
    }

    /// A drain transaction spends all the available utxos to a single RecipientAddress.
    pub fn create_drain_transaction(
        &self,
        available_utxos: Vec<(OutPoint, DiscoveredOutput)>,
        recipient: RecipientAddress,
        fee_rate: FeeRate,
        network: Network,
    ) -> Result<Psbt> {
        // used to estimate the size of a taproot output
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
            RecipientAddress::LegacyAddress(address) => Ok(TxOut {
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

                Ok(TxOut {
                    value: Amount::ZERO,
                    script_pubkey: placeholder_spk.clone(),
                })
            }
            RecipientAddress::Data(_) => Err(Error::msg("Draining to OP_RETURN not allowed")),
        }?;

        // for a drain transaction, we have no target outputs.
        // instead, we register the recipient as the drain output.
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

        // as a silent payment wallet, we only spend taproot outputs
        let candidates: Vec<Candidate> = available_utxos
            .iter()
            .map(|(_, o)| Candidate::new_tr_keyspend(o.value.to_sat()))
            .collect();

        let mut coin_selector = CoinSelector::new(&candidates);

        // we force a change, by having the min_value be set to 0
        let change_policy = ChangePolicy::min_value(drain_output, 0);

        let target = Target {
            fee: TargetFee::from_feerate(fee_rate),
            outputs: target_outputs,
        };

        // for a drain transaction, we select all avaliable inputs
        coin_selector.select_all();

        let change = coin_selector.drain(target, change_policy);

        if change.is_none() {
            return Err(Error::msg("No funds available"));
        }

        let mut constructor = Creator::new().constructor_modifiable();

        // add inputs
        for (outpoint, _output) in available_utxos.iter() {
            constructor = constructor.input(Input::new(outpoint));
        }

        // add outputs
        match recipient {
            RecipientAddress::SpAddress(sp_address) => {
                let effective_tx_out = TxOut {
                    value: Amount::from_sat(change.value),
                    script_pubkey: ScriptBuf::default(),
                };
                constructor = constructor.output(Output::new(effective_tx_out));
                // We add the sp address to the output
                let mut psbt = constructor.psbt()?;
                let output = psbt.outputs.last_mut().expect("we just added it");
                output.set_sp_info(&sp_address);
                // We convert the psbt back to a constructor
                constructor = Constructor::<Modifiable>::new(psbt)?;
            }
            RecipientAddress::LegacyAddress(_) => {
                constructor = constructor.output(Output::new(output));
            }
            RecipientAddress::Data(_) => {
                return Err(Error::msg("Draining to OP_RETURN not allowed"));
            }
        }

        Ok(constructor.psbt()?)
    }

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
