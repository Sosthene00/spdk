use anyhow::Result;
use bdk_coin_select::{Candidate, ChangePolicy, CoinSelector, DrainWeights, FeeRate, TR_DUST_RELAY_MIN_VALUE, Target, TargetFee, TargetOutputs};
use bitcoin::{Amount, OutPoint, TxOut};

pub struct InputSelection {
    pub selected_utxos: Vec<OutPoint>,
    pub change: Amount,
    pub fee: Amount,
}

pub fn pick_utxos_for_fee_rate(
    available_utxos: Vec<(OutPoint, TxOut)>,
    tx_outs: Vec<TxOut>,
    fee_rate: FeeRate,
) -> Result<InputSelection> {
    // as a silent payment wallet, we only spend taproot outputs
    let candidates: Vec<Candidate> = available_utxos
        .iter()
        .map(|(_, o)| {
            if o.script_pubkey.is_p2tr() {
                Candidate::new_tr_keyspend(o.value.to_sat())
            } else {
                unimplemented!()
            }
        })
        .collect();

    let mut coin_selector = CoinSelector::new(&candidates);

    // The min may need to be adjusted, 2 or 3x that would be sensible
    let change_policy =
        ChangePolicy::min_value(DrainWeights::TR_KEYSPEND, TR_DUST_RELAY_MIN_VALUE * 2);

    let target = Target {
        fee: TargetFee::from_feerate(fee_rate),
        outputs: TargetOutputs::fund_outputs(
            tx_outs
                .iter()
                .map(|o| (o.weight().to_wu(), o.value.to_sat())),
        ),
    };

    coin_selector.select_until_target_met(target)?;

    // get the utxos that have been chosen by the coin selector
    let selected_indices = coin_selector.selected_indices();
    let mut selected_utxos = vec![];
    for i in selected_indices {
        let (outpoint, _) = &available_utxos[*i];
        selected_utxos.push(*outpoint);
    }

    // if there is change, add a return address to the list of recipients
    let change = coin_selector.drain(target, change_policy);
    let change_value = if change.is_some() { change.value } else { 0 };
    let fee_value = coin_selector.fee(target.outputs.value_sum, change_value);
    if fee_value < 0 {
        return Err(anyhow::Error::msg("Not enough funds available"));
    }

    Ok(InputSelection {
        selected_utxos,
        change: Amount::from_sat(change_value),
        fee: Amount::from_sat(fee_value as u64),
    })
}