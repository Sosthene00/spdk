use bitcoin::{OutPoint, ScriptBuf, TxOut};
use psbt_v2::v2::{Creator, Output};
use rand::seq::SliceRandom;

use crate::core::{Error, Psbt, Result};

pub trait ConstructorPsbtExt {
    fn create_new_transaction(
        outputs: Vec<Output>,
    ) -> Result<Self> where Self: Sized;
}

impl ConstructorPsbtExt for Psbt {
    fn create_new_transaction(
        mut outputs: Vec<Output>,
    ) -> Result<Self> {
        // used to estimate the size of a taproot output
        // let placeholder_spk = ScriptBuf::new_p2tr_tweaked(
        //     bitcoin::XOnlyPublicKey::from_str(NUMS)
        //         .expect("NUMS is always valid")
        //         .dangerous_assume_tweaked(),
        // );

        // // as a silent payment wallet, we only spend taproot outputs
        // let candidates: Vec<Candidate> = available_utxos
        //     .iter()
        //     .map(|(_, o)| Candidate::new_tr_keyspend(o.value.to_sat()))
        //     .collect();

        // let mut coin_selector = CoinSelector::new(&candidates);

        // // The min may need to be adjusted, 2 or 3x that would be sensible
        // let change_policy =
        //     ChangePolicy::min_value(DrainWeights::TR_KEYSPEND, TR_DUST_RELAY_MIN_VALUE);

        // let target = Target {
        //     fee: TargetFee::from_feerate(fee_rate),
        //     outputs: TargetOutputs::fund_outputs(
        //         tx_outs
        //             .iter()
        //             .map(|(_, o)| (o.weight().to_wu(), o.value.to_sat())),
        //     ),
        // };

        // coin_selector.select_until_target_met(target)?;

        // // get the utxos that have been chosen by the coin selector
        // let selected_indices = coin_selector.selected_indices();
        // let mut selected_utxos = vec![];
        // for i in selected_indices {
        //     let (outpoint, output) = &available_utxos[*i];
        //     selected_utxos.push((*outpoint, output.clone()));
        // }

        // // if there is change, add a return address to the list of recipients
        // let change = coin_selector.drain(target, change_policy);
        // let change_value = if change.is_some() { change.value } else { 0 };
        // let change_address = self.sp_receiver.get_change_address();
        // let recipient_change = RecipientAddress::SpAddress(change_address);
        // if change_value > 0 {
        //     tx_outs.push((
        //         &recipient_change,
        //         TxOut {
        //             value: Amount::from_sat(change_value),
        //             script_pubkey: ScriptBuf::default(),
        //         },
        //     ));
        // };

        // Randomize the order of the outputs
        outputs.shuffle(&mut rand::thread_rng());

        let mut constructor = Creator::new().constructor_modifiable();

        // add outputs
        for output in outputs {
            constructor = constructor.output(output);
        }

        Ok(constructor.psbt()?)
    }
}
