use crate::core::{error::Error, Result};

use psbt_v2::v2::Output;
use secp256k1::PublicKey;
use silentpayments::SilentPaymentAddress;

pub trait Bip375OutputConstructorExt {
    fn get_sp_info(&self) -> Option<(PublicKey, PublicKey)>;
    fn set_sp_info(&mut self, address: &SilentPaymentAddress) -> Option<Vec<u8>>;
    fn get_sp_label(&self) -> Option<u32>;
    fn set_sp_label(&mut self, label: u32) -> Option<u32>;
}

impl Bip375OutputConstructorExt for Output {
    fn get_sp_info(&self) -> Option<(PublicKey, PublicKey)> {
        if let Some(bytes) = &self.sp_v0_info {
            if bytes.len() != 66 {
                return None;
            };
            let scan_key = PublicKey::from_slice(&bytes[..33]).ok();
            let spend_key = PublicKey::from_slice(&bytes[33..]).ok();
            if let (Some(scan_key), Some(spend_key)) = (scan_key, spend_key) {
                return Some((scan_key, spend_key));
            }
        }

        None
    }

    fn set_sp_info(
        &mut self,
        address: &SilentPaymentAddress,
    ) -> Option<Vec<u8>> {
        let old_info = self.sp_v0_info.clone();
        // PSBT_OUT_SP_V0_INFO contains only the keys (66 bytes)
        // Label is stored separately in PSBT_OUT_SP_V0_LABEL
        let mut bytes = Vec::with_capacity(66);
        bytes.extend_from_slice(&address.get_scan_key().serialize());
        bytes.extend_from_slice(&address.get_spend_key().serialize());
        self.sp_v0_info = Some(bytes);

        old_info
    }

    fn get_sp_label(&self) -> Option<u32> {
        self.sp_v0_label
    }

    fn set_sp_label(&mut self, label: u32) -> Option<u32> {
        let old_label = self.sp_v0_label;
        self.sp_v0_label = Some(label);

        old_label
    }

}
