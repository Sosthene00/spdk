use crate::Error;
use bitcoin::{OutPoint, consensus::serialize};
use bitcoin_hashes::{sha256t_hash_newtype, Hash, HashEngine};
use secp256k1::{PublicKey, Scalar, SecretKey};

sha256t_hash_newtype! {
    pub struct InputsTag = hash_str("BIP0352/Inputs");

    /// BIP0352-tagged hash with tag \"Inputs\".
    ///
    /// This is used for computing the inputs hash.
    #[hash_newtype(forward)]
    pub struct InputsHash(_);

    pub struct LabelTag = hash_str("BIP0352/Label");

    /// BIP0352-tagged hash with tag \"Label\".
    ///
    /// This is used for computing the label tweak.
    #[hash_newtype(forward)]
    pub struct LabelHash(_);

    pub struct SharedSecretTag = hash_str("BIP0352/SharedSecret");

    /// BIP0352-tagged hash with tag \"SharedSecret\".
    ///
    /// This hash type is for computing the shared secret.
    #[hash_newtype(forward)]
    pub struct SharedSecretHash(_);
}

impl InputsHash {
    pub fn from_outpoint_and_A_sum(smallest_outpoint: &OutPoint, A_sum: PublicKey) -> InputsHash {
        let mut eng = InputsHash::engine();
        eng.input(&serialize(smallest_outpoint));
        eng.input(&A_sum.serialize());
        InputsHash::from_engine(eng)
    }
    pub fn to_scalar(self) -> Scalar {
        // This is statistically extremely unlikely to panic.
        Scalar::from_be_bytes(self.to_byte_array()).expect("hash value greater than curve order")
    }
}

impl LabelHash {
    pub fn from_b_scan_and_m(b_scan: SecretKey, m: u32) -> LabelHash {
        let mut eng = LabelHash::engine();
        eng.input(&b_scan.secret_bytes());
        eng.input(&m.to_be_bytes());
        LabelHash::from_engine(eng)
    }

    pub fn to_scalar(self) -> Scalar {
        // This is statistically extremely unlikely to panic.
        Scalar::from_be_bytes(self.to_byte_array()).expect("hash value greater than curve order")
    }
}

impl SharedSecretHash {
    pub fn from_ecdh_and_k(ecdh: &PublicKey, k: u32) -> SharedSecretHash {
        let mut eng = SharedSecretHash::engine();
        eng.input(&ecdh.serialize());
        eng.input(&k.to_be_bytes());
        SharedSecretHash::from_engine(eng)
    }
}

pub fn calculate_input_hash(
    outpoints: &[OutPoint],
    A_sum: PublicKey,
) -> Result<Scalar, Error> {
    if outpoints.is_empty() {
        return Err(Error::GenericError("No outpoints provided".to_owned()));
    }

    let smallest_outpoint = outpoints
        .iter()
        // BIP352 selects the lexicographically smallest serialized outpoint.
        // `OutPoint`'s derived `Ord` compares `vout` numerically, but consensus
        // serialization uses little-endian bytes for `vout`.
        .min_by_key(|outpoint| serialize(outpoint))
        .expect("non-empty outpoints checked above");

    Ok(InputsHash::from_outpoint_and_A_sum(smallest_outpoint, A_sum).to_scalar())
}
