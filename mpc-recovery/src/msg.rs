use serde::{Deserialize, Serialize};
use threshold_crypto::{Signature, SignatureShare};

use crate::NodeId;

#[derive(Serialize, Deserialize)]
pub struct LeaderRequest {
    pub payload: String,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum LeaderResponse {
    Ok {
        #[serde(with = "hex_sig_share")]
        signature: Signature,
    },
    Err,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SigShareRequest {
    pub payload: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SigShareResponse {
    pub node_id: NodeId,
    pub sig_share: SignatureShare,
}

mod hex_sig_share {
    use serde::{Deserialize, Deserializer, Serializer};
    use threshold_crypto::Signature;

    pub fn serialize<S>(sig_share: &Signature, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = hex::encode(sig_share.to_bytes());
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Signature, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Signature::from_bytes(
            &hex::decode(s)
                .map_err(serde::de::Error::custom)?
                .try_into()
                .map_err(|v: Vec<u8>| {
                    serde::de::Error::custom(format!(
                        "signature has incorrect length: expected 96 bytes, but got {}",
                        v.len()
                    ))
                })?,
        )
        .map_err(serde::de::Error::custom)
    }
}
