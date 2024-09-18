use crypto_shared::kdf::{check_ec_signature, derive_secret_key};
use crypto_shared::{
    derive_key, ScalarExt as _, SerializableAffinePoint, SerializableScalar,
    SignatureResponse,
};
use digest::{Digest, FixedOutput};
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::point::DecompressPoint as _;
use k256::{AffinePoint, FieldBytes, Scalar, Secp256k1};
use mpc_contract::primitives::SignatureRequest;
use signature::hazmat::PrehashSigner;

pub const CONTRACT_FILE_PATH: &str =
    "../../target/wasm32-unknown-unknown/release/mpc_contract.wasm";
pub const INVALID_CONTRACT: &str = "../res/mpc_test_contract.wasm";
pub const PARTICIPANT_LEN: usize = 3;

/// Process the message, creating the same hash with type of Digest, Scalar, and [u8; 32]
pub async fn process_message(msg: &str) -> (impl Digest, k256::Scalar, [u8; 32]) {
    let msg = msg.as_bytes();
    let digest = <k256::Secp256k1 as ecdsa::hazmat::DigestPrimitive>::Digest::new_with_prefix(msg);
    let bytes: FieldBytes = digest.clone().finalize_fixed();
    let scalar_hash =
        <k256::Scalar as Reduce<<Secp256k1 as k256::elliptic_curve::Curve>::Uint>>::reduce_bytes(
            &bytes,
        );

    let payload_hash: [u8; 32] = bytes.into();
    (digest, scalar_hash, payload_hash)
}

pub async fn generate_response(
    request: &SignatureRequest,
    sk: &k256::SecretKey,
) -> SignatureResponse {
    let payload_hash: [u8; 32] = request.payload_hash.scalar.to_bytes().into();
    let epsilon = request.epsilon.scalar;

    let pk = sk.public_key();
    let derived_sk = derive_secret_key(sk, epsilon);
    let derived_pk = derive_key(pk.into(), epsilon);
    let signing_key = k256::ecdsa::SigningKey::from(&derived_sk);

    let (signature, _): (ecdsa::Signature<Secp256k1>, _) =
        signing_key.sign_prehash(&payload_hash).unwrap();

    // let verifying_key =
    //     k256::ecdsa::VerifyingKey::from(&k256::PublicKey::from_affine(derived_pk).unwrap());
    // assert!(verifying_key.verify(&msg.as_bytes(), &signature).is_ok());

    let s = signature.s();
    let (r_bytes, _s_bytes) = signature.split_bytes();
    let big_r =
        AffinePoint::decompress(&r_bytes, k256::elliptic_curve::subtle::Choice::from(0)).unwrap();
    let s: k256::Scalar = *s.as_ref();

    let payload_hash_s = Scalar::from_bytes(payload_hash).unwrap();
    let recovery_id = if check_ec_signature(&derived_pk, &big_r, &s, payload_hash_s, 0).is_ok() {
        0
    } else if check_ec_signature(&derived_pk, &big_r, &s, payload_hash_s, 1).is_ok() {
        1
    } else {
        panic!("unable to use recovery id of 0 or 1");
    };

    let respond_resp = SignatureResponse {
        big_r: SerializableAffinePoint {
            affine_point: big_r,
        },
        s: SerializableScalar { scalar: s },
        recovery_id,
    };

    respond_resp
}
