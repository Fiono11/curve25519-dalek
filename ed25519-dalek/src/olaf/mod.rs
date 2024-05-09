//! Implementation of the Olaf protocol (<https://eprint.iacr.org/2023/899>), which is composed of the Distributed
//! Key Generation (DKG) protocol SimplPedPoP and the Threshold Signing protocol FROST.

use self::types::SCALAR_LENGTH;
use crate::{SecretKey, VerifyingKey};
use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, EdwardsPoint, Scalar};
use merlin::Transcript;

pub mod errors;
pub mod simplpedpop;
mod tests;
mod types;

pub use types::AllMessage;

const MINIMUM_THRESHOLD: u16 = 2;
const GENERATOR: EdwardsPoint = ED25519_BASEPOINT_POINT;

/// The group public key generated by the SimplPedPoP protocol.
pub struct GroupPublicKey(VerifyingKey);
/// The verifying share of a participant in the SimplPedPoP protocol, used to verify its signature share.
pub struct VerifyingShare(VerifyingKey);
/// The signing share of a participant in the SimplPedPoP protocol, used to produce its signature share.
pub struct SigningShare(SecretKey);

/// The identifier of a participant in the Olaf protocol.
#[derive(Clone, Copy)]
pub struct Identifier(Scalar);

impl Identifier {
    pub(super) fn generate(recipients_hash: &[u8; 16], index: u16) -> Identifier {
        let mut pos = Transcript::new(b"Identifier");
        pos.append_message(b"RecipientsHash", recipients_hash);
        pos.append_message(b"i", &index.to_le_bytes()[..]);

        let mut buf = [0; 64];
        pos.challenge_bytes(b"identifier", &mut buf);

        Identifier(Scalar::from_bytes_mod_order_wide(&buf))
    }
}

pub(crate) fn scalar_from_canonical_bytes(bytes: [u8; 32]) -> Option<Scalar> {
    let key = Scalar::from_canonical_bytes(bytes);

    // Note: this is a `CtOption` so we have to do this to extract the value.
    if bool::from(key.is_none()) {
        return None;
    }

    Some(key.unwrap())
}
