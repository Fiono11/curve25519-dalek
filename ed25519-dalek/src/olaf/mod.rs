//! Implementation of the Olaf protocol (<https://eprint.iacr.org/2023/899>), which is composed of the Distributed
//! Key Generation (DKG) protocol SimplPedPoP and the Threshold Signing protocol FROST.

/// Implementation of the FROST protocol.
pub mod frost;
/// Implementation of the SimplPedPoP protocol.
pub mod simplpedpop;

use crate::{SigningKey, VerifyingKey};
use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, EdwardsPoint, Scalar};
use merlin::Transcript;

pub(super) const MINIMUM_THRESHOLD: u16 = 2;
pub(super) const GENERATOR: EdwardsPoint = ED25519_BASEPOINT_POINT;

/// The threshold public key generated in the SimplPedPoP protocol, used to validate the threshold signatures of the FROST protocol.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ThresholdPublicKey(pub(crate) VerifyingKey);

/// The verifying share of a participant generated in the SimplPedPoP protocol, used to verify its signatures shares in the FROST protocol.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VerifyingShare(pub(crate) VerifyingKey);

/// The signing keypair of a participant generated in the SimplPedPoP protocol, used to produce its signatures shares in the FROST protocol.
#[derive(Clone, Debug)]
pub struct SigningKeypair(pub(crate) SigningKey);

/// The identifier of a participant, which is the same in the SimplPedPoP protocol and in the FROST protocol.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Identifier(pub(crate) Scalar);

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
