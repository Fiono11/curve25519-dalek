//! Errors of the FROST protocol.

use core::array::TryFromSliceError;

use alloc::vec::Vec;

use crate::{
    olaf::{simplpedpop::errors::SPPError, VerifyingShare},
    SignatureError,
};

/// A result for the SimplPedPoP protocol.
pub type FROSTResult<T> = Result<T, FROSTError>;

/// An error ocurred during the execution of the SimplPedPoP protocol.
#[derive(Debug)]
pub enum FROSTError {
    /// The number of signing commitments must be at least equal to the threshold.
    InvalidNumberOfSigningCommitments,
    /// The participant's signing commitment is missing.
    MissingOwnSigningCommitment,
    /// Commitment equals the identity
    IdentitySigningCommitment,
    /// The number of veriyfing shares must be equal to the number of signers.
    IncorrectNumberOfVerifyingShares,
    /// Error deserializing the signature share.
    SignatureShareDeserializationError,
    /// The signature share is invalid.
    InvalidSignatureShare {
        /// The verifying share(s) of the culprit(s).
        culprit: Vec<VerifyingShare>,
    },
    /// The output of the SimplPedPoP protocol must contain the participant's verifying share.
    InvalidOwnVerifyingShare,
    /// Invalid signature.
    InvalidSignature(SignatureError),
    /// Deserialization error.
    DeserializationError(TryFromSliceError),
    /// Invalid nonce commitment.
    InvalidNonceCommitment,
    /// Error deserializing the output of the SimplPedPoP protocol.
    SPPOutputDeserializationError(SPPError),
    /// The number of signing packages must be at least equal to the threshold.
    InvalidNumberOfSigningPackages,
    /// The common data of all the signing packages must be the same.
    MismatchedCommonData,
    /// The number of signature shares and the number of signing commitments must be the same.
    MismatchedSignatureSharesAndSigningCommitments,
    /// The signing packages are empty.
    EmptySigningPackages,
}

#[cfg(test)]
mod tests {
    use super::FROSTError;
    use crate::{
        olaf::{
            frost::types::{NonceCommitment, SigningCommitments},
            simplpedpop::{AllMessage, Parameters},
            SigningKeypair, GENERATOR, MINIMUM_THRESHOLD,
        },
        SigningKey, VerifyingKey,
    };
    use alloc::vec::Vec;
    use curve25519_dalek::{traits::Identity, EdwardsPoint, Scalar};
    use rand::Rng;
    use rand_core::OsRng;

    const MAXIMUM_PARTICIPANTS: u16 = 2;
    const MINIMUM_PARTICIPANTS: u16 = 2;

    fn generate_parameters() -> Parameters {
        let mut rng = rand::thread_rng();
        let participants = rng.gen_range(MINIMUM_PARTICIPANTS..=MAXIMUM_PARTICIPANTS);
        let threshold = rng.gen_range(MINIMUM_THRESHOLD..=participants);

        Parameters::generate(participants, threshold)
    }

    #[test]
    fn test_invalid_own_verifying_share_error() {
        let mut rng = OsRng;
        let parameters = generate_parameters();
        let participants = parameters.participants as usize;
        let threshold = parameters.threshold as usize;

        let mut keypairs: Vec<SigningKey> = (0..participants)
            .map(|_| SigningKey::generate(&mut rng))
            .collect();
        let public_keys: Vec<VerifyingKey> = keypairs.iter().map(|kp| kp.verifying_key).collect();

        let mut all_messages = Vec::new();
        for i in 0..participants {
            let message: AllMessage = keypairs[i]
                .simplpedpop_contribute_all(threshold as u16, public_keys.clone())
                .unwrap();
            all_messages.push(message);
        }

        let mut spp_outputs = Vec::new();

        for kp in &mut keypairs {
            let spp_output = kp.simplpedpop_recipient_all(&all_messages).unwrap();
            spp_outputs.push(spp_output);
        }

        let mut all_signing_commitments = Vec::new();
        let mut all_signing_nonces = Vec::new();

        for spp_output in &spp_outputs {
            let (signing_nonces, signing_commitments) = spp_output.1.commit(&mut OsRng);
            all_signing_nonces.push(signing_nonces);
            all_signing_commitments.push(signing_commitments);
        }

        let message = b"message";

        spp_outputs[0].1 = SigningKeypair(SigningKey::generate(&mut rng));

        let result = spp_outputs[0].1.sign(
            message,
            &spp_outputs[0].0.spp_output,
            &all_signing_commitments,
            &all_signing_nonces[0],
        );

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => match e {
                FROSTError::InvalidOwnVerifyingShare => assert!(true),
                _ => {
                    panic!(
                        "Expected FROSTError::InvalidOwnVerifyingShare, but got {:?}",
                        e
                    )
                }
            },
        }
    }

    #[test]
    fn test_incorrect_number_of_verifying_shares_error() {
        let mut rng = OsRng;
        let parameters = generate_parameters();
        let participants = parameters.participants as usize;
        let threshold = parameters.threshold as usize;

        let mut keypairs: Vec<SigningKey> = (0..participants)
            .map(|_| SigningKey::generate(&mut rng))
            .collect();
        let public_keys: Vec<VerifyingKey> = keypairs.iter().map(|kp| kp.verifying_key).collect();

        let mut all_messages = Vec::new();
        for i in 0..participants {
            let message: AllMessage = keypairs[i]
                .simplpedpop_contribute_all(threshold as u16, public_keys.clone())
                .unwrap();
            all_messages.push(message);
        }

        let mut spp_outputs = Vec::new();

        for kp in &mut keypairs {
            let spp_output = kp.simplpedpop_recipient_all(&all_messages).unwrap();
            spp_outputs.push(spp_output);
        }

        let mut all_signing_commitments = Vec::new();
        let mut all_signing_nonces = Vec::new();

        for spp_output in &spp_outputs {
            let (signing_nonces, signing_commitments) = spp_output.1.commit(&mut OsRng);
            all_signing_nonces.push(signing_nonces);
            all_signing_commitments.push(signing_commitments);
        }

        let message = b"message";

        spp_outputs[0].0.spp_output.verifying_keys.pop();

        let result = spp_outputs[0].1.sign(
            message,
            &spp_outputs[0].0.spp_output,
            &all_signing_commitments,
            &all_signing_nonces[0],
        );

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => match e {
                FROSTError::IncorrectNumberOfVerifyingShares => assert!(true),
                _ => {
                    panic!(
                        "Expected FROSTError::IncorrectNumberOfVerifyingShares, but got {:?}",
                        e
                    )
                }
            },
        }
    }

    #[test]
    fn test_missing_own_signing_commitment_error() {
        let mut rng = OsRng;
        let parameters = generate_parameters();
        let participants = parameters.participants as usize;
        let threshold = parameters.threshold as usize;

        let mut keypairs: Vec<SigningKey> = (0..participants)
            .map(|_| SigningKey::generate(&mut rng))
            .collect();
        let public_keys: Vec<VerifyingKey> = keypairs.iter().map(|kp| kp.verifying_key).collect();

        let mut all_messages = Vec::new();
        for i in 0..participants {
            let message: AllMessage = keypairs[i]
                .simplpedpop_contribute_all(threshold as u16, public_keys.clone())
                .unwrap();
            all_messages.push(message);
        }

        let mut spp_outputs = Vec::new();

        for kp in &mut keypairs {
            let spp_output = kp.simplpedpop_recipient_all(&all_messages).unwrap();
            spp_outputs.push(spp_output);
        }

        let mut all_signing_commitments = Vec::new();
        let mut all_signing_nonces = Vec::new();

        for spp_output in &spp_outputs {
            let (signing_nonces, signing_commitments) = spp_output.1.commit(&mut OsRng);
            all_signing_nonces.push(signing_nonces);
            all_signing_commitments.push(signing_commitments);
        }

        let message = b"message";

        all_signing_commitments[0] = SigningCommitments {
            hiding: NonceCommitment(Scalar::random(&mut OsRng) * GENERATOR),
            binding: NonceCommitment(Scalar::random(&mut OsRng) * GENERATOR),
        };

        let result = spp_outputs[0].1.sign(
            message,
            &spp_outputs[0].0.spp_output,
            &all_signing_commitments,
            &all_signing_nonces[0],
        );

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => match e {
                FROSTError::MissingOwnSigningCommitment => assert!(true),
                _ => {
                    panic!(
                        "Expected FROSTError::MissingOwnSigningCommitment, but got {:?}",
                        e
                    )
                }
            },
        }
    }

    #[test]
    fn test_identity_signing_commitment_error() {
        let mut rng = OsRng;
        let parameters = generate_parameters();
        let participants = parameters.participants as usize;
        let threshold = parameters.threshold as usize;

        let mut keypairs: Vec<SigningKey> = (0..participants)
            .map(|_| SigningKey::generate(&mut rng))
            .collect();
        let public_keys: Vec<VerifyingKey> = keypairs.iter().map(|kp| kp.verifying_key).collect();

        let mut all_messages = Vec::new();
        for i in 0..participants {
            let message: AllMessage = keypairs[i]
                .simplpedpop_contribute_all(threshold as u16, public_keys.clone())
                .unwrap();
            all_messages.push(message);
        }

        let mut spp_outputs = Vec::new();

        for kp in &mut keypairs {
            let spp_output = kp.simplpedpop_recipient_all(&all_messages).unwrap();
            spp_outputs.push(spp_output);
        }

        let mut all_signing_commitments = Vec::new();
        let mut all_signing_nonces = Vec::new();

        for spp_output in &spp_outputs {
            let (signing_nonces, signing_commitments) = spp_output.1.commit(&mut OsRng);
            all_signing_nonces.push(signing_nonces);
            all_signing_commitments.push(signing_commitments);
        }

        let message = b"message";

        all_signing_commitments[1].hiding = NonceCommitment(EdwardsPoint::identity());
        let result = spp_outputs[0].1.sign(
            message,
            &spp_outputs[0].0.spp_output,
            &all_signing_commitments,
            &all_signing_nonces[0],
        );

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => match e {
                FROSTError::IdentitySigningCommitment => assert!(true),
                _ => {
                    panic!(
                        "Expected FROSTError::IdentitySigningCommitment, but got {:?}",
                        e
                    )
                }
            },
        }
    }

    #[test]
    fn test_incorrect_number_of_signing_commitments_error() {
        let mut rng = OsRng;
        let parameters = generate_parameters();
        let participants = parameters.participants as usize;
        let threshold = parameters.threshold as usize;

        let mut keypairs: Vec<SigningKey> = (0..participants)
            .map(|_| SigningKey::generate(&mut rng))
            .collect();
        let public_keys: Vec<VerifyingKey> = keypairs.iter().map(|kp| kp.verifying_key).collect();

        let mut all_messages = Vec::new();
        for i in 0..participants {
            let message: AllMessage = keypairs[i]
                .simplpedpop_contribute_all(threshold as u16, public_keys.clone())
                .unwrap();
            all_messages.push(message);
        }

        let mut spp_outputs = Vec::new();

        for kp in &mut keypairs {
            let spp_output = kp.simplpedpop_recipient_all(&all_messages).unwrap();
            spp_outputs.push(spp_output);
        }

        let mut all_signing_commitments = Vec::new();
        let mut all_signing_nonces = Vec::new();

        for spp_output in &spp_outputs {
            let (signing_nonces, signing_commitments) = spp_output.1.commit(&mut OsRng);
            all_signing_nonces.push(signing_nonces);
            all_signing_commitments.push(signing_commitments);
        }

        let message = b"message";

        let result = spp_outputs[0].1.sign(
            message,
            &spp_outputs[0].0.spp_output,
            &all_signing_commitments[..1],
            &all_signing_nonces[0],
        );

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => match e {
                FROSTError::InvalidNumberOfSigningCommitments => assert!(true),
                _ => {
                    panic!(
                        "Expected FROSTError::IncorrectNumberOfSigningCommitments, but got {:?}",
                        e
                    )
                }
            },
        }
    }
}
