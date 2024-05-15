//! Errors of the Olaf protocol.

use crate::SignatureError;
use core::array::TryFromSliceError;

/// A result for the SimplPedPoP protocol.
pub type SPPResult<T> = Result<T, SPPError>;

/// An error ocurred during the execution of the SimplPedPoP protocol.
#[derive(Debug)]
pub enum SPPError {
    /// Invalid parameters.
    InvalidParameters,
    /// Threshold cannot be greater than the number of participants.
    ExcessiveThreshold,
    /// Threshold must be at least 2.
    InsufficientThreshold,
    /// Number of participants is invalid.
    InvalidNumberOfParticipants,
    /// Invalid public key.
    InvalidPublicKey(SignatureError),
    /// Invalid group public key.
    InvalidGroupPublicKey,
    /// Invalid signature.
    InvalidSignature(SignatureError),
    /// Invalid coefficient commitment of the polynomial commitment.
    InvalidCoefficientCommitment,
    /// Invalid identifier.
    InvalidIdentifier,
    /// Invalid secret share.
    InvalidSecretShare,
    /// Deserialization Error.
    DeserializationError(TryFromSliceError),
    /// The parameters of all messages must be equal.
    DifferentParameters,
    /// The recipients hash of all messages must be equal.
    DifferentRecipientsHash,
    /// The number of messages should be 2 at least, which the minimum number of participants.
    InvalidNumberOfMessages,
    /// The number of coefficient commitments of the polynomial commitment must be equal to the threshold - 1.
    IncorrectNumberOfCoefficientCommitments,
    /// The number of encrypted shares per message must be equal to the number of participants.
    IncorrectNumberOfEncryptedShares,
    /// Decryption error when decrypting an encrypted secret share.
    DecryptionError(chacha20poly1305::Error),
    /// Encryption error when encrypting the secret share.
    EncryptionError(chacha20poly1305::Error),
}

#[cfg(test)]
mod tests {
    use crate::olaf::simplpedpop::errors::SPPError;
    use crate::olaf::simplpedpop::types::{
        AllMessage, EncryptedSecretShare, Parameters, CHACHA20POLY1305_LENGTH,
        RECIPIENTS_HASH_LENGTH,
    };
    use crate::olaf::{GENERATOR, MINIMUM_THRESHOLD};
    use crate::{SigningKey, VerifyingKey};
    use alloc::vec::Vec;
    use curve25519_dalek::Scalar;
    use ed25519::signature::Signer;
    use rand::Rng;
    use rand_core::OsRng;

    const MAXIMUM_PARTICIPANTS: u16 = 10;
    const MINIMUM_PARTICIPANTS: u16 = 2;

    fn generate_parameters() -> Parameters {
        let mut rng = rand::thread_rng();
        let participants = rng.gen_range(MINIMUM_PARTICIPANTS..=MAXIMUM_PARTICIPANTS);
        let threshold = rng.gen_range(MINIMUM_THRESHOLD..=participants);

        Parameters {
            participants,
            threshold,
        }
    }

    #[test]
    fn test_invalid_number_of_messages() {
        let mut rng = OsRng;
        let parameters = generate_parameters();
        let participants = parameters.participants;
        let threshold = parameters.threshold;

        let mut keypairs: Vec<SigningKey> = (0..participants)
            .map(|_| SigningKey::generate(&mut rng))
            .collect();

        let public_keys: Vec<VerifyingKey> = keypairs
            .iter_mut()
            .map(|kp| kp.verifying_key.clone())
            .collect();

        let mut messages: Vec<AllMessage> = keypairs
            .iter_mut()
            .map(|kp| {
                kp.simplpedpop_contribute_all(threshold, public_keys.clone())
                    .unwrap()
            })
            .collect();

        messages.pop();

        let result = keypairs[0].simplpedpop_recipient_all(&messages);

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => match e {
                SPPError::InvalidNumberOfMessages => assert!(true),
                _ => {
                    panic!(
                        "Expected SPPError::InvalidNumberOfMessages, but got {:?}",
                        e
                    )
                }
            },
        }
    }

    #[test]
    fn test_different_parameters() {
        let parameters = generate_parameters();
        let participants = parameters.participants;
        let threshold = parameters.threshold;
        let mut rng = OsRng;

        let mut keypairs: Vec<SigningKey> = (0..participants)
            .map(|_| SigningKey::generate(&mut rng))
            .collect();
        let public_keys: Vec<VerifyingKey> =
            keypairs.iter().map(|kp| kp.verifying_key.clone()).collect();

        let mut messages: Vec<AllMessage> = Vec::new();
        for i in 0..participants {
            let message = keypairs[i as usize]
                .simplpedpop_contribute_all(threshold, public_keys.clone())
                .unwrap();
            messages.push(message);
        }

        messages[1].content.parameters.threshold += 1;

        let result = keypairs[0].simplpedpop_recipient_all(&messages);

        // Check if the result is an error
        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => match e {
                SPPError::DifferentParameters => assert!(true),
                _ => panic!("Expected SPPError::DifferentParameters, but got {:?}", e),
            },
        }
    }

    #[test]
    fn test_different_recipients_hash() {
        let parameters = generate_parameters();
        let participants = parameters.participants;
        let threshold = parameters.threshold;
        let mut rng = OsRng;

        let mut keypairs: Vec<SigningKey> = (0..participants)
            .map(|_| SigningKey::generate(&mut rng))
            .collect();
        let public_keys: Vec<VerifyingKey> =
            keypairs.iter().map(|kp| kp.verifying_key.clone()).collect();

        let mut messages: Vec<AllMessage> = keypairs
            .iter_mut()
            .map(|kp| {
                kp.simplpedpop_contribute_all(threshold, public_keys.clone())
                    .unwrap()
            })
            .collect();

        messages[1].content.recipients_hash = [1; RECIPIENTS_HASH_LENGTH];

        let result = keypairs[0].simplpedpop_recipient_all(&messages);

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => match e {
                SPPError::DifferentRecipientsHash => assert!(true),
                _ => {
                    panic!(
                        "Expected SPPError::DifferentRecipientsHash, but got {:?}",
                        e
                    )
                }
            },
        }
    }

    #[test]
    fn test_incorrect_number_of_commitments() {
        let parameters = generate_parameters();
        let participants = parameters.participants;
        let threshold = parameters.threshold;
        let mut rng = OsRng;

        let mut keypairs: Vec<SigningKey> = (0..participants)
            .map(|_| SigningKey::generate(&mut rng))
            .collect();
        let public_keys: Vec<VerifyingKey> =
            keypairs.iter().map(|kp| kp.verifying_key.clone()).collect();

        let mut messages: Vec<AllMessage> = keypairs
            .iter_mut()
            .map(|kp| {
                kp.simplpedpop_contribute_all(threshold, public_keys.clone())
                    .unwrap()
            })
            .collect();

        messages[1]
            .content
            .polynomial_commitment
            .coefficients_commitments
            .pop();

        let result = keypairs[0].simplpedpop_recipient_all(&messages);

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => match e {
                SPPError::IncorrectNumberOfCoefficientCommitments => assert!(true),
                _ => panic!(
                    "Expected SPPError::IncorrectNumberOfCoefficientCommitments, but got {:?}",
                    e
                ),
            },
        }
    }

    #[test]
    fn test_incorrect_number_of_encrypted_shares() {
        let parameters = generate_parameters();
        let participants = parameters.participants;
        let threshold = parameters.threshold;
        let mut rng = OsRng;

        let mut keypairs: Vec<SigningKey> = (0..participants)
            .map(|_| SigningKey::generate(&mut rng))
            .collect();
        let public_keys: Vec<VerifyingKey> =
            keypairs.iter().map(|kp| kp.verifying_key.clone()).collect();

        let mut messages: Vec<AllMessage> = keypairs
            .iter_mut()
            .map(|kp| {
                kp.simplpedpop_contribute_all(threshold, public_keys.clone())
                    .unwrap()
            })
            .collect();

        messages[1].content.encrypted_secret_shares.pop();

        let result = keypairs[0].simplpedpop_recipient_all(&messages);

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => match e {
                SPPError::IncorrectNumberOfEncryptedShares => assert!(true),
                _ => panic!(
                    "Expected SPPError::IncorrectNumberOfEncryptedShares, but got {:?}",
                    e
                ),
            },
        }
    }

    #[test]
    fn test_invalid_secret_share() {
        let parameters = generate_parameters();
        let participants = parameters.participants;
        let threshold = parameters.threshold;
        let mut rng = OsRng;

        let mut keypairs: Vec<SigningKey> = (0..participants)
            .map(|_| SigningKey::generate(&mut rng))
            .collect();
        let public_keys: Vec<VerifyingKey> =
            keypairs.iter().map(|kp| kp.verifying_key.clone()).collect();

        let mut messages: Vec<AllMessage> = keypairs
            .iter_mut()
            .map(|kp| {
                kp.simplpedpop_contribute_all(threshold, public_keys.clone())
                    .unwrap()
            })
            .collect();

        messages[1].content.encrypted_secret_shares[0] =
            EncryptedSecretShare(vec![1; CHACHA20POLY1305_LENGTH]);

        let result = keypairs[0].simplpedpop_recipient_all(&messages);

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => match e {
                SPPError::InvalidSecretShare => assert!(true),
                _ => panic!("Expected SPPError::InvalidSecretShare, but got {:?}", e),
            },
        }
    }

    #[test]
    fn test_invalid_signature() {
        let parameters = generate_parameters();
        let participants = parameters.participants;
        let threshold = parameters.threshold;
        let mut rng = OsRng;

        let mut keypairs: Vec<SigningKey> = (0..participants)
            .map(|_| SigningKey::generate(&mut rng))
            .collect();

        let public_keys: Vec<VerifyingKey> =
            keypairs.iter().map(|kp| kp.verifying_key.clone()).collect();

        let mut messages: Vec<AllMessage> = keypairs
            .iter_mut()
            .map(|kp| {
                kp.simplpedpop_contribute_all(threshold, public_keys.clone())
                    .unwrap()
            })
            .collect();

        messages[1].signature = keypairs[1].sign(b"invalid");

        let result = keypairs[0].simplpedpop_recipient_all(&messages);

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => match e {
                SPPError::InvalidSignature(_) => assert!(true),
                _ => panic!("Expected SPPError::InvalidSignature, but got {:?}", e),
            },
        }
    }

    #[test]
    fn test_invalid_threshold() {
        let mut rng = OsRng;
        let mut keypair = SigningKey::generate(&mut rng);

        let result = keypair.simplpedpop_contribute_all(
            1,
            vec![
                VerifyingKey::from(Scalar::random(&mut rng) * GENERATOR),
                VerifyingKey::from(Scalar::random(&mut rng) * GENERATOR),
            ],
        );

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => match e {
                SPPError::InsufficientThreshold => assert!(true),
                _ => panic!("Expected SPPError::InsufficientThreshold, but got {:?}", e),
            },
        }
    }

    #[test]
    fn test_invalid_participants() {
        let mut rng = OsRng;
        let mut keypair = SigningKey::generate(&mut rng);

        let result = keypair.simplpedpop_contribute_all(
            2,
            vec![VerifyingKey::from(Scalar::random(&mut rng) * GENERATOR)],
        );

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => match e {
                SPPError::InvalidNumberOfParticipants => assert!(true),
                _ => {
                    panic!(
                        "Expected SPPError::InvalidNumberOfParticipants, but got {:?}",
                        e
                    )
                }
            },
        }
    }

    #[test]
    fn test_threshold_greater_than_participants() {
        let mut rng = OsRng;
        let mut keypair = SigningKey::generate(&mut rng);

        let result = keypair.simplpedpop_contribute_all(
            3,
            vec![
                VerifyingKey::from(Scalar::random(&mut rng) * GENERATOR),
                VerifyingKey::from(Scalar::random(&mut rng) * GENERATOR),
            ],
        );

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => match e {
                SPPError::ExcessiveThreshold => assert!(true),
                _ => panic!("Expected SPPError::ExcessiveThreshold, but got {:?}", e),
            },
        }
    }
}
