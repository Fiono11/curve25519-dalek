use super::{
    errors::{DKGError, DKGResult},
    types::{
        AllMessage, DKGOutput, DKGOutputMessage, MessageContent, Parameters, PolynomialCommitment,
        SecretPolynomial, SecretShare, CHACHA20POLY1305_KEY_LENGTH, ENCRYPTION_NONCE_LENGTH,
        RECIPIENTS_HASH_LENGTH,
    },
    GroupPublicKey, Identifier, SigningShare, VerifyingShare, GENERATOR,
};
use crate::{SecretKey, SigningKey, VerifyingKey};
use alloc::vec::Vec;
use curve25519_dalek::{traits::Identity, EdwardsPoint, Scalar};
use ed25519::signature::{SignerMut, Verifier};
use merlin::Transcript;
use rand_core::{OsRng, RngCore};

impl SigningKey {
    /// First round of the SimplPedPoP protocol.
    pub fn simplpedpop_contribute_all(
        &mut self,
        threshold: u16,
        recipients: Vec<VerifyingKey>,
    ) -> DKGResult<AllMessage> {
        let parameters = Parameters::generate(recipients.len() as u16, threshold);
        parameters.validate()?;

        let mut rng = OsRng;

        // We do not recipients.sort() because the protocol is simpler
        // if we require that all contributions provide the list in
        // exactly the same order.
        //
        // Instead we create a kind of session id by hashing the list
        // provided, but we provide only hash to recipients, not the
        // full recipients list.
        let mut recipients_transcript = Transcript::new(b"RecipientsHash");
        parameters.commit(&mut recipients_transcript);

        for recipient in &recipients {
            recipients_transcript.append_message(b"recipient", recipient.as_bytes());
        }

        let mut recipients_hash = [0u8; RECIPIENTS_HASH_LENGTH];
        recipients_transcript.challenge_bytes(b"finalize", &mut recipients_hash);

        let secret_polynomial =
            SecretPolynomial::generate(parameters.threshold as usize - 1, &mut rng);

        let mut encrypted_secret_shares = Vec::new();

        let polynomial_commitment = PolynomialCommitment::commit(&secret_polynomial);

        let mut encryption_transcript = Transcript::new(b"Encryption");
        parameters.commit(&mut encryption_transcript);
        encryption_transcript.append_message(b"contributor", self.verifying_key.as_bytes());

        let mut encryption_nonce = [0u8; ENCRYPTION_NONCE_LENGTH];
        rng.fill_bytes(&mut encryption_nonce);
        encryption_transcript.append_message(b"nonce", &encryption_nonce);

        let secret = *secret_polynomial
            .coefficients
            .first()
            .expect("This never fails because the minimum threshold is 2");

        let mut nonce: [u8; 32] = [0u8; 32];
        rng.fill_bytes(&mut nonce);

        let ephemeral_key = SigningKey::from_bytes(secret.as_bytes());

        for i in 0..parameters.participants {
            let identifier = Identifier::generate(&recipients_hash, i);

            let polynomial_evaluation = secret_polynomial.evaluate(&identifier.0);

            let secret_share = SecretShare(polynomial_evaluation);

            let recipient = recipients[i as usize];

            let key_exchange: EdwardsPoint = secret * recipient.point;

            //println!("secret: {:?}", secret);
            println!("point1-A: {:?}", secret * GENERATOR);
            //println!("scalar: {:?}", ephemeral_key.to_scalar());
            println!("point2-A: {:?}", recipient.point);

            let mut encryption_transcript = encryption_transcript.clone();
            encryption_transcript.append_message(b"recipient", recipient.as_bytes());
            encryption_transcript
                .append_message(b"key exchange", &key_exchange.compress().as_bytes()[..]);
            encryption_transcript.append_message(b"i", &(i as usize).to_le_bytes());

            let mut key_bytes = [0; CHACHA20POLY1305_KEY_LENGTH];
            encryption_transcript.challenge_bytes(b"key", &mut key_bytes);

            let encrypted_secret_share = secret_share.encrypt(&key_bytes, &encryption_nonce)?;

            encrypted_secret_shares.push(encrypted_secret_share);
        }

        let message_content = MessageContent::new(
            self.verifying_key,
            encryption_nonce,
            parameters,
            recipients_hash,
            polynomial_commitment,
            encrypted_secret_shares,
        );

        let signature = self.sign(&message_content.to_bytes());

        Ok(AllMessage::new(message_content, signature))
    }

    /// Second round of the SimplPedPoP protocol.
    pub fn simplpedpop_recipient_all(
        &mut self,
        messages: &[AllMessage],
    ) -> DKGResult<(DKGOutputMessage, SigningShare)> {
        let first_message = &messages[0];
        let parameters = &first_message.content.parameters;
        let threshold = parameters.threshold as usize;
        let participants = parameters.participants as usize;

        first_message.content.parameters.validate()?;

        if messages.len() < participants {
            return Err(DKGError::InvalidNumberOfMessages);
        }

        let mut secret_shares = Vec::with_capacity(participants);
        let mut verifying_keys = Vec::with_capacity(participants);
        let mut senders = Vec::with_capacity(participants);
        let mut signatures = Vec::with_capacity(participants);
        let mut signatures_messages = Vec::with_capacity(participants);
        let mut group_point = EdwardsPoint::identity();
        let mut total_secret_share = Scalar::ZERO;
        let mut total_polynomial_commitment = PolynomialCommitment {
            coefficients_commitments: vec![],
        };
        let mut identifiers = Vec::new();

        for (j, message) in messages.iter().enumerate() {
            message
                .content
                .sender
                .verify(&message.content.to_bytes(), &message.signature)
                .map_err(DKGError::InvalidSignature)?;

            if &message.content.parameters != parameters {
                return Err(DKGError::DifferentParameters);
            }
            if message.content.recipients_hash != first_message.content.recipients_hash {
                return Err(DKGError::DifferentRecipientsHash);
            }

            let content = &message.content;
            let polynomial_commitment = &content.polynomial_commitment;
            let encrypted_secret_shares = &content.encrypted_secret_shares;

            let secret_commitment: EdwardsPoint = *polynomial_commitment
                .coefficients_commitments
                .first()
                .expect("This never fails because the minimum threshold is 2");

            senders.push(content.sender);
            signatures.push(message.signature);

            let mut encryption_transcript = Transcript::new(b"Encryption");
            parameters.commit(&mut encryption_transcript);
            encryption_transcript.append_message(b"contributor", content.sender.as_bytes());
            encryption_transcript.append_message(b"nonce", &content.encryption_nonce);

            if polynomial_commitment.coefficients_commitments.len() != threshold {
                return Err(DKGError::IncorrectNumberOfCoefficientCommitments);
            }

            if encrypted_secret_shares.len() != participants {
                return Err(DKGError::IncorrectNumberOfEncryptedShares);
            }

            signatures_messages.push(content.to_bytes());

            total_polynomial_commitment = PolynomialCommitment::sum_polynomial_commitments(&[
                &total_polynomial_commitment,
                &polynomial_commitment,
            ]);

            let key_exchange: EdwardsPoint = self.to_scalar() * secret_commitment;

            assert!(self.to_scalar() * GENERATOR == self.verifying_key.point);

            println!("point1-B: {:?}", secret_commitment);
            println!("point2-B: {:?}", self.to_scalar() * GENERATOR);

            encryption_transcript.append_message(b"recipient", self.verifying_key.as_bytes());
            encryption_transcript
                .append_message(b"key exchange", &key_exchange.compress().as_bytes()[..]);

            let mut secret_share_found = false;

            for (i, encrypted_secret_share) in encrypted_secret_shares.iter().enumerate() {
                let mut encryption_transcript = encryption_transcript.clone();

                encryption_transcript.append_message(b"i", &i.to_le_bytes());

                let mut key_bytes = [0; CHACHA20POLY1305_KEY_LENGTH];
                encryption_transcript.challenge_bytes(b"key", &mut key_bytes);

                if identifiers.len() != participants {
                    let identifier =
                        Identifier::generate(&first_message.content.recipients_hash, i as u16);
                    identifiers.push(identifier);
                }

                if !secret_share_found {
                    if let Ok(secret_share) =
                        encrypted_secret_share.decrypt(&key_bytes, &content.encryption_nonce)
                    {
                        if secret_share.0 * GENERATOR
                            == polynomial_commitment.evaluate(&identifiers[i].0)
                        {
                            secret_shares.push(secret_share);
                            secret_share_found = true;
                        }
                    }
                }
            }

            total_secret_share += secret_shares.get(j).ok_or(DKGError::InvalidSecretShare)?.0;
            group_point += secret_commitment;
        }

        for id in &identifiers {
            let evaluation = total_polynomial_commitment.evaluate(&id.0);
            verifying_keys.push((*id, VerifyingShare(VerifyingKey::from(evaluation))));
        }

        let dkg_output = DKGOutput::new(
            GroupPublicKey(VerifyingKey::from(group_point)),
            verifying_keys,
        );

        let signature = self.sign(&dkg_output.to_bytes());
        let dkg_output = DKGOutputMessage::new(self.verifying_key, dkg_output, signature);

        let mut nonce: [u8; 32] = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);

        let signing_key = SigningKey::from_bytes(total_secret_share.as_bytes());

        Ok((dkg_output, SigningShare(signing_key.secret_key)))
    }
}
