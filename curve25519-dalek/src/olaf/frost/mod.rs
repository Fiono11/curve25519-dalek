//! Implementation of the FROST protocol (<https://eprint.iacr.org/2020/852>).

#![allow(non_snake_case)]

mod errors;
mod types;

use self::{
    errors::{FROSTError, FROSTResult},
    types::{
        BindingFactor, BindingFactorList, CommonData, GroupCommitment, SignatureShare, SignerData,
        SigningCommitments, SigningNonces, SigningPackage,
    },
};
use super::{
    simplpedpop::SPPOutput, Identifier, SigningKeypair, ThresholdPublicKey, VerifyingShare,
};
use alloc::vec::Vec;
use curve25519_dalek::Scalar;
use ed25519::{signature::Verifier, Signature};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

impl SigningKeypair {
    /// Done once by each participant, to generate _their_ nonces and commitments
    /// that are then used during signing.
    ///
    /// This is only needed if pre-processing is needed (for 1-round FROST). For
    /// regular 2-round FROST, use [`commit`].
    ///
    /// When performing signing using two rounds, num_nonces would equal 1, to
    /// perform the first round. Batching entails generating more than one
    /// nonce/commitment pair at a time.  Nonces should be stored in secret storage
    /// for later use, whereas the commitments are published.
    pub fn preprocess<R>(
        &self,
        num_nonces: u8,
        rng: &mut R,
    ) -> (Vec<SigningNonces>, Vec<SigningCommitments>)
    where
        R: CryptoRng + RngCore,
    {
        let mut signing_nonces: Vec<SigningNonces> = Vec::with_capacity(num_nonces as usize);
        let mut signing_commitments: Vec<SigningCommitments> =
            Vec::with_capacity(num_nonces as usize);

        for _ in 0..num_nonces {
            let nonces = SigningNonces::new(&self.0.secret_key, rng);
            signing_commitments.push(SigningCommitments::from(&nonces));
            signing_nonces.push(nonces);
        }

        (signing_nonces, signing_commitments)
    }

    /// Performed once by each participant selected for the signing operation.
    ///
    /// Implements [`commit`] from the spec.
    ///
    /// Generates the signing nonces and commitments to be used in the signing
    /// operation.
    ///
    /// [`commit`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#name-round-one-commitment.
    pub fn commit<R>(&self, rng: &mut R) -> (SigningNonces, SigningCommitments)
    where
        R: CryptoRng + RngCore,
    {
        let (mut vec_signing_nonces, mut vec_signing_commitments) = self.preprocess(1, rng);
        (
            vec_signing_nonces.pop().expect("must have 1 element"),
            vec_signing_commitments.pop().expect("must have 1 element"),
        )
    }

    /// Performed once by each participant selected for the signing operation.
    ///
    /// Implements [`sign`] from the spec.
    ///
    /// Receives the message to be signed and a set of signing commitments and a set
    /// of randomizing commitments to be used in that signing operation, including
    /// that for this participant.
    ///
    /// Assumes the participant has already determined which nonce corresponds with
    /// the commitment that was assigned by the coordinator in the SigningPackage.
    ///
    /// [`sign`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#name-round-two-signature-share-g
    /// Performed once by each participant selected for the signing operation.
    ///
    /// Implements [`sign`] from the spec.
    ///
    /// Receives the message to be signed and a set of signing commitments and a set
    /// of randomizing commitments to be used in that signing operation, including
    /// that for this participant.
    ///
    /// Assumes the participant has already determined which nonce corresponds with
    /// the commitment that was assigned by the coordinator in the SigningPackage.
    ///
    /// [`sign`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#name-round-two-signature-share-g
    pub fn sign(
        &self,
        message: &[u8],
        spp_output: &SPPOutput,
        all_signing_commitments: &[SigningCommitments],
        signer_nonces: &SigningNonces,
    ) -> FROSTResult<SigningPackage> {
        let len = all_signing_commitments.len();

        if len < spp_output.parameters.threshold as usize {
            return Err(FROSTError::InvalidNumberOfSigningCommitments);
        }

        if spp_output.verifying_keys.len() != len {
            return Err(FROSTError::IncorrectNumberOfVerifyingShares);
        }

        if !all_signing_commitments.contains(&signer_nonces.commitments) {
            return Err(FROSTError::MissingOwnSigningCommitment);
        }

        let mut identifiers = Vec::new();
        let mut shares = Vec::new();

        let mut index = 0;

        let own_verifying_share = VerifyingShare(self.0.verifying_key);

        for (i, (identifier, share)) in spp_output.verifying_keys.iter().enumerate() {
            identifiers.push(identifier);
            shares.push(share);

            if share == &own_verifying_share {
                index = i;
            }
        }

        if !shares.contains(&&own_verifying_share) {
            return Err(FROSTError::InvalidOwnVerifyingShare);
        }

        if all_signing_commitments.len() < spp_output.parameters.threshold as usize {
            return Err(FROSTError::InvalidNumberOfSigningCommitments);
        }

        let binding_factor_list: BindingFactorList = BindingFactorList::compute(
            all_signing_commitments,
            &spp_output.threshold_public_key,
            message,
            &[],
        );

        let group_commitment =
            GroupCommitment::compute(all_signing_commitments, &binding_factor_list)?;

        let identifiers_vec: Vec<_> = spp_output.verifying_keys.iter().map(|x| x.0).collect();

        let lambda_i = compute_lagrange_coefficient(&identifiers_vec, None, *identifiers[index]);

        let mut preimage = vec![];

        preimage.extend_from_slice(group_commitment.0.compress().as_bytes());
        preimage.extend_from_slice(spp_output.threshold_public_key.0.as_bytes());
        preimage.extend_from_slice(&message);

        let challenge = hash_to_scalar(&[&preimage[..]]);

        let signature_share = self.compute_signature_share(
            signer_nonces,
            &binding_factor_list.0[index].1,
            &lambda_i,
            &challenge,
        );

        let signer_data = SignerData { signature_share };
        let common_data = CommonData {
            message: message.to_vec(),
            signing_commitments: all_signing_commitments.to_vec(),
            spp_output: spp_output.clone(),
        };

        let signing_package = SigningPackage {
            signer_data,
            common_data,
        };

        Ok(signing_package)
    }

    fn compute_signature_share(
        &self,
        signer_nonces: &SigningNonces,
        binding_factor: &BindingFactor,
        lambda_i: &Scalar,
        challenge: &Scalar,
    ) -> SignatureShare {
        let z_share: Scalar = signer_nonces.hiding.0
            + (signer_nonces.binding.0 * binding_factor.0)
            + (lambda_i * Scalar::from_canonical_bytes(self.0.secret_key).unwrap() * challenge);

        SignatureShare { share: z_share }
    }
}

/// Aggregates the signature shares to produce a final signature that
/// can be verified with the group public key.
///
/// `signature_shares` maps the identifier of each participant to the
/// [`round2::SignatureShare`] they sent. These identifiers must come from whatever mapping
/// the coordinator has between communication channels and participants, i.e.
/// they must have assurance that the [`round2::SignatureShare`] came from
/// the participant with that identifier.
///
/// This operation is performed by a coordinator that can communicate with all
/// the signing participants before publishing the final signature. The
/// coordinator can be one of the participants or a semi-trusted third party
/// (who is trusted to not perform denial of service attacks, but does not learn
/// any secret information). Note that because the coordinator is trusted to
/// report misbehaving parties in order to avoid publishing an invalid
/// signature, if the coordinator themselves is a signer and misbehaves, they
/// can avoid that step. However, at worst, this results in a denial of
/// service attack due to publishing an invalid signature.
pub fn aggregate(signing_packages: &[SigningPackage]) -> Result<Signature, FROSTError> {
    if signing_packages.is_empty() {
        return Err(FROSTError::EmptySigningPackages);
    }

    let parameters = &signing_packages[0].common_data.spp_output.parameters;

    if signing_packages.len() < parameters.threshold as usize {
        return Err(FROSTError::InvalidNumberOfSigningPackages);
    }

    let common_data = &signing_packages[0].common_data;
    let message = &common_data.message;
    let signing_commitments = &common_data.signing_commitments;
    let threshold_public_key = &common_data.spp_output.threshold_public_key;
    let spp_output = &common_data.spp_output;
    let mut signature_shares = Vec::new();

    for signing_package in signing_packages.iter() {
        if &signing_package.common_data != common_data {
            return Err(FROSTError::MismatchedCommonData);
        }

        signature_shares.push(signing_package.signer_data.signature_share.clone());
    }

    if signature_shares.len() != signing_commitments.len() {
        return Err(FROSTError::MismatchedSignatureSharesAndSigningCommitments);
    }

    let binding_factor_list: BindingFactorList =
        BindingFactorList::compute(signing_commitments, &threshold_public_key, message, &[]);

    let group_commitment = GroupCommitment::compute(signing_commitments, &binding_factor_list)?;

    let mut s = Scalar::ZERO;

    for signature_share in &signature_shares {
        s += signature_share.share;
    }

    let mut bytes = [0; 64];
    bytes[0..32].copy_from_slice(group_commitment.0.compress().as_bytes());
    bytes[32..].copy_from_slice(s.as_bytes());

    let group_signature = Signature::from_bytes(&bytes);

    let verification_result = threshold_public_key
        .0
        .verify(message, &group_signature)
        .map_err(FROSTError::InvalidSignature);

    let identifiers: Vec<Identifier> = spp_output.verifying_keys.iter().map(|x| x.0).collect();

    let verifying_shares: Vec<VerifyingShare> =
        spp_output.verifying_keys.iter().map(|x| x.1).collect();

    let mut valid_shares = Vec::new();

    // Only if the verification of the aggregate signature failed; verify each share to find the cheater.
    // This approach is more efficient since we don't need to verify all shares
    // if the aggregate signature is valid (which should be the common case).
    if verification_result.is_err() {
        // Compute the per-message challenge.
        let mut preimage = vec![];

        preimage.extend_from_slice(group_commitment.0.compress().as_bytes());
        preimage.extend_from_slice(spp_output.threshold_public_key.0.as_bytes());
        preimage.extend_from_slice(&message);

        let challenge = hash_to_scalar(&[&preimage[..]]);

        // Verify the signature shares.
        for (j, signature_share) in signature_shares.iter().enumerate() {
            for (i, (identifier, verifying_share)) in spp_output.verifying_keys.iter().enumerate() {
                let lambda_i = compute_lagrange_coefficient(&identifiers, None, *identifier);

                let binding_factor = &binding_factor_list.0.get(i).expect("This never fails because signature_shares.len() == signing_commitments.len().").1;

                let R_share = signing_commitments[j].to_group_commitment_share(binding_factor);

                if signature_share.verify(&R_share, verifying_share, lambda_i, &challenge) {
                    valid_shares.push(*verifying_share);
                    break;
                }
            }
        }

        let mut invalid_shares = Vec::new();

        for verifying_share in verifying_shares {
            if !valid_shares.contains(&verifying_share) {
                invalid_shares.push(verifying_share);
            }
        }

        return Err(FROSTError::InvalidSignatureShare {
            culprit: invalid_shares,
        });
    }

    Ok(group_signature)
}

pub(super) fn hash_to_array(inputs: &[&[u8]]) -> [u8; 64] {
    let mut h = Sha512::new();
    for i in inputs {
        h.update(i);
    }
    let mut output = [0u8; 64];
    output.copy_from_slice(h.finalize().as_slice());
    output
}

pub(super) fn hash_to_scalar(inputs: &[&[u8]]) -> Scalar {
    let output = hash_to_array(inputs);
    Scalar::from_bytes_mod_order_wide(&output)
}

/// Generates a lagrange coefficient.
///
/// The Lagrange polynomial for a set of points (x_j, y_j) for 0 <= j <= k
/// is ∑_{i=0}^k y_i.ℓ_i(x), where ℓ_i(x) is the Lagrange basis polynomial:
///
/// ℓ_i(x) = ∏_{0≤j≤k; j≠i} (x - x_j) / (x_i - x_j).
///
/// This computes ℓ_j(x) for the set of points `xs` and for the j corresponding
/// to the given xj.
///
/// If `x` is None, it uses 0 for it (since Identifiers can't be 0).
pub(super) fn compute_lagrange_coefficient(
    x_set: &[Identifier],
    x: Option<Identifier>,
    x_i: Identifier,
) -> Scalar {
    let mut num = Scalar::ONE;
    let mut den = Scalar::ONE;

    for x_j in x_set.iter() {
        if x_i == *x_j {
            continue;
        }

        if let Some(x) = x {
            num *= x.0 - x_j.0;
            den *= x_i.0 - x_j.0;
        } else {
            // Both signs inverted just to avoid requiring Neg (-*xj)
            num *= x_j.0;
            den *= x_j.0 - x_i.0;
        }
    }

    num * den.invert()
}

#[cfg(test)]
mod tests {
    use super::{
        aggregate,
        types::{SigningCommitments, SigningNonces},
    };
    use crate::{
        olaf::{
            simplpedpop::{AllMessage, Parameters},
            test_utils::generate_parameters,
            MINIMUM_THRESHOLD,
        },
        SigningKey, VerifyingKey,
    };
    use alloc::vec::Vec;
    use rand::Rng;
    use rand_core::OsRng;

    const NONCES: u8 = 10;

    #[test]
    fn test_n_of_n_frost_with_simplpedpop() {
        let mut rng = OsRng;
        let parameters = generate_parameters();
        let participants = parameters.participants as usize;
        let threshold = parameters.threshold as usize;

        let mut keypairs: Vec<SigningKey> = (0..participants)
            .map(|_| SigningKey::generate(&mut rng))
            .collect();
        let public_keys: Vec<VerifyingKey> =
            keypairs.iter_mut().map(|kp| kp.verifying_key).collect();

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

        let mut signing_packages = Vec::new();

        let message = b"message";

        for (i, spp_output) in spp_outputs.iter().enumerate() {
            let signature_share = spp_output
                .1
                .sign(
                    message,
                    &spp_output.0.spp_output,
                    &all_signing_commitments,
                    &all_signing_nonces[i],
                )
                .unwrap();

            signing_packages.push(signature_share);
        }

        aggregate(&signing_packages).unwrap();
    }

    #[test]
    fn test_t_of_n_frost_with_simplpedpop() {
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
            let mut spp_output = kp.simplpedpop_recipient_all(&all_messages).unwrap();

            spp_output.0.spp_output.verifying_keys = spp_output
                .0
                .spp_output
                .verifying_keys
                .into_iter()
                .take(threshold)
                .collect();

            spp_outputs.push(spp_output);
        }

        let mut all_signing_commitments = Vec::new();
        let mut all_signing_nonces = Vec::new();

        for spp_output in &spp_outputs[..threshold] {
            let (signing_nonces, signing_commitments) = spp_output.1.commit(&mut OsRng);
            all_signing_nonces.push(signing_nonces);
            all_signing_commitments.push(signing_commitments);
        }

        let mut signing_packages = Vec::new();

        let message = b"message";

        for (i, spp_output) in spp_outputs[..threshold].iter().enumerate() {
            let signature_share = spp_output
                .1
                .sign(
                    message,
                    &spp_output.0.spp_output,
                    &all_signing_commitments,
                    &all_signing_nonces[i],
                )
                .unwrap();

            signing_packages.push(signature_share);
        }

        aggregate(&signing_packages).unwrap();
    }

    #[test]
    fn test_preprocessing_frost_with_simplpedpop() {
        let mut rng = OsRng;
        let parameters = generate_parameters();
        let participants = parameters.participants as usize;
        let threshold = parameters.threshold as usize;

        let mut keypairs: Vec<SigningKey> = (0..participants)
            .map(|_| SigningKey::generate(&mut rng))
            .collect();
        let public_keys: Vec<VerifyingKey> =
            keypairs.iter_mut().map(|kp| kp.verifying_key).collect();

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

        let group_public_key = spp_outputs[0].0.spp_output.threshold_public_key;

        let mut all_nonces_map: Vec<Vec<SigningNonces>> = Vec::new();
        let mut all_commitments_map: Vec<Vec<SigningCommitments>> = Vec::new();

        for spp_output in &spp_outputs {
            let (nonces, commitments) = spp_output.1.preprocess(NONCES, &mut OsRng);

            all_nonces_map.push(nonces);
            all_commitments_map.push(commitments);
        }

        let mut nonces: Vec<&SigningNonces> = Vec::new();
        let mut commitments: Vec<Vec<SigningCommitments>> = Vec::new();

        for i in 0..NONCES {
            let mut comms = Vec::new();

            for (j, _) in spp_outputs.iter().enumerate() {
                nonces.push(&all_nonces_map[j][i as usize]);
                comms.push(all_commitments_map[j][i as usize].clone())
            }
            commitments.push(comms);
        }

        let mut signing_packages = Vec::new();

        let mut messages = Vec::new();

        for i in 0..NONCES {
            let mut message = b"message".to_vec();
            message.extend_from_slice(&i.to_be_bytes());
            messages.push(message);
        }

        for i in 0..NONCES {
            let message = &messages[i as usize];

            let commitments: Vec<SigningCommitments> = commitments[i as usize].clone();

            for (j, spp_output) in spp_outputs.iter().enumerate() {
                let nonces_to_use = &all_nonces_map[j][i as usize];

                let signature_share = spp_output
                    .1
                    .sign(
                        &message,
                        &spp_output.0.spp_output,
                        &commitments,
                        nonces_to_use,
                    )
                    .unwrap();

                signing_packages.push(signature_share);
            }

            aggregate(&signing_packages).unwrap();

            signing_packages = Vec::new();
        }
    }
}
