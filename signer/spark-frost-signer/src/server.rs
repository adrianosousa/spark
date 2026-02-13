use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use frost_service_server::FrostService;
use rayon::prelude::*;
use spark_frost::hex_string_to_identifier;
use spark_frost::proto::common::*;
use spark_frost::proto::frost::*;
use tonic::{Request, Response, Status};
use tracing::{info, instrument};

use crate::dkg::{
    key_package_from_dkg_result, round1_package_maps_from_package_maps,
    round2_package_maps_from_package_maps, DKGState,
};

#[derive(Debug, Default)]
pub struct FrostDKGState {
    state: HashMap<String, DKGState>,
}

#[derive(Debug, Default)]
pub struct FrostServer {
    dkg_state: Arc<Mutex<FrostDKGState>>,
}

#[tonic::async_trait]
impl FrostService for FrostServer {
    /// Test function for gRPC connectivity
    ///
    /// This endpoint simply echoes back the received message with a prefix,
    /// allowing clients to verify the gRPC connection is working properly.
    async fn echo(&self, request: Request<EchoRequest>) -> Result<Response<EchoResponse>, Status> {
        let message = request.get_ref().message.clone();
        Ok(Response::new(EchoResponse {
            message: format!("echo: {message}"),
        }))
    }

    async fn dkg_round1(
        &self,
        request: Request<DkgRound1Request>,
    ) -> Result<Response<DkgRound1Response>, Status> {
        tracing::info!("Received DKG round 1 request");
        let req = request.get_ref();
        if req.min_signers > req.max_signers {
            return Err(Status::invalid_argument(
                "min_signers must be less than max_signers",
            ));
        }

        if req.min_signers < 1 {
            return Err(Status::invalid_argument("min_signers must be at least 1"));
        }

        if req.max_signers > u16::MAX as u64 {
            return Err(Status::invalid_argument(
                "max_signers must be less than 65535",
            ));
        }

        let identifier = hex_string_to_identifier(&req.identifier).map_err(|e| {
            Status::internal(format!("Failed to convert hex string to identifier: {e:?}"))
        })?;
        let min_signers = req.min_signers as u16;
        let max_signers = req.max_signers as u16;
        let key_count = req.key_count as usize;

        let mut dkg_state = self.dkg_state.lock().unwrap();

        if dkg_state.state.contains_key(&req.request_id) {
            return Err(Status::internal("DKG state is not None"));
        }

        let round1_results: Result<Vec<_>, Status> = (0..key_count)
            .into_par_iter()
            .map(|_| {
                let mut rng = rand::thread_rng();
                let (round1_secret_packages, round1_packages) =
                    frost_secp256k1_tr::keys::dkg::part1(
                        identifier,
                        max_signers,
                        min_signers,
                        &mut rng,
                    )
                    .map_err(|e| {
                        Status::internal(format!("Failed to generate DKG round 1: {e:?}"))
                    })?;
                let serialized = round1_packages.serialize().map_err(|e| {
                    Status::internal(format!("Failed to serialize DKG round 1 package: {e:?}"))
                })?;
                Ok((round1_secret_packages, serialized))
            })
            .collect();

        let (result_secret_packages, result_packages): (Vec<_>, Vec<_>) =
            round1_results?.into_iter().unzip();

        dkg_state.state.insert(
            req.request_id.clone(),
            DKGState::Round1(result_secret_packages),
        );

        Ok(Response::new(DkgRound1Response {
            round1_packages: result_packages,
        }))
    }

    async fn dkg_round2(
        &self,
        request: Request<DkgRound2Request>,
    ) -> Result<Response<DkgRound2Response>, Status> {
        tracing::info!("Received DKG round 2 request");
        let req = request.get_ref();
        let mut dkg_state = self.dkg_state.lock().unwrap();
        let round1_secrets = match dkg_state.state.get(&req.request_id) {
            Some(DKGState::Round1(secrets)) => secrets,
            _ => return Err(Status::internal("DKG state is not Round1")),
        };
        let round1_packages_maps = round1_package_maps_from_package_maps(&req.round1_packages_maps)
            .map_err(|e| {
                Status::internal(format!("Failed to parse round1 packages maps: {e:?}"))
            })?;

        if round1_packages_maps.len() != round1_secrets.len() {
            return Err(Status::internal(
                "Number of round1 packages maps does not match number of round1 secrets",
            ));
        }

        let parallel_results: Result<Vec<_>, Status> = round1_secrets
            .par_iter()
            .zip(round1_packages_maps.par_iter())
            .map(|(round1_secret, round1_packages_map)| {
                let (round2_secret, round2_packages) = frost_secp256k1_tr::keys::dkg::part2(
                    round1_secret.clone(),
                    round1_packages_map,
                )
                .map_err(|e| Status::internal(format!("Failed to generate DKG round 2: {e:?}")))?;

                let packages_map = round2_packages
                    .into_iter()
                    .map(|(id, pkg)| {
                        let serialized =
                            pkg.serialize().expect("Failed to serialize round2 package");
                        (hex::encode(id.serialize()), serialized)
                    })
                    .collect::<HashMap<String, Vec<u8>>>();

                Ok((
                    round2_secret,
                    PackageMap {
                        packages: packages_map,
                    },
                ))
            })
            .collect();

        let parallel_results = parallel_results?;
        let mut result_secret_packages = Vec::with_capacity(parallel_results.len());
        let mut result_packages = Vec::with_capacity(parallel_results.len());
        for (round2_secret, package_map) in parallel_results {
            result_secret_packages.push(round2_secret);
            result_packages.push(package_map);
        }

        dkg_state.state.insert(
            req.request_id.clone(),
            DKGState::Round2(result_secret_packages),
        );

        Ok(Response::new(DkgRound2Response {
            round2_packages: result_packages,
        }))
    }

    async fn dkg_round3(
        &self,
        request: Request<DkgRound3Request>,
    ) -> Result<Response<DkgRound3Response>, Status> {
        tracing::info!("Received DKG round 3 request");
        let request = request.into_inner();

        let mut dkg_state = self.dkg_state.lock().unwrap();
        let round2_secrets = match dkg_state.state.get(&request.request_id) {
            Some(DKGState::Round2(secrets)) => secrets.clone(),
            _ => {
                return Err(Status::internal(
                    "DKG state is not in Round2, cannot proceed with Round3",
                ));
            }
        };

        let round1_packages_maps =
            round1_package_maps_from_package_maps(&request.round1_packages_maps).map_err(|e| {
                Status::internal(format!("Failed to parse round1 packages maps: {e:?}"))
            })?;

        let round2_packages_maps =
            round2_package_maps_from_package_maps(&request.round2_packages_maps).map_err(|e| {
                Status::internal(format!("Failed to parse round2 packages maps: {e:?}"))
            })?;

        if round1_packages_maps.len() != round2_secrets.len()
            || round2_packages_maps.len() != round2_secrets.len()
        {
            return Err(Status::internal(
                "Number of packages maps does not match number of round2 secrets",
            ));
        }

        let key_packages: Vec<_> = (0..round2_secrets.len())
            .into_par_iter()
            .map(|idx| {
                let round2_secret = round2_secrets[idx].clone();
                let round1_packages = &round1_packages_maps[idx];
                let round2_packages = &round2_packages_maps[idx];

                let (secret_package, public_package) = frost_secp256k1_tr::keys::dkg::part3(
                    &round2_secret,
                    round1_packages,
                    round2_packages,
                )
                .map_err(|e| Status::internal(format!("Failed to generate DKG round 3: {e:?}")))?;

                key_package_from_dkg_result(secret_package, public_package).map_err(|e| {
                    Status::internal(format!(
                        "Failed to convert DKG result to key package: {e:?}"
                    ))
                })
            })
            .collect::<Result<Vec<_>, Status>>()?;

        dkg_state.state.remove(&request.request_id);

        Ok(Response::new(DkgRound3Response { key_packages }))
    }

    async fn frost_nonce(
        &self,
        request: Request<FrostNonceRequest>,
    ) -> Result<Response<FrostNonceResponse>, Status> {
        tracing::info!("Received frost nonce request");
        let response =
            spark_frost::signing::frost_nonce(request.get_ref()).map_err(Status::internal)?;
        Ok(Response::new(response))
    }

    #[instrument(fields(trace_id = %uuid::Uuid::new_v4()), skip(self, request))]
    async fn sign_frost(
        &self,
        request: Request<SignFrostRequest>,
    ) -> Result<Response<SignFrostResponse>, Status> {
        info!("Received frost sign request");
        let response =
            spark_frost::signing::sign_frost(request.get_ref()).map_err(Status::internal)?;
        info!("Returning frost sign request");
        Ok(Response::new(response))
    }

    async fn aggregate_frost(
        &self,
        request: Request<AggregateFrostRequest>,
    ) -> Result<Response<AggregateFrostResponse>, Status> {
        tracing::info!("Received frost aggregate request");
        let response =
            spark_frost::signing::aggregate_frost(request.get_ref()).map_err(Status::internal)?;
        Ok(Response::new(response))
    }

    async fn validate_signature_share(
        &self,
        request: Request<ValidateSignatureShareRequest>,
    ) -> Result<Response<()>, Status> {
        tracing::info!("Received frost validate signature share request");
        spark_frost::signing::validate_signature_share(request.get_ref())
            .map_err(Status::internal)
            .map(|_| Response::new(()))
    }

    /// T-PRE: Compute partial ECDH for threshold proxy re-encryption.
    ///
    /// Each signer computes S_i = key_share_i * ephemeral_pubkey using its
    /// FROST secret key share and the ephemeral public key from the ECIES
    /// ciphertext. The operator collects t-of-n of these shares and uses
    /// Lagrange interpolation to reconstruct the full ECDH shared secret.
    async fn partial_ecdh(
        &self,
        request: Request<PartialEcdhRequest>,
    ) -> Result<Response<PartialEcdhResponse>, Status> {
        tracing::info!("Received T-PRE partial ECDH request");
        let req = request.get_ref();

        // Extract the secret key share from the key package
        let key_package = req
            .key_package
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("key_package is required"))?;

        let secret_share = &key_package.secret_share;
        if secret_share.len() != 32 {
            return Err(Status::invalid_argument(format!(
                "secret_share must be 32 bytes, got {}",
                secret_share.len()
            )));
        }

        let ephemeral_pk = &req.ephemeral_public_key;
        if ephemeral_pk.len() != 65 {
            return Err(Status::invalid_argument(format!(
                "ephemeral_public_key must be 65 bytes (uncompressed), got {}",
                ephemeral_pk.len()
            )));
        }

        // Compute partial ECDH: S_i = key_share_i * R
        let partial_point = spark_frost::tpre::partial_ecdh(secret_share, ephemeral_pk)
            .map_err(|e| Status::internal(format!("partial ECDH failed: {e}")))?;

        tracing::info!("T-PRE partial ECDH computed successfully");

        Ok(Response::new(PartialEcdhResponse {
            partial_ecdh_point: partial_point,
            identifier: key_package.identifier.clone(),
        }))
    }

    /// T-PRE: Combined threshold decrypt and re-encrypt.
    ///
    /// Takes the partial ECDH shares from threshold operators, combines them
    /// via Lagrange interpolation, decrypts the content key from the ECIES
    /// ciphertext, and re-encrypts it to the reader's public key.
    async fn threshold_decrypt_reencrypt(
        &self,
        request: Request<ThresholdDecryptReencryptRequest>,
    ) -> Result<Response<ThresholdDecryptReencryptResponse>, Status> {
        tracing::info!("Received T-PRE threshold decrypt+reencrypt request");
        let req = request.get_ref();

        // Validate input
        if req.sealed_content_key.len() < 97 {
            return Err(Status::invalid_argument(format!(
                "sealed_content_key too short: {} bytes, need at least 97",
                req.sealed_content_key.len()
            )));
        }
        if req.reader_public_key.len() != 33 && req.reader_public_key.len() != 65 {
            return Err(Status::invalid_argument(format!(
                "reader_public_key must be 33 or 65 bytes, got {}",
                req.reader_public_key.len()
            )));
        }
        if req.partial_shares.is_empty() {
            return Err(Status::invalid_argument("no partial shares provided"));
        }
        if req.threshold == 0 {
            return Err(Status::invalid_argument("threshold must be > 0"));
        }

        // Convert proto shares to (index, point) tuples for the combiner
        let shares: Vec<(u32, Vec<u8>)> = req
            .partial_shares
            .iter()
            .map(|s| (s.operator_index, s.partial_ecdh_point.clone()))
            .collect();

        // Step 1: Combine partial ECDH shares via Lagrange interpolation
        let combined_point = spark_frost::tpre::combine_ecdh_shares(&shares)
            .map_err(|e| Status::internal(format!("failed to combine ECDH shares: {e}")))?;

        // Step 2: Threshold decrypt the content key
        // threshold_decrypt_with_shared_point extracts the ephemeral pubkey internally
        let content_key = spark_frost::tpre::threshold_decrypt_with_shared_point(
            &req.sealed_content_key,
            &combined_point,
        )
        .map_err(|e| Status::internal(format!("threshold decryption failed: {e}")))?;

        tracing::info!(
            "T-PRE: decrypted content key ({} bytes), re-encrypting to reader",
            content_key.len()
        );

        // Step 4: Re-encrypt the content key to the reader's public key
        let re_encrypted = spark_frost::tpre::reencrypt(&content_key, &req.reader_public_key)
            .map_err(|e| Status::internal(format!("re-encryption failed: {e}")))?;

        tracing::info!(
            "T-PRE: re-encryption complete ({} bytes)",
            re_encrypted.len()
        );

        Ok(Response::new(ThresholdDecryptReencryptResponse {
            re_encrypted_key: re_encrypted,
            content_key: content_key,
        }))
    }
}
