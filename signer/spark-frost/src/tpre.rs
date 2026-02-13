//! Threshold Proxy Re-Encryption (T-PRE) for Spark.
//!
//! Provides threshold ECIES decryption using FROST key shares and
//! re-encryption to a new recipient public key.
//!
//! # ECIES Ciphertext Format (ecies crate v0.2.x, default config)
//!
//! ```text
//! [65-byte uncompressed ephemeral pubkey R] [16-byte nonce] [16-byte tag] [encrypted data]
//! ```
//!
//! # Threshold Decryption
//!
//! Standard ECIES decryption: `S = sk * R`, then `sym_key = HKDF(R || S)`.
//! Since the federation private key `sk = Σ λᵢ · skᵢ` (Shamir/FROST shares):
//!
//! 1. Each signer computes a partial ECDH: `Sᵢ = skᵢ * R`
//! 2. Coordinator combines: `S = Σ λᵢ · Sᵢ = sk * R`
//! 3. Derives symmetric key and decrypts
//!
//! This works because scalar multiplication distributes over point addition
//! on the elliptic curve.

use aes_gcm::{
    aead::{generic_array::GenericArray, AeadInPlace},
    aes::Aes256,
    AesGcm, KeyInit,
};
use hkdf::Hkdf;
use libsecp256k1::{PublicKey, SecretKey};
use sha2::Sha256;

/// ECIES constants (matching ecies crate default config)
const UNCOMPRESSED_PUBKEY_SIZE: usize = 65;
const NONCE_LENGTH: usize = 16;
const AEAD_TAG_LENGTH: usize = 16;
const NONCE_TAG_LENGTH: usize = NONCE_LENGTH + AEAD_TAG_LENGTH;

/// AES-256-GCM with 16-byte nonce (matches ecies crate default)
type Cipher = AesGcm<Aes256, typenum::consts::U16>;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Compute a partial ECDH share: `Sᵢ = skᵢ * R`
///
/// Each FROST signer calls this with their key share and the ephemeral pubkey
/// extracted from the ECIES ciphertext.
///
/// # Arguments
/// * `key_share_bytes` - 32-byte scalar (signer's FROST secret key share)
/// * `ephemeral_pubkey_bytes` - 65-byte uncompressed public key from ECIES ciphertext
///
/// # Returns
/// 65-byte uncompressed public key representing the partial ECDH point
pub fn partial_ecdh(
    key_share_bytes: &[u8],
    ephemeral_pubkey_bytes: &[u8],
) -> Result<Vec<u8>, String> {
    let sk = SecretKey::parse_slice(key_share_bytes)
        .map_err(|e| format!("invalid key share: {e:?}"))?;
    let mut point = PublicKey::parse_slice(ephemeral_pubkey_bytes, None)
        .map_err(|e| format!("invalid ephemeral pubkey: {e:?}"))?;

    // Multiply: point = sk * R
    point
        .tweak_mul_assign(&sk)
        .map_err(|e| format!("ECDH mul failed: {e:?}"))?;

    Ok(point.serialize().to_vec())
}

/// Extract the ephemeral public key from an ECIES ciphertext.
///
/// # Arguments
/// * `ciphertext` - Full ECIES ciphertext (ephemeral_pubkey || nonce || tag || encrypted_data)
///
/// # Returns
/// 65-byte uncompressed ephemeral public key
pub fn extract_ephemeral_pubkey(ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    if ciphertext.len() < UNCOMPRESSED_PUBKEY_SIZE + NONCE_TAG_LENGTH {
        return Err(format!(
            "ciphertext too short: {} < {}",
            ciphertext.len(),
            UNCOMPRESSED_PUBKEY_SIZE + NONCE_TAG_LENGTH
        ));
    }

    let pubkey_bytes = &ciphertext[..UNCOMPRESSED_PUBKEY_SIZE];

    // Validate it's a valid public key
    PublicKey::parse_slice(pubkey_bytes, None)
        .map_err(|e| format!("invalid ephemeral pubkey in ciphertext: {e:?}"))?;

    Ok(pubkey_bytes.to_vec())
}

/// Combine partial ECDH shares using Lagrange interpolation to reconstruct
/// the full ECDH shared point.
///
/// # Arguments
/// * `shares` - Vec of (participant_index, partial_ecdh_point) tuples.
///   `participant_index` is the 1-based FROST signer index (as u32).
///   `partial_ecdh_point` is a 65-byte uncompressed public key.
///
/// # Returns
/// 65-byte uncompressed public key representing the full ECDH point `S = sk * R`
pub fn combine_ecdh_shares(shares: &[(u32, Vec<u8>)]) -> Result<Vec<u8>, String> {
    if shares.is_empty() {
        return Err("no shares provided".to_string());
    }

    let n = shares.len();

    // Parse all share points
    let points: Vec<(u32, PublicKey)> = shares
        .iter()
        .map(|(idx, bytes)| {
            let pk = PublicKey::parse_slice(bytes, None)
                .map_err(|e| format!("invalid share point for signer {idx}: {e:?}"))?;
            Ok((*idx, pk))
        })
        .collect::<Result<Vec<_>, String>>()?;

    // Compute Lagrange coefficients for each participant
    // λᵢ = Π_{j≠i} (x_j / (x_j - x_i))   (over the scalar field)
    let indices: Vec<u32> = points.iter().map(|(idx, _)| *idx).collect();

    // We need to compute λᵢ · Sᵢ for each share, then sum them.
    // Since we can't directly scalar-multiply a PublicKey by an arbitrary scalar
    // in libsecp256k1, we use tweak_mul_assign with the Lagrange coefficient.

    // First compute Lagrange coefficients as scalars
    let lagrange_coeffs = compute_lagrange_coefficients(&indices)?;

    // Multiply each share point by its Lagrange coefficient: λᵢ · Sᵢ
    let mut weighted_points: Vec<PublicKey> = Vec::with_capacity(n);
    for (i, (_, point)) in points.iter().enumerate() {
        let coeff = &lagrange_coeffs[i];
        let mut weighted = *point;
        weighted
            .tweak_mul_assign(coeff)
            .map_err(|e| format!("lagrange mul failed for signer {}: {e:?}", indices[i]))?;
        weighted_points.push(weighted);
    }

    // Sum all weighted points: S = Σ λᵢ · Sᵢ
    let mut result = weighted_points[0];
    for point in &weighted_points[1..] {
        result = PublicKey::combine(&[result, *point])
            .map_err(|e| format!("point addition failed: {e:?}"))?;
    }

    Ok(result.serialize().to_vec())
}

/// Threshold decrypt an ECIES ciphertext given the reconstructed ECDH shared point.
///
/// This is the coordinator's step after combining partial ECDH shares.
///
/// # Arguments
/// * `ciphertext` - Full ECIES ciphertext
/// * `shared_point_bytes` - 65-byte reconstructed ECDH point `S = sk * R`
///
/// # Returns
/// Decrypted plaintext (the content key `K_F`)
pub fn threshold_decrypt_with_shared_point(
    ciphertext: &[u8],
    shared_point_bytes: &[u8],
) -> Result<Vec<u8>, String> {
    if ciphertext.len() < UNCOMPRESSED_PUBKEY_SIZE + NONCE_TAG_LENGTH {
        return Err("ciphertext too short".to_string());
    }

    let ephemeral_pk_bytes = &ciphertext[..UNCOMPRESSED_PUBKEY_SIZE];
    let encrypted = &ciphertext[UNCOMPRESSED_PUBKEY_SIZE..];

    // Derive symmetric key exactly as ecies crate does:
    // sym_key = HKDF-SHA256(ephemeral_pubkey_uncompressed || shared_point_uncompressed)
    let sym_key = hkdf_derive(ephemeral_pk_bytes, shared_point_bytes);

    // AES-256-GCM decrypt
    aes_gcm_decrypt(&sym_key, encrypted)
}

/// Full threshold decryption: extract ephemeral key, combine shares, decrypt.
///
/// Convenience function that does everything in one call.
///
/// # Arguments
/// * `ciphertext` - Full ECIES ciphertext
/// * `shares` - Vec of (participant_index, partial_ecdh_bytes) from each signer
///
/// # Returns
/// Decrypted plaintext
pub fn threshold_decrypt(
    ciphertext: &[u8],
    shares: &[(u32, Vec<u8>)],
) -> Result<Vec<u8>, String> {
    let shared_point = combine_ecdh_shares(shares)?;
    threshold_decrypt_with_shared_point(ciphertext, &shared_point)
}

/// Re-encrypt a plaintext to a new recipient's public key using standard ECIES.
///
/// This wraps the ecies crate's encrypt function.
///
/// # Arguments
/// * `plaintext` - The decrypted content key
/// * `recipient_pubkey_bytes` - Recipient's public key (33 or 65 bytes)
///
/// # Returns
/// ECIES ciphertext sealed to the recipient
pub fn reencrypt(plaintext: &[u8], recipient_pubkey_bytes: &[u8]) -> Result<Vec<u8>, String> {
    ecies::encrypt(recipient_pubkey_bytes, plaintext).map_err(|e| format!("re-encrypt failed: {e:?}"))
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// HKDF-SHA256 key derivation matching ecies crate's implementation.
///
/// `HKDF-SHA256(salt=None, ikm=(part1 || part2), info=empty) -> 32 bytes`
fn hkdf_derive(part1: &[u8], part2: &[u8]) -> [u8; 32] {
    let mut master = Vec::with_capacity(part1.len() + part2.len());
    master.extend_from_slice(part1);
    master.extend_from_slice(part2);

    let h = Hkdf::<Sha256>::new(None, &master);
    let mut out = [0u8; 32];
    h.expand(&[], &mut out).expect("HKDF expand failed");
    out
}

/// AES-256-GCM decrypt matching ecies crate's format:
/// `[16-byte nonce] [16-byte tag] [encrypted data]`
fn aes_gcm_decrypt(key: &[u8; 32], encrypted: &[u8]) -> Result<Vec<u8>, String> {
    if encrypted.len() < NONCE_TAG_LENGTH {
        return Err("encrypted data too short for nonce+tag".to_string());
    }

    let key = GenericArray::from_slice(key);
    let aead = Cipher::new(key);

    let nonce = GenericArray::from_slice(&encrypted[..NONCE_LENGTH]);
    let tag = GenericArray::from_slice(&encrypted[NONCE_LENGTH..NONCE_TAG_LENGTH]);

    let mut out = encrypted[NONCE_TAG_LENGTH..].to_vec();

    aead.decrypt_in_place_detached(nonce, &[], &mut out, tag)
        .map_err(|_| "AES-GCM decryption failed (bad key or corrupted ciphertext)".to_string())?;

    Ok(out)
}

/// Compute Lagrange coefficients for the given participant indices.
///
/// For participant i with index xᵢ:
/// ```text
/// λᵢ = Π_{j≠i} (xⱼ / (xⱼ - xᵢ))   mod group_order
/// ```
///
/// Returns SecretKey values (scalars mod group_order) for each participant.
fn compute_lagrange_coefficients(indices: &[u32]) -> Result<Vec<SecretKey>, String> {
    // secp256k1 group order
    let order = scalar_from_be_bytes(&[
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0,
        0x36, 0x41, 0x41,
    ]);

    let n = indices.len();
    let mut coefficients = Vec::with_capacity(n);

    for i in 0..n {
        let xi = indices[i] as u64;
        let mut num = [0u8; 32]; // numerator product
        num[31] = 1; // start at 1
        let mut den = [0u8; 32]; // denominator product
        den[31] = 1; // start at 1

        for j in 0..n {
            if i == j {
                continue;
            }
            let xj = indices[j] as u64;

            // numerator *= xj
            num = scalar_mul_u64(&num, xj, &order);

            // denominator *= (xj - xi) mod order
            let diff = if xj > xi {
                xj - xi
            } else {
                // (xj - xi) mod order = order - (xi - xj)
                // We handle this by computing the modular negation
                let pos_diff = xi - xj;
                // We need order - pos_diff, but since order is huge and pos_diff is small,
                // we can compute it directly
                let mut result = order;
                result = scalar_sub_u64(&result, pos_diff, &order);
                // Now den *= result (which is a 32-byte scalar)
                den = scalar_mul_scalar(&den, &result, &order);
                continue;
            };
            den = scalar_mul_u64(&den, diff, &order);
        }

        // λᵢ = num * den^(-1) mod order
        let den_inv = scalar_mod_inverse(&den, &order)
            .ok_or_else(|| format!("zero denominator for signer index {}", indices[i]))?;
        let coeff_bytes = scalar_mul_scalar(&num, &den_inv, &order);

        let coeff = SecretKey::parse_slice(&coeff_bytes)
            .map_err(|e| format!("invalid lagrange coeff: {e:?}"))?;
        coefficients.push(coeff);
    }

    Ok(coefficients)
}

// ---------------------------------------------------------------------------
// Big-integer scalar arithmetic (mod secp256k1 group order)
// These operate on 32-byte big-endian byte arrays.
// ---------------------------------------------------------------------------

/// Convert 32 bytes (big-endian) to a 256-bit value conceptually.
/// We just use the raw bytes for our arithmetic helpers.
fn scalar_from_be_bytes(bytes: &[u8; 32]) -> [u8; 32] {
    *bytes
}

/// Multiply a 32-byte scalar by a u64, mod `order`.
fn scalar_mul_u64(a: &[u8; 32], b: u64, order: &[u8; 32]) -> [u8; 32] {
    // Convert a to u64 limbs (little-endian), multiply, then reduce
    let a_limbs = be_bytes_to_limbs(a);
    let b_limbs = [b, 0, 0, 0];
    let product = limbs_mul_wide(&a_limbs, &b_limbs);
    let order_limbs = be_bytes_to_limbs(order);
    let result = limbs_mod(&product, &order_limbs);
    limbs_to_be_bytes(&result)
}

/// Subtract a u64 from a 32-byte scalar, mod `order`.
fn scalar_sub_u64(a: &[u8; 32], b: u64, order: &[u8; 32]) -> [u8; 32] {
    let a_limbs = be_bytes_to_limbs(a);
    let order_limbs = be_bytes_to_limbs(order);

    // a - b: if a >= b, just subtract. Otherwise, a - b + order.
    let (result, borrow) = limbs_sub(&a_limbs, &[b, 0, 0, 0]);
    if borrow {
        let (r, _) = limbs_add(&result, &order_limbs);
        limbs_to_be_bytes(&r)
    } else {
        limbs_to_be_bytes(&result)
    }
}

/// Multiply two 32-byte scalars, mod `order`.
fn scalar_mul_scalar(a: &[u8; 32], b: &[u8; 32], order: &[u8; 32]) -> [u8; 32] {
    let a_limbs = be_bytes_to_limbs(a);
    let b_limbs = be_bytes_to_limbs(b);
    let product = limbs_mul_wide(&a_limbs, &b_limbs);
    let order_limbs = be_bytes_to_limbs(order);
    let result = limbs_mod(&product, &order_limbs);
    limbs_to_be_bytes(&result)
}

/// Modular inverse via extended Euclidean algorithm (Fermat's little theorem).
/// Since `order` is prime, `a^(-1) = a^(order-2) mod order`.
fn scalar_mod_inverse(a: &[u8; 32], order: &[u8; 32]) -> Option<[u8; 32]> {
    // Check a is not zero
    if a.iter().all(|&b| b == 0) {
        return None;
    }

    let a_limbs = be_bytes_to_limbs(a);
    let order_limbs = be_bytes_to_limbs(order);

    // exp = order - 2
    let (exp_limbs, _) = limbs_sub(&order_limbs, &[2, 0, 0, 0]);

    // a^exp mod order via square-and-multiply
    let result = limbs_mod_pow(&a_limbs, &exp_limbs, &order_limbs);
    Some(limbs_to_be_bytes(&result))
}

// ---------------------------------------------------------------------------
// 256-bit limb arithmetic (4 × u64, little-endian limb order)
// ---------------------------------------------------------------------------

fn be_bytes_to_limbs(bytes: &[u8; 32]) -> [u64; 4] {
    [
        u64::from_be_bytes(bytes[24..32].try_into().unwrap()),
        u64::from_be_bytes(bytes[16..24].try_into().unwrap()),
        u64::from_be_bytes(bytes[8..16].try_into().unwrap()),
        u64::from_be_bytes(bytes[0..8].try_into().unwrap()),
    ]
}

fn limbs_to_be_bytes(limbs: &[u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&limbs[3].to_be_bytes());
    out[8..16].copy_from_slice(&limbs[2].to_be_bytes());
    out[16..24].copy_from_slice(&limbs[1].to_be_bytes());
    out[24..32].copy_from_slice(&limbs[0].to_be_bytes());
    out
}

/// Add two 256-bit numbers, return (result, carry).
fn limbs_add(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], bool) {
    let mut result = [0u64; 4];
    let mut carry = 0u64;
    for i in 0..4 {
        let sum = (a[i] as u128) + (b[i] as u128) + (carry as u128);
        result[i] = sum as u64;
        carry = (sum >> 64) as u64;
    }
    (result, carry != 0)
}

/// Subtract b from a, return (result, borrow).
fn limbs_sub(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], bool) {
    let mut result = [0u64; 4];
    let mut borrow = 0i128;
    for i in 0..4 {
        let diff = (a[i] as i128) - (b[i] as i128) - borrow;
        if diff < 0 {
            result[i] = (diff + (1i128 << 64)) as u64;
            borrow = 1;
        } else {
            result[i] = diff as u64;
            borrow = 0;
        }
    }
    (result, borrow != 0)
}

/// Compare two 256-bit numbers: returns Ordering.
fn limbs_cmp(a: &[u64; 4], b: &[u64; 4]) -> std::cmp::Ordering {
    for i in (0..4).rev() {
        match a[i].cmp(&b[i]) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
    std::cmp::Ordering::Equal
}

/// Wide multiply: 256-bit × 256-bit → 512-bit result (8 limbs).
fn limbs_mul_wide(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    let mut result = [0u64; 8];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let product = (a[i] as u128) * (b[j] as u128) + (result[i + j] as u128) + carry;
            result[i + j] = product as u64;
            carry = product >> 64;
        }
        result[i + 4] = carry as u64;
    }
    result
}

/// Reduce a 512-bit number mod a 256-bit modulus. Uses schoolbook division.
fn limbs_mod(a: &[u64; 8], modulus: &[u64; 4]) -> [u64; 4] {
    // Simple: convert to wider representation and do shift-subtract
    let mut remainder = *a;
    let mut mod_wide = [0u64; 8];
    mod_wide[..4].copy_from_slice(modulus);

    // Find highest set bit of remainder
    let rem_bits = wide_bit_length(&remainder);
    let mod_bits = bit_length_4(modulus);

    if mod_bits == 0 {
        return [0u64; 4]; // shouldn't happen with valid order
    }

    if rem_bits <= mod_bits {
        let mut result = [0u64; 4];
        // Check if remainder < modulus
        let r4: [u64; 4] = [remainder[0], remainder[1], remainder[2], remainder[3]];
        if limbs_cmp(&r4, modulus) == std::cmp::Ordering::Less {
            result.copy_from_slice(&remainder[..4]);
            return result;
        }
    }

    // Shift modulus left so its MSB aligns with remainder's MSB
    let shift = if rem_bits > mod_bits {
        rem_bits - mod_bits
    } else {
        0
    };

    let mut shifted_mod = wide_shift_left(&mod_wide, shift);

    for _ in 0..=shift {
        if wide_cmp(&remainder, &shifted_mod) != std::cmp::Ordering::Less {
            remainder = wide_sub(&remainder, &shifted_mod);
        }
        shifted_mod = wide_shift_right(&shifted_mod, 1);
    }

    [remainder[0], remainder[1], remainder[2], remainder[3]]
}

/// Modular exponentiation: base^exp mod modulus (square-and-multiply).
fn limbs_mod_pow(base: &[u64; 4], exp: &[u64; 4], modulus: &[u64; 4]) -> [u64; 4] {
    let mut result = [1u64, 0, 0, 0]; // 1
    let mut current_base = *base;

    let exp_bits = bit_length_4(exp);

    for bit in 0..exp_bits {
        let limb_idx = bit / 64;
        let bit_idx = bit % 64;

        if (exp[limb_idx] >> bit_idx) & 1 == 1 {
            // result = result * current_base mod modulus
            let product = limbs_mul_wide(&result, &current_base);
            result = limbs_mod(&product, modulus);
        }

        // current_base = current_base^2 mod modulus
        let sq = limbs_mul_wide(&current_base, &current_base);
        current_base = limbs_mod(&sq, modulus);
    }

    result
}

fn bit_length_4(a: &[u64; 4]) -> usize {
    for i in (0..4).rev() {
        if a[i] != 0 {
            return i * 64 + (64 - a[i].leading_zeros() as usize);
        }
    }
    0
}

fn wide_bit_length(a: &[u64; 8]) -> usize {
    for i in (0..8).rev() {
        if a[i] != 0 {
            return i * 64 + (64 - a[i].leading_zeros() as usize);
        }
    }
    0
}

fn wide_cmp(a: &[u64; 8], b: &[u64; 8]) -> std::cmp::Ordering {
    for i in (0..8).rev() {
        match a[i].cmp(&b[i]) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
    std::cmp::Ordering::Equal
}

fn wide_sub(a: &[u64; 8], b: &[u64; 8]) -> [u64; 8] {
    let mut result = [0u64; 8];
    let mut borrow = 0i128;
    for i in 0..8 {
        let diff = (a[i] as i128) - (b[i] as i128) - borrow;
        if diff < 0 {
            result[i] = (diff + (1i128 << 64)) as u64;
            borrow = 1;
        } else {
            result[i] = diff as u64;
            borrow = 0;
        }
    }
    result
}

fn wide_shift_left(a: &[u64; 8], shift: usize) -> [u64; 8] {
    if shift == 0 {
        return *a;
    }
    let limb_shift = shift / 64;
    let bit_shift = shift % 64;
    let mut result = [0u64; 8];
    for i in limb_shift..8 {
        result[i] = a[i - limb_shift] << bit_shift;
        if bit_shift > 0 && i > limb_shift {
            result[i] |= a[i - limb_shift - 1] >> (64 - bit_shift);
        }
    }
    result
}

fn wide_shift_right(a: &[u64; 8], shift: usize) -> [u64; 8] {
    if shift == 0 {
        return *a;
    }
    let limb_shift = shift / 64;
    let bit_shift = shift % 64;
    let mut result = [0u64; 8];
    for i in 0..(8 - limb_shift) {
        result[i] = a[i + limb_shift] >> bit_shift;
        if bit_shift > 0 && (i + limb_shift + 1) < 8 {
            result[i] |= a[i + limb_shift + 1] << (64 - bit_shift);
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ecies::{decrypt, encrypt};

    /// Generate a random keypair using the ecies crate.
    fn gen_keypair() -> (SecretKey, PublicKey) {
        let sk = SecretKey::random(&mut rand::thread_rng());
        let pk = PublicKey::from_secret_key(&sk);
        (sk, pk)
    }

    #[test]
    fn test_extract_ephemeral_pubkey() {
        let (_, pk) = gen_keypair();
        let msg = b"hello world";
        let ciphertext = encrypt(&pk.serialize(), msg).unwrap();

        let eph_pk = extract_ephemeral_pubkey(&ciphertext).unwrap();
        assert_eq!(eph_pk.len(), 65);
        // Verify it parses as a valid public key
        PublicKey::parse_slice(&eph_pk, None).unwrap();
    }

    #[test]
    fn test_single_signer_threshold_decrypt() {
        // With threshold=1, single signer, threshold decrypt should equal normal decrypt
        let (sk, pk) = gen_keypair();
        let plaintext = b"secret content key for paywalled article";
        let ciphertext = encrypt(&pk.serialize(), plaintext).unwrap();

        // Extract ephemeral pubkey and compute partial ECDH
        let eph_pk = extract_ephemeral_pubkey(&ciphertext).unwrap();
        let share = partial_ecdh(&sk.serialize(), &eph_pk).unwrap();

        // "Combine" the single share (participant 1, Lagrange coeff = 1)
        let combined = combine_ecdh_shares(&[(1, share)]).unwrap();

        // Decrypt
        let decrypted =
            threshold_decrypt_with_shared_point(&ciphertext, &combined).unwrap();
        assert_eq!(&decrypted, plaintext);

        // Cross-check with standard ECIES decrypt
        let standard_decrypted = decrypt(&sk.serialize(), &ciphertext).unwrap();
        assert_eq!(&decrypted, &standard_decrypted[..]);
    }

    #[test]
    fn test_threshold_3_of_5() {
        // Simulate a 3-of-5 threshold setup using Shamir's secret sharing
        let (federation_sk, federation_pk) = gen_keypair();

        // Split the secret key into 5 shares with threshold 3
        let shares = shamir_split(&federation_sk.serialize(), 5, 3);

        let plaintext = b"K_F: the symmetric key for encrypting premium content";
        let ciphertext = encrypt(&federation_pk.serialize(), plaintext).unwrap();

        let eph_pk = extract_ephemeral_pubkey(&ciphertext).unwrap();

        // Each of 3 signers computes their partial ECDH
        let partial_shares: Vec<(u32, Vec<u8>)> = shares[..3]
            .iter()
            .map(|(idx, share_bytes)| {
                let partial = partial_ecdh(share_bytes, &eph_pk).unwrap();
                (*idx, partial)
            })
            .collect();

        // Combine and decrypt
        let decrypted = threshold_decrypt(&ciphertext, &partial_shares).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_threshold_decrypt_then_reencrypt() {
        // Full T-PRE flow:
        // 1. Author encrypts content key to federation
        // 2. 3-of-5 threshold decrypt
        // 3. Re-encrypt to reader's key
        // 4. Reader decrypts
        let (federation_sk, federation_pk) = gen_keypair();
        let (reader_sk, reader_pk) = gen_keypair();

        let content_key = b"AES-256 key for encrypting the article body";
        let sealed = encrypt(&federation_pk.serialize(), content_key).unwrap();

        // Threshold decrypt
        let shares = shamir_split(&federation_sk.serialize(), 5, 3);
        let eph_pk = extract_ephemeral_pubkey(&sealed).unwrap();
        let partial_shares: Vec<(u32, Vec<u8>)> = shares[..3]
            .iter()
            .map(|(idx, sb)| (*idx, partial_ecdh(sb, &eph_pk).unwrap()))
            .collect();
        let recovered_key = threshold_decrypt(&sealed, &partial_shares).unwrap();
        assert_eq!(&recovered_key, content_key);

        // Re-encrypt to reader
        let resealed = reencrypt(&recovered_key, &reader_pk.serialize_compressed()).unwrap();

        // Reader decrypts
        let reader_decrypted = decrypt(&reader_sk.serialize(), &resealed).unwrap();
        assert_eq!(&reader_decrypted[..], content_key);
    }

    #[test]
    fn test_different_share_subsets() {
        // Any 3-of-5 subset should produce the same result
        let (federation_sk, federation_pk) = gen_keypair();
        let content_key = b"test key for subset verification";
        let ciphertext = encrypt(&federation_pk.serialize(), content_key).unwrap();
        let eph_pk = extract_ephemeral_pubkey(&ciphertext).unwrap();

        let shares = shamir_split(&federation_sk.serialize(), 5, 3);

        // Try different subsets of 3
        let subsets: Vec<Vec<usize>> = vec![
            vec![0, 1, 2],
            vec![0, 1, 3],
            vec![0, 1, 4],
            vec![0, 2, 3],
            vec![0, 2, 4],
            vec![0, 3, 4],
            vec![1, 2, 3],
            vec![1, 2, 4],
            vec![1, 3, 4],
            vec![2, 3, 4],
        ];

        for subset in subsets {
            let partial: Vec<(u32, Vec<u8>)> = subset
                .iter()
                .map(|&i| {
                    let (idx, sb) = &shares[i];
                    (*idx, partial_ecdh(sb, &eph_pk).unwrap())
                })
                .collect();

            let decrypted = threshold_decrypt(&ciphertext, &partial).unwrap();
            assert_eq!(
                &decrypted, content_key,
                "failed with subset {:?}",
                subset
            );
        }
    }

    #[test]
    fn test_insufficient_shares_fails() {
        // 2-of-5 should NOT decrypt (threshold is 3)
        let (federation_sk, federation_pk) = gen_keypair();
        let content_key = b"should not decrypt with too few shares";
        let ciphertext = encrypt(&federation_pk.serialize(), content_key).unwrap();
        let eph_pk = extract_ephemeral_pubkey(&ciphertext).unwrap();

        let shares = shamir_split(&federation_sk.serialize(), 5, 3);

        // Only use 2 shares (below threshold)
        let partial: Vec<(u32, Vec<u8>)> = shares[..2]
            .iter()
            .map(|(idx, sb)| (*idx, partial_ecdh(sb, &eph_pk).unwrap()))
            .collect();

        let result = threshold_decrypt(&ciphertext, &partial);
        // Should fail because wrong shared secret → wrong AES key → decryption error
        assert!(result.is_err(), "should fail with insufficient shares");
    }

    // -----------------------------------------------------------------------
    // Test helper: Shamir's Secret Sharing over secp256k1 scalar field
    // -----------------------------------------------------------------------

    /// Split a 32-byte secret into `n` shares with threshold `t`.
    /// Returns vec of (1-based index, 32-byte share).
    fn shamir_split(secret: &[u8; 32], n: u32, t: u32) -> Vec<(u32, Vec<u8>)> {
        // secp256k1 group order
        let order: [u8; 32] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2,
            0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
        ];

        // Generate random polynomial coefficients: a_0 = secret, a_1..a_{t-1} random
        let mut coeffs: Vec<[u8; 32]> = Vec::with_capacity(t as usize);
        coeffs.push(*secret);
        for _ in 1..t {
            let random_sk = SecretKey::random(&mut rand::thread_rng());
            coeffs.push(random_sk.serialize());
        }

        // Evaluate polynomial at x = 1, 2, ..., n
        let mut shares = Vec::with_capacity(n as usize);
        for i in 1..=n {
            let x = i as u64;
            // f(x) = a_0 + a_1*x + a_2*x^2 + ... + a_{t-1}*x^{t-1}
            let mut result = coeffs[0];
            let mut x_power = x;
            for coeff in coeffs.iter().skip(1) {
                let term = scalar_mul_u64(coeff, x_power, &order);
                // result += term mod order
                let r_limbs = be_bytes_to_limbs(&result);
                let t_limbs = be_bytes_to_limbs(&term);
                let (sum, overflow) = limbs_add(&r_limbs, &t_limbs);
                let order_limbs = be_bytes_to_limbs(&order);
                if overflow || limbs_cmp(&sum, &order_limbs) != std::cmp::Ordering::Less {
                    let (reduced, _) = limbs_sub(&sum, &order_limbs);
                    result = limbs_to_be_bytes(&reduced);
                } else {
                    result = limbs_to_be_bytes(&sum);
                }
                // x_power *= x
                x_power = x_power.wrapping_mul(x); // fine for small indices
            }
            shares.push((i, result.to_vec()));
        }

        shares
    }

    /// Integration test using REAL DKG keyshares from the running Spark federation.
    ///
    /// These keyshares were produced by the 5-operator regtest federation's DKG process.
    /// Group public key: 03846df6e2a4a04f4c8f02cfba604ae5b22472547340486582d16770f390359c2c
    /// Threshold: 3-of-5
    #[test]
    fn test_real_federation_keyshares() {
        // Group public key (33 bytes compressed, from all operators' signing_keyshares table)
        let group_pk_hex = "03846df6e2a4a04f4c8f02cfba604ae5b22472547340486582d16770f390359c2c";
        let group_pk_bytes = hex::decode(group_pk_hex).unwrap();
        let group_pk = PublicKey::parse_slice(&group_pk_bytes, None).unwrap();

        // Secret shares from each operator (32 bytes each)
        let operator_shares: Vec<(u32, Vec<u8>)> = vec![
            (1, hex::decode("977c9e434099e84397d2b04ac300023436b8737c2c6fb52b34fb69098ea88e4c").unwrap()),
            (2, hex::decode("0e0297a545417f07d6ddeb13fd6db4dc3810393568c90ece7df5cf3adbc9f7b2").unwrap()),
            (3, hex::decode("f637c482332681044da22f08e1513c034604a8b9d1b79ca7a752dbfd07a62e01").unwrap()),
            (4, hex::decode("501c24da0a48ee38fc1f7c296eaa97ad30892b5559617e03719b73a9a19a6d76").unwrap()),
            (5, hex::decode("1bafb8accaa8c6a5e255d275a579c7d76cfb7ad55e57f3595c74535a4a133893").unwrap()),
        ];

        // 1. Author encrypts a content key to the federation's group public key
        let content_key = b"real-federation-test-content-key-32";
        let ciphertext = encrypt(&group_pk.serialize(), content_key).unwrap();
        assert!(ciphertext.len() >= 97, "ciphertext should be at least 97 bytes");

        // 2. Extract ephemeral pubkey
        let eph_pk = extract_ephemeral_pubkey(&ciphertext).unwrap();

        // 3. Each operator computes partial ECDH with their real DKG share
        let partial_shares: Vec<(u32, Vec<u8>)> = operator_shares
            .iter()
            .map(|(idx, share_bytes)| {
                let partial = partial_ecdh(share_bytes, &eph_pk).unwrap();
                (*idx, partial)
            })
            .collect();

        // 4. Use 3-of-5 (threshold) shares to threshold-decrypt
        // Try operators {1, 2, 3}
        let subset_123: Vec<(u32, Vec<u8>)> = partial_shares[..3].to_vec();
        let decrypted = threshold_decrypt(&ciphertext, &subset_123).unwrap();
        assert_eq!(&decrypted, content_key, "failed with real DKG shares 1,2,3");

        // Try operators {1, 3, 5}
        let subset_135: Vec<(u32, Vec<u8>)> = vec![
            partial_shares[0].clone(),
            partial_shares[2].clone(),
            partial_shares[4].clone(),
        ];
        let decrypted2 = threshold_decrypt(&ciphertext, &subset_135).unwrap();
        assert_eq!(&decrypted2, content_key, "failed with real DKG shares 1,3,5");

        // Try operators {2, 4, 5}
        let subset_245: Vec<(u32, Vec<u8>)> = vec![
            partial_shares[1].clone(),
            partial_shares[3].clone(),
            partial_shares[4].clone(),
        ];
        let decrypted3 = threshold_decrypt(&ciphertext, &subset_245).unwrap();
        assert_eq!(&decrypted3, content_key, "failed with real DKG shares 2,4,5");

        // 5. Full T-PRE flow: decrypt and re-encrypt to a reader
        let (reader_sk, reader_pk) = gen_keypair();
        let resealed = reencrypt(&decrypted, &reader_pk.serialize_compressed()).unwrap();
        let reader_decrypted = decrypt(&reader_sk.serialize(), &resealed).unwrap();
        assert_eq!(
            &reader_decrypted[..], content_key,
            "reader failed to decrypt re-encrypted key"
        );

        // Use ALL 5 shares (should also work)
        let decrypted_all5 = threshold_decrypt(&ciphertext, &partial_shares).unwrap();
        assert_eq!(&decrypted_all5, content_key, "failed with all 5 real DKG shares");
    }

    #[test]
    fn test_lagrange_reconstruction() {
        // Verify our Lagrange interpolation is correct by reconstructing a secret
        let order: [u8; 32] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2,
            0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
        ];

        let (sk, _) = gen_keypair();
        let secret = sk.serialize();
        let shares = shamir_split(&secret, 5, 3);

        // Reconstruct using 3 shares
        let indices: Vec<u32> = shares[..3].iter().map(|(i, _)| *i).collect();
        let coeffs = compute_lagrange_coefficients(&indices).unwrap();

        // secret = Σ λᵢ · share_i
        let mut reconstructed = [0u8; 32];
        for (i, (_, share_bytes)) in shares[..3].iter().enumerate() {
            let share: [u8; 32] = share_bytes[..32].try_into().unwrap();
            let term = scalar_mul_scalar(&coeffs[i].serialize(), &share, &order);
            let r_limbs = be_bytes_to_limbs(&reconstructed);
            let t_limbs = be_bytes_to_limbs(&term);
            let (sum, overflow) = limbs_add(&r_limbs, &t_limbs);
            let order_limbs = be_bytes_to_limbs(&order);
            if overflow || limbs_cmp(&sum, &order_limbs) != std::cmp::Ordering::Less {
                let (reduced, _) = limbs_sub(&sum, &order_limbs);
                reconstructed = limbs_to_be_bytes(&reduced);
            } else {
                reconstructed = limbs_to_be_bytes(&sum);
            }
        }

        assert_eq!(reconstructed, secret);
    }
}
