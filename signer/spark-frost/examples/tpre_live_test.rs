//! T-PRE Live Test Data Generator
//!
//! Generates test data for the live gRPC integration test.

use ecies::encrypt;
use libsecp256k1::{PublicKey, SecretKey};

fn main() {
    // Federation group public key from DKG (33 bytes compressed)
    let group_pk_hex = "03846df6e2a4a04f4c8f02cfba604ae5b22472547340486582d16770f390359c2c";
    let group_pk_bytes = hex::decode(group_pk_hex).unwrap();

    // Content key to encrypt
    let content_key = b"tpre-live-test-content-key-12345";

    // Encrypt the content key to the federation's group public key
    let sealed_content_key = encrypt(&group_pk_bytes, content_key).unwrap();

    // Generate a reader keypair
    let reader_sk = SecretKey::random(&mut rand::thread_rng());
    let reader_pk = PublicKey::from_secret_key(&reader_sk);

    println!("SEALED_KEY_HEX={}", hex::encode(&sealed_content_key));
    println!("READER_PK_HEX={}", hex::encode(reader_pk.serialize_compressed()));
    println!("READER_SK_HEX={}", hex::encode(reader_sk.serialize()));
    println!("CONTENT_KEY_HEX={}", hex::encode(content_key));
}
