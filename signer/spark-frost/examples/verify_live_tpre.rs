//! Verify the live T-PRE re-encrypted key can be decrypted by the reader.
//!
//! Usage: cargo run --release --example verify_live_tpre

use ecies::decrypt;
use libsecp256k1::SecretKey;

fn main() {
    // Re-encrypted key returned by the live federation (base64 decoded to hex)
    let reencrypted_hex = "04e9a6dda2a3935996c520e44db9aae8500ae30993b11050c74133b357c2e838b69d7c63c0d5a92b924f62e5f5dc1a060fb60d425bcf8e4bc94b32e419f381fdd02db16a4388b1bc7e4f1957c9b225f461d48a5bc301cc5305646f747f205cca5726391e4e8641f684fed75b87a1092cda056d1710b6a7f2eedbc80d10fffc5acb";
    let reencrypted_bytes = hex::decode(reencrypted_hex).unwrap();

    // Reader's secret key
    let reader_sk_hex = "f870dcd3ac1822fbb909c482077cb152cc850baf0332384a603c7172e9821631";
    let reader_sk_bytes = hex::decode(reader_sk_hex).unwrap();
    let reader_sk = SecretKey::parse_slice(&reader_sk_bytes).unwrap();

    // Expected content key
    let expected_content_key = b"tpre-live-test-content-key-12345";

    // Decrypt using ECIES with reader's secret key
    let decrypted = decrypt(&reader_sk.serialize(), &reencrypted_bytes)
        .expect("Reader should be able to decrypt re-encrypted key");

    println!("Decrypted content key (hex): {}", hex::encode(&decrypted));
    println!("Decrypted content key (text): {}", String::from_utf8_lossy(&decrypted));
    println!("Expected content key (text): {}", String::from_utf8_lossy(expected_content_key));

    assert_eq!(
        decrypted.as_slice(),
        expected_content_key,
        "Decrypted content key should match original!"
    );

    println!("\n✅ SUCCESS! Live T-PRE end-to-end verification passed!");
    println!("   - Federation threshold-decrypted the sealed content key");
    println!("   - Re-encrypted to reader's public key");
    println!("   - Reader successfully decrypted with their private key");
    println!("   - Content key matches: \"{}\"", String::from_utf8_lossy(expected_content_key));
}
