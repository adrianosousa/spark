use ecies;
use hex;

fn main() {
    // Federation group public key (compressed, from DKG)
    let group_pk_hex = "03846df6e2a4a04f4c8f02cfba604ae5b22472547340486582d16770f390359c2c";
    let group_pk = hex::decode(group_pk_hex).unwrap();

    // Generate reader keypair
    let (reader_sk, reader_pk) = ecies::utils::generate_keypair();
    let reader_pk_bytes = reader_pk.serialize();

    // Content key to seal (31 bytes, will test decryption)
    let content_key: &[u8] = b"tpre-e2e-test-key-ok-32bytes-ab";

    // ECIES encrypt content key to federation group pubkey
    let sealed = ecies::encrypt(&group_pk, content_key).unwrap();

    // Manual base64 encoder (avoid extra dependency)
    fn to_b64(data: &[u8]) -> String {
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut result = String::new();
        for chunk in data.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
            let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
            let triple = (b0 << 16) | (b1 << 8) | b2;
            result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
            result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
            if chunk.len() > 1 {
                result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
            } else {
                result.push('=');
            }
            if chunk.len() > 2 {
                result.push(CHARS[(triple & 0x3F) as usize] as char);
            } else {
                result.push('=');
            }
        }
        result
    }

    let sealed_b64 = to_b64(&sealed);
    let reader_pk_b64 = to_b64(&reader_pk_bytes);
    let post_id_b64 = to_b64(b"e2e-test-post-001");

    // JSON output on stdout
    print!("{{");
    print!("\"sealed_content_key\":\"{}\",", sealed_b64);
    print!("\"reader_public_key\":\"{}\",", reader_pk_b64);
    print!("\"post_id\":\"{}\",", post_id_b64);
    print!("\"transfer_id\":\"tpre-poc\",");
    print!("\"payment_amount_sats\":\"100\"");
    println!("}}");

    // Debug info on stderr
    eprintln!("sealed_key_len: {}", sealed.len());
    eprintln!("reader_sk_hex: {}", hex::encode(reader_sk.serialize()));
    eprintln!("reader_pk_hex: {}", hex::encode(&reader_pk_bytes));
    eprintln!("content_key: {}", String::from_utf8_lossy(content_key));
    eprintln!("content_key_hex: {}", hex::encode(content_key));
}
