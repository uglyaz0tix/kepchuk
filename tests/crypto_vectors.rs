use kepchuk::crypto;

#[test]
fn test_sha256_nist_vectors() {
    // empty string
    assert_eq!(
        crypto::sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );

    // standard abc
    assert_eq!(
        crypto::sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );

    // two block message
    assert_eq!(
        crypto::sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
}

#[test]
fn test_rfc4231_case_1() {
    let key = [0x0bu8; 20];
    let data = b"Hi There";
    let expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
    assert_eq!(crypto::hmac_sha256_hex(&key, data), expected);
}

#[test]
fn test_rfc4231_case_2() {
    let key = b"Jefe";
    let data = b"what do ya want for nothing?";
    let expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
    assert_eq!(crypto::hmac_sha256_hex(key, data), expected);
}

#[test]
fn test_rfc4231_case_3() {
    let key = [0xaau8; 20];
    let data = [0xddu8; 50];
    let expected = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe";
    assert_eq!(crypto::hmac_sha256_hex(&key, &data), expected);
}

#[test]
fn test_rfc4231_case_4() {
    let key: Vec<u8> = (1..=25).map(|b| b as u8).collect();
    let data = [0xcdu8; 50];
    let expected = "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b";
    assert_eq!(crypto::hmac_sha256_hex(&key, &data), expected);
}

#[test]
fn test_rfc4231_case_5() {
    let key = [0x0cu8; 20];
    let data = b"Test With Truncation";
    let full_digest = crypto::hmac_sha256(&key, data);
    // rfc 4231 specifies 128-bit truncation (first 16 bytes)
    let truncated_hex = hex::encode(&full_digest[..16]);
    assert_eq!(truncated_hex, "a3b6167473100ee06e0c796c2955552b");
}

#[test]
fn test_rfc4231_case_6() {
    let key = [0xaau8; 131];
    let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
    let expected = "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54";
    assert_eq!(crypto::hmac_sha256_hex(&key, data), expected);
}

#[test]
fn test_rfc4231_case_7() {
    let key = [0xaau8; 131];
    let data = b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
    let expected = "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2";
    assert_eq!(crypto::hmac_sha256_hex(&key, data), expected);
}

#[test]
fn test_constant_time_comparison() {
    let a = b"signature-payload-1234567890abcdef";
    let b = b"signature-payload-1234567890abcdef";
    let c = b"signature-payload-1234567890abcdeg";
    let d = b"short";

    assert!(crypto::secure_compare(a, b));
    assert!(!crypto::secure_compare(a, c));
    assert!(!crypto::secure_compare(a, d));
}
