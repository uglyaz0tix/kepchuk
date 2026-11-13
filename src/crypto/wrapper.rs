use super::ffi;
use subtle::ConstantTimeEq;

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    // invoke c sha256
    unsafe {
        ffi::kep_sha256(data.as_ptr(), data.len(), out.as_mut_ptr());
    }
    out
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(sha256(data))
}

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    // invoke c hmac sha256
    unsafe {
        ffi::kep_hmac_sha256(
            key.as_ptr(),
            key.len(),
            msg.as_ptr(),
            msg.len(),
            out.as_mut_ptr(),
        );
    }
    out
}

pub fn hmac_sha256_hex(key: &[u8], msg: &[u8]) -> String {
    hex::encode(hmac_sha256(key, msg))
}

pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    // invoke c constant time comparison
    let c_result = unsafe { ffi::kep_secure_compare(a.as_ptr(), b.as_ptr(), a.len()) == 1 };
    let subtle_result: bool = a.ct_eq(b).into();
    c_result && subtle_result
}
