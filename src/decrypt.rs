use crate::error::{Error, Result};
use aes_gcm::{
    Aes128Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use hkdf::Hkdf;
use p256::{PublicKey, SecretKey};
use sha2::Sha256;

pub fn decrypt(
    crypto_key_str: &str, // e.g. "dh=..."
    salt_str: &str,       // e.g. "salt=..."
    auth_secret_b64: &str,
    private_key_b64: &str,
    raw_data: &[u8],
) -> Result<Vec<u8>> {
    use base64::Engine;
    use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};

    let decode_b64 = |s: &str| -> Result<Vec<u8>> {
        URL_SAFE_NO_PAD
            .decode(s)
            .or_else(|_| URL_SAFE.decode(s))
            .map_err(|e| Error::Crypto(format!("Base64 decode failed: {e}")))
    };

    let salt_b64 = match salt_str.strip_prefix("salt=") {
        Some(s) => s,
        None => salt_str,
    };
    let dh_key_str = match crypto_key_str.strip_prefix("dh=") {
        Some(s) => s,
        None => crypto_key_str,
    };

    let salt = decode_b64(salt_b64)?;
    let auth_secret = decode_b64(auth_secret_b64)?;
    let private_key_bytes = decode_b64(private_key_b64)?;
    let dh_pub_bytes = decode_b64(dh_key_str)?;

    let secret_key = SecretKey::from_slice(&private_key_bytes)
        .map_err(|e| Error::Crypto(format!("Invalid private key: {e}")))?;
    let public_key = PublicKey::from_sec1_bytes(&dh_pub_bytes)
        .map_err(|e| Error::Crypto(format!("Invalid public key: {e}")))?;

    let shared_secret =
        p256::ecdh::diffie_hellman(secret_key.to_nonzero_scalar(), public_key.as_affine());
    let ikm = shared_secret.raw_secret_bytes();

    let hkdf_auth = Hkdf::<Sha256>::new(Some(&auth_secret), ikm.as_slice());
    let mut prk = [0u8; 32];
    hkdf_auth
        .expand(b"Content-Encoding: auth\0", &mut prk)
        .map_err(|e| Error::Crypto(format!("HKDF auth expand failed: {e}")))?;

    let hkdf = Hkdf::<Sha256>::new(Some(&salt), &prk);

    let mut cek = [0u8; 16];
    hkdf.expand(b"Content-Encoding: aesgcm\0", &mut cek)
        .map_err(|e| Error::Crypto(format!("HKDF cek expand failed: {e}")))?;

    let mut nonce_bytes = [0u8; 12];
    hkdf.expand(b"Content-Encoding: nonce\0", &mut nonce_bytes)
        .map_err(|e| Error::Crypto(format!("HKDF nonce expand failed: {e}")))?;

    let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&cek));
    let nonce = Nonce::from_slice(&nonce_bytes);

    let decrypted = cipher
        .decrypt(nonce, raw_data)
        .map_err(|e| Error::Crypto(format!("Decryption failed: {e}")))?;

    if decrypted.len() >= 2 {
        let pad_len = u16::from_be_bytes([decrypted[0], decrypted[1]]) as usize;
        if decrypted.len() >= 2 + pad_len {
            return Ok(decrypted[2 + pad_len..].to_vec());
        }
    }

    Ok(decrypted)
}
