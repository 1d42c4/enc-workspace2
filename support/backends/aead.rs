fn encrypt(key: &[u8], nonce: &[u8], aad: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    use aead::{Aead, KeyInit, Payload};
    let engine = Engine::new_from_slice(key).map_err(|_| invalid())?;
    let nonce = aead::Nonce::<Engine>::try_from(nonce).map_err(|_| invalid())?;
    engine
        .encrypt(&nonce, Payload { msg: data, aad })
        .map(Zeroizing::new)
        .map_err(|_| invalid())
}
fn decrypt(key: &[u8], nonce: &[u8], aad: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    use aead::{Aead, KeyInit, Payload};
    let engine = Engine::new_from_slice(key).map_err(|_| invalid())?;
    let nonce = aead::Nonce::<Engine>::try_from(nonce).map_err(|_| invalid())?;
    engine
        .decrypt(&nonce, Payload { msg: data, aad })
        .map(Zeroizing::new)
        .map_err(|_| invalid())
}

#[cfg(test)]
mod native_aead_tests {
    use super::*;
    #[test]
    fn native_tag_protects_plaintext_and_associated_data() {
        let key = vec![37; App::KEY_LEN];
        let nonce = vec![81; App::NONCE_LEN];
        let encoded = encrypt(&key, &nonce, b"header", b"private data").unwrap();
        assert!(decrypt(&key, &nonce, b"wrong header", &encoded).is_err());
        for i in 0..encoded.len() {
            let mut altered = encoded.clone();
            altered[i] ^= 1;
            assert!(decrypt(&key, &nonce, b"header", &altered).is_err());
        }
        assert!(encrypt(&key, &[], b"header", b"data").is_err());
    }
}
