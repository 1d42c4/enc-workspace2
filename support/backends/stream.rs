fn encrypt(key: &[u8], nonce: &[u8], _: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    use cipher::{KeyIvInit, StreamCipher};
    let mut engine = Engine::new_from_slices(key, nonce).map_err(|_| invalid())?;
    let mut output = Zeroizing::new(data.to_vec());
    engine
        .try_apply_keystream(&mut output)
        .map_err(|_| invalid())?;
    Ok(output)
}
fn decrypt(key: &[u8], nonce: &[u8], aad: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    encrypt(key, nonce, aad, data)
}
