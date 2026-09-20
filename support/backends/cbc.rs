fn encrypt(key: &[u8], nonce: &[u8], _: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    use cipher::{BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
    let engine = cbc::Encryptor::<Engine>::new_from_slices(key, nonce).map_err(|_| invalid())?;
    Ok(Zeroizing::new(engine.encrypt_padded_vec::<Pkcs7>(data)))
}
fn decrypt(key: &[u8], nonce: &[u8], _: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    use cipher::{BlockModeDecrypt, KeyIvInit, block_padding::Pkcs7};
    let engine = cbc::Decryptor::<Engine>::new_from_slices(key, nonce).map_err(|_| invalid())?;
    let mut output = Zeroizing::new(data.to_vec());
    let len = engine
        .decrypt_padded::<Pkcs7>(&mut output)
        .map_err(|_| invalid())?
        .len();
    output.truncate(len);
    Ok(output)
}
