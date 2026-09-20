use keyfile_core::{Result, Spec, invalid};
use zeroize::Zeroizing;
pub struct App;
type Engine = aes_gcm::AesGcm<aes::Aes192, aead::consts::U12>;
impl Spec for App {
    const ID: u16 = 4;
    const NAME: &str = "AES-192-GCM";
    const CATEGORY: &str = "established primitive";
    const KEY_LEN: usize = 24;
    const NONCE_LEN: usize = 12;
    fn body_len(n: usize) -> usize {
        n + 16
    }
    fn encrypt(key: &[u8], nonce: &[u8], aad: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        encrypt(key, nonce, aad, data)
    }
    fn decrypt(key: &[u8], nonce: &[u8], aad: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        decrypt(key, nonce, aad, data)
    }
}
include!("../../../support/backends/aead.rs");
