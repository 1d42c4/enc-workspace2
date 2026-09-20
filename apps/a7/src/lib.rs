use keyfile_core::{Result, Spec, invalid};
use zeroize::Zeroizing;
pub struct App;
type Engine = aes_gcm_siv::Aes256GcmSiv;
impl Spec for App {
    const ID: u16 = 7;
    const NAME: &str = "AES-256-GCM-SIV";
    const CATEGORY: &str = "established primitive";
    const KEY_LEN: usize = 32;
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
