use keyfile_core::{Result, Spec, invalid};
use zeroize::Zeroizing;
pub struct App;
type Engine = chacha20::XChaCha12;
impl Spec for App {
    const ID: u16 = 79;
    const NAME: &str = "XChaCha12-HMAC";
    const CATEGORY: &str = "reduced-round / experimental";
    const KEY_LEN: usize = 32;
    const NONCE_LEN: usize = 24;
    fn body_len(n: usize) -> usize {
        n
    }
    fn encrypt(key: &[u8], nonce: &[u8], aad: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        encrypt(key, nonce, aad, data)
    }
    fn decrypt(key: &[u8], nonce: &[u8], aad: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        decrypt(key, nonce, aad, data)
    }
}
include!("../../../support/backends/stream.rs");
