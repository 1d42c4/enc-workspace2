use keyfile_core::{Result, Spec, invalid};
use zeroize::Zeroizing;
pub struct App;
type Engine = salsa20::Salsa8;
impl Spec for App {
    const ID: u16 = 81;
    const NAME: &str = "Salsa8-HMAC";
    const CATEGORY: &str = "reduced-round / experimental";
    const KEY_LEN: usize = 32;
    const NONCE_LEN: usize = 8;
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
