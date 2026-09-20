use keyfile_core::{Result, Spec, invalid};
use zeroize::Zeroizing;
pub struct App;
type Engine = ascon_aead::AsconAead128;
impl Spec for App {
    const ID: u16 = 10;
    const NAME: &str = "Ascon-AEAD128";
    const CATEGORY: &str = "established primitive";
    const KEY_LEN: usize = 16;
    const NONCE_LEN: usize = 16;
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
