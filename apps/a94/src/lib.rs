use keyfile_core::{Result, Spec, invalid};
use zeroize::Zeroizing;
pub struct App;
const TOY: &str = "beaufort-byte";
impl Spec for App {
    const ID: u16 = 94;
    const NAME: &str = "Toy beaufort-byte";
    const CATEGORY: &str = "TOY / insecure";
    const KEY_LEN: usize = 32;
    const NONCE_LEN: usize = 0;
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
include!("../../../support/backends/toy.rs");
