use keyfile_core::{Result, Spec, invalid};
use zeroize::Zeroizing;
pub struct App;
type Engine = rc4::Rc4;
impl Spec for App {
    const ID: u16 = 90;
    const NAME: &str = "RC4-128-HMAC";
    const CATEGORY: &str = "obsolete / insecure";
    const KEY_LEN: usize = 16;
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
include!("../../../support/backends/rc4.rs");
