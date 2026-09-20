use keyfile_core::{Result, Spec, invalid};
use zeroize::Zeroizing;
pub struct App;
type Engine = aria::Aria256;
impl Spec for App {
    const ID: u16 = 68;
    const NAME: &str = "ARIA-256-CBC";
    const CATEGORY: &str = "established primitive";
    const KEY_LEN: usize = 32;
    const NONCE_LEN: usize = 16;
    fn body_len(n: usize) -> usize {
        (n / 16 + 1) * 16
    }
    fn encrypt(key: &[u8], nonce: &[u8], aad: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        encrypt(key, nonce, aad, data)
    }
    fn decrypt(key: &[u8], nonce: &[u8], aad: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        decrypt(key, nonce, aad, data)
    }
}
include!("../../../support/backends/cbc.rs");

#[cfg(test)]
mod primitive_known_answer {

    #[test]
    fn published_block_vector() {
        use cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
        type Primitive = aria::Aria256;
        let key: &[u8] = &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let plain: &[u8] = &[
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let expected: &[u8] = &[
            0xf9, 0x2b, 0xd7, 0xc7, 0x9f, 0xb7, 0x2e, 0x2f, 0x2b, 0x8f, 0x80, 0xc1, 0x97, 0x2d,
            0x24, 0xfc,
        ];
        let engine = Primitive::new_from_slice(key).unwrap();
        let mut block = Block::<Primitive>::try_from(plain).unwrap();
        engine.encrypt_block(&mut block);
        assert_eq!(block.as_slice(), expected);
        engine.decrypt_block(&mut block);
        assert_eq!(block.as_slice(), plain);
    }
}
