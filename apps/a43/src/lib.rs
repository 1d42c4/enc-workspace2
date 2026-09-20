use keyfile_core::{Result, Spec, invalid};
use zeroize::Zeroizing;
pub struct App;
type Engine = ccm::Ccm<cast6::Cast6, aead::consts::U16, aead::consts::U11>;
impl Spec for App {
    const ID: u16 = 43;
    const NAME: &str = "CAST6-256-CCM";
    const CATEGORY: &str = "composed / experimental";
    const KEY_LEN: usize = 32;
    const NONCE_LEN: usize = 11;
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

#[cfg(test)]
mod primitive_known_answer {

    #[test]
    fn published_block_vector() {
        use cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
        type Primitive = cast6::Cast6;
        let key: &[u8] = &[
            0x23, 0x42, 0xbb, 0x9e, 0xfa, 0x38, 0x54, 0x2c, 0xbe, 0xd0, 0xac, 0x83, 0x94, 0x0a,
            0xc2, 0x98, 0x8d, 0x7c, 0x47, 0xce, 0x26, 0x49, 0x08, 0x46, 0x1c, 0xc1, 0xb5, 0x13,
            0x7a, 0xe6, 0xb6, 0x04,
        ];
        let plain: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let expected: &[u8] = &[
            0x4f, 0x6a, 0x20, 0x38, 0x28, 0x68, 0x97, 0xb9, 0xc9, 0x87, 0x01, 0x36, 0x55, 0x33,
            0x17, 0xfa,
        ];
        let engine = Primitive::new_from_slice(key).unwrap();
        let mut block = Block::<Primitive>::try_from(plain).unwrap();
        engine.encrypt_block(&mut block);
        assert_eq!(block.as_slice(), expected);
        engine.decrypt_block(&mut block);
        assert_eq!(block.as_slice(), plain);
    }
}
